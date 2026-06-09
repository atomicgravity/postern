package oauthlogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeCCServer is a minimal IdP that serves OIDC discovery plus a
// client-credentials token endpoint, recording the posted form so tests can
// assert the audience/scope/secret wiring. The token response carries no
// refresh_token, mirroring real client-credentials grants.
type fakeCCServer struct {
	t           *testing.T
	server      *httptest.Server
	accessToken string
	tokenForm   url.Values
	tokenStatus int
	tokenBody   string
}

func newFakeCCServer(t *testing.T) *fakeCCServer {
	t.Helper()
	s := &fakeCCServer{
		t:           t,
		accessToken: fakeJWT(t, map[string]any{"sub": "machine-sub", "exp": 1777003600}),
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	return s
}

func (s *fakeCCServer) URL() string { return s.server.URL }
func (s *fakeCCServer) Close()      { s.server.Close() }

func (s *fakeCCServer) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	s.t.Helper()
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		writeDiscoveryDoc(writer, s.server.URL)
	case "/token":
		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		s.tokenForm = request.PostForm
		if s.tokenStatus != 0 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(s.tokenStatus)
			_, _ = writer.Write([]byte(s.tokenBody))
			return
		}
		if got, want := request.PostForm.Get("grant_type"), "client_credentials"; got != want {
			http.Error(writer, "bad grant_type", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token": s.accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	default:
		http.NotFound(writer, request)
	}
}

// TestClientCredentialsTokenMintsWithoutRefreshToken proves the happy path:
// discovery + a client-credentials grant returning no refresh_token yields a
// usable access token, with the audience and scopes threaded into the token
// request and the secret sent as a form parameter.
func TestClientCredentialsTokenMintsWithoutRefreshToken(t *testing.T) {
	idp := newFakeCCServer(t)
	defer idp.Close()

	token, err := ClientCredentialsToken(context.Background(), ClientCredentialsOptions{
		Issuer:        idp.URL(),
		ClientID:      "m2m-client",
		ClientSecret:  "s3cr3t",
		Audience:      "https://broker.example.com",
		AudienceParam: "resource",
		Scopes:        "postern/m2m extra",
	})
	if err != nil {
		t.Fatalf("ClientCredentialsToken() error = %v", err)
	}
	if token != idp.accessToken {
		t.Fatalf("token = %q, want %q", token, idp.accessToken)
	}

	form := idp.tokenForm
	if got, want := form.Get("grant_type"), "client_credentials"; got != want {
		t.Fatalf("grant_type = %q, want %q", got, want)
	}
	if got, want := form.Get("client_id"), "m2m-client"; got != want {
		t.Fatalf("client_id = %q, want %q", got, want)
	}
	if got, want := form.Get("client_secret"), "s3cr3t"; got != want {
		t.Fatalf("client_secret = %q, want %q", got, want)
	}
	if got, want := form.Get("resource"), "https://broker.example.com"; got != want {
		t.Fatalf("resource = %q, want %q", got, want)
	}
	if got, want := form.Get("scope"), "postern/m2m extra"; got != want {
		t.Fatalf("scope = %q, want %q", got, want)
	}
}

// TestClientCredentialsTokenScopesOnly confirms the scopes-only configuration
// (no audience) omits the audience param but still mints.
func TestClientCredentialsTokenScopesOnly(t *testing.T) {
	idp := newFakeCCServer(t)
	defer idp.Close()

	token, err := ClientCredentialsToken(context.Background(), ClientCredentialsOptions{
		Issuer:       idp.URL(),
		ClientID:     "m2m-client",
		ClientSecret: "s3cr3t",
		Scopes:       "postern/m2m",
	})
	if err != nil {
		t.Fatalf("ClientCredentialsToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("ClientCredentialsToken() returned empty token")
	}
	if got := idp.tokenForm.Get("resource"); got != "" {
		t.Fatalf("resource = %q, want empty (no audience configured)", got)
	}
}

// TestClientCredentialsTokenRequiresSecret guards the validation: an empty
// secret fails fast with the typed sentinel before any network call.
func TestClientCredentialsTokenRequiresSecret(t *testing.T) {
	_, err := ClientCredentialsToken(context.Background(), ClientCredentialsOptions{
		Issuer:   "https://issuer.example.com",
		ClientID: "m2m-client",
		Scopes:   "postern/m2m",
	})
	if !errors.Is(err, ErrClientCredentialsClientSecretRequired) {
		t.Fatalf("error = %v, want errors.Is(ErrClientCredentialsClientSecretRequired)", err)
	}
}

// TestClientCredentialsTokenSurfacesTokenError confirms an IdP token-endpoint
// rejection wraps the client-credentials sentinel and preserves the body.
func TestClientCredentialsTokenSurfacesTokenError(t *testing.T) {
	idp := newFakeCCServer(t)
	idp.tokenStatus = http.StatusUnauthorized
	idp.tokenBody = `{"error":"invalid_client","error_description":"bad secret"}`
	defer idp.Close()

	_, err := ClientCredentialsToken(context.Background(), ClientCredentialsOptions{
		Issuer:       idp.URL(),
		ClientID:     "m2m-client",
		ClientSecret: "wrong",
		Scopes:       "postern/m2m",
	})
	if !errors.Is(err, ErrOAuthClientCredentials) {
		t.Fatalf("error = %v, want errors.Is(ErrOAuthClientCredentials)", err)
	}
}
