package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomicgravity/postern/internal/tokenstore"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestDefaultTokenStore(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		envVal  string
		envSet  bool
		want    any
		wantErr bool
	}{
		{name: "all-unset-defaults-to-keychain", want: tokenstore.Keychain{}},
		{name: "config-keychain", config: "keychain", want: tokenstore.Keychain{}},
		{name: "config-keyring-alias", config: "keyring", want: tokenstore.Keychain{}},
		{name: "config-file", config: "file", want: tokenstore.File{}},
		{name: "config-case-insensitive", config: "  FILE  ", want: tokenstore.File{}},
		{name: "config-unknown-errors", config: "vault", wantErr: true},

		{name: "env-file-no-config", envVal: "file", envSet: true, want: tokenstore.File{}},
		{name: "env-empty-falls-through-to-config", config: "file", envVal: "", envSet: true, want: tokenstore.File{}},
		{name: "env-overrides-config-keychain-wins", config: "file", envVal: "keychain", envSet: true, want: tokenstore.Keychain{}},
		{name: "env-overrides-config-file-wins", config: "keychain", envVal: "file", envSet: true, want: tokenstore.File{}},
		{name: "env-unknown-errors", config: "file", envVal: "vault", envSet: true, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupEnv := func(name string) (string, bool) {
				if name == "POSTERN_TOKEN_STORE" && tc.envSet {
					return tc.envVal, true
				}
				return "", false
			}

			store, err := defaultTokenStore("postern", tc.config, "POSTERN", lookupEnv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("defaultTokenStore() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("defaultTokenStore() error = %v", err)
			}

			switch tc.want.(type) {
			case tokenstore.Keychain:
				if _, ok := store.(tokenstore.Keychain); !ok {
					t.Fatalf("defaultTokenStore() = %T, want tokenstore.Keychain", store)
				}
			case tokenstore.File:
				if _, ok := store.(tokenstore.File); !ok {
					t.Fatalf("defaultTokenStore() = %T, want tokenstore.File", store)
				}
			}
		})
	}
}

// TestDefaultTokenStoreFileDir verifies the file backend persists under
// ~/.<binary-name>/tokens/ so engineers know where the on-disk state lives.
func TestDefaultTokenStoreFileDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}

	store, err := defaultTokenStore("acme-access", "file", "ACME_ACCESS", func(name string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatalf("defaultTokenStore() error = %v", err)
	}

	want := tokenstore.NewFile(filepath.Join(home, ".acme-access", "tokens"))
	if store != want {
		t.Fatalf("defaultTokenStore() = %#v, want %#v", store, want)
	}
}

// ccIDPServer is a minimal IdP serving OIDC discovery + a client-credentials
// token endpoint, used to exercise the real defaultAccessToken /
// defaultLoginRunner closures on the client-credentials branch.
type ccIDPServer struct {
	t         *testing.T
	server    *httptest.Server
	tokenForm url.Values
}

func newCCIDPServer(t *testing.T) *ccIDPServer {
	t.Helper()
	s := &ccIDPServer{t: t}
	s.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"issuer":                                s.server.URL,
				"authorization_endpoint":                s.server.URL + "/authorize",
				"token_endpoint":                        s.server.URL + "/token",
				"jwks_uri":                              s.server.URL + "/.well-known/jwks.json",
				"id_token_signing_alg_values_supported": []string{"EdDSA"},
				"subject_types_supported":               []string{"public"},
				"response_types_supported":              []string{"code"},
			})
		case "/token":
			if err := request.ParseForm(); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			s.tokenForm = request.PostForm
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"access_token": ccTestJWT(t),
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	return s
}

func (s *ccIDPServer) URL() string { return s.server.URL }
func (s *ccIDPServer) Close()      { s.server.Close() }

// ccTestJWT mints an HS256 JWT carrying an exp claim. defaultAccessToken only
// reads exp (the broker is the real verifier), so the signature is irrelevant.
func ccTestJWT(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("test-fixture-throwaway-key-32-bytes")},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{"sub": "m2m-sub", "exp": 9999999999}).Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}
	return token
}

func ccProfile(issuer string) ResolvedProfile {
	return ResolvedProfile{
		Name: "svc",
		Profile: Profile{
			Broker: "https://broker.example.com",
			IDP: IDPConfig{
				Issuer:        issuer,
				ClientID:      "m2m-client",
				Audience:      "https://broker.example.com",
				AudienceParam: DefaultAudienceParam,
				Grant:         GrantClientCredentials,
			},
		},
	}
}

// TestDefaultAccessTokenClientCredentialsBypassesStore proves the
// client-credentials branch mints a fresh token in-memory and never writes the
// token store: HOME is a temp dir, and after the call no token files exist.
func TestDefaultAccessTokenClientCredentialsBypassesStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	idp := newCCIDPServer(t)
	defer idp.Close()

	lookupEnv := mapEnv(map[string]string{"POSTERN_IDP_CLIENT_SECRET": "s3cr3t"})
	accessToken := defaultAccessToken("postern", "POSTERN", lookupEnv)

	token, err := accessToken(context.Background(), ccProfile(idp.URL()))
	if err != nil {
		t.Fatalf("accessToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("accessToken() returned empty token")
	}

	if entries, err := os.ReadDir(filepath.Join(home, ".postern", "tokens")); err == nil && len(entries) > 0 {
		t.Fatalf("token store written on client-credentials path: %v", entries)
	}
}

// TestClientCredentialsPathIgnoresAuthParams proves AC #4 for the
// client-credentials grant: even when the resolved profile carries auth_params,
// they never reach the token request. ClientCredentialsOptions has no
// AuthParams field, so the wiring cannot leak them — this asserts it end to end.
func TestClientCredentialsPathIgnoresAuthParams(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	idp := newCCIDPServer(t)
	defer idp.Close()

	lookupEnv := mapEnv(map[string]string{"POSTERN_IDP_CLIENT_SECRET": "s3cr3t"})
	accessToken := defaultAccessToken("postern", "POSTERN", lookupEnv)

	profile := ccProfile(idp.URL())
	profile.Profile.IDP.AuthParams = map[string]string{"idp_identifier": "mydomain.com"}

	if _, err := accessToken(context.Background(), profile); err != nil {
		t.Fatalf("accessToken() error = %v", err)
	}
	if got := idp.tokenForm.Get("idp_identifier"); got != "" {
		t.Fatalf("idp_identifier leaked onto client-credentials token request = %q, want empty", got)
	}
}

// TestDefaultAccessTokenClientCredentialsMissingSecret confirms the actionable
// error names the env var when the secret is absent.
func TestDefaultAccessTokenClientCredentialsMissingSecret(t *testing.T) {
	idp := newCCIDPServer(t)
	defer idp.Close()

	accessToken := defaultAccessToken("postern", "POSTERN", emptyEnv)
	_, err := accessToken(context.Background(), ccProfile(idp.URL()))
	if err == nil {
		t.Fatal("accessToken() error = nil, want missing-secret error")
	}
	if !strings.Contains(err.Error(), "POSTERN_IDP_CLIENT_SECRET") {
		t.Fatalf("accessToken() error = %v, want it to name POSTERN_IDP_CLIENT_SECRET", err)
	}
}

// TestDefaultLoginRunnerClientCredentialsPrintsIdentity confirms login on the
// client-credentials path validates the credentials (one mint) and prints the
// client identity, persisting nothing.
func TestDefaultLoginRunnerClientCredentialsPrintsIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	idp := newCCIDPServer(t)
	defer idp.Close()

	lookupEnv := mapEnv(map[string]string{"POSTERN_IDP_CLIENT_SECRET": "s3cr3t"})
	loginRunner := defaultLoginRunner("postern", "POSTERN", lookupEnv)

	var out strings.Builder
	// NoBrowser is a no-op on this path: it must not error or change behavior.
	if err := loginRunner(context.Background(), ccProfile(idp.URL()), &out, loginOptions{NoBrowser: true}); err != nil {
		t.Fatalf("loginRunner() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "Authenticated as client m2m-client") {
		t.Fatalf("login output = %q, want it to name the client identity", got)
	}

	if entries, err := os.ReadDir(filepath.Join(home, ".postern", "tokens")); err == nil && len(entries) > 0 {
		t.Fatalf("token store written on client-credentials login: %v", entries)
	}
}

// TestDefaultDeleteTokenUsesProfileBackend exercises the real defaultDeleteToken
// closure end-to-end: it must thread the resolved profile's token_store into the
// File backend and delete by profile name. This is the one network-free token
// closure, so it guards the profile.TokenStore -> backend wiring that login and
// refresh share but cannot test without an OAuth round trip.
func TestDefaultDeleteTokenUsesProfileBackend(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tokensDir := filepath.Join(home, ".postern", "tokens")
	fileStore := tokenstore.NewFile(tokensDir)
	state := tokenstore.State{
		Version:      tokenstore.StateVersion,
		IDPIssuer:    "https://idp.example.com",
		IDPClientID:  "client-123",
		RefreshToken: "refresh-token",
	}
	if err := fileStore.Save("acct", state); err != nil {
		t.Fatalf("seed Save() error = %v", err)
	}

	deleteToken := defaultDeleteToken("postern", "POSTERN", emptyEnv)
	resolved := ResolvedProfile{Name: "acct", Profile: Profile{TokenStore: "file"}}
	if err := deleteToken(resolved); err != nil {
		t.Fatalf("deleteToken() error = %v", err)
	}

	if _, err := fileStore.Load("acct"); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("after delete, Load() error = %v, want ErrNotFound (file backend should have removed the slot)", err)
	}
}
