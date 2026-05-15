package oauthlogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/tokenstore"
)

func TestAccessTokenUsesFreshCachedToken(t *testing.T) {
	now := time.Unix(1777000000, 0)
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:    "https://idp.example.com",
		IDPClientID:  "client-123",
		AccessToken:  accessTokenExpiringAt(t, now.Add(10*time.Minute)),
		RefreshToken: "refresh-token-123",
	}}

	token, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      "https://idp.example.com",
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}
	if token != store.state.AccessToken {
		t.Fatalf("AccessToken() = %q, want cached token", token)
	}
	if store.saveCalls != 0 {
		t.Fatalf("save calls = %d, want 0", store.saveCalls)
	}
}

func TestAccessTokenRefreshesExpiredCachedToken(t *testing.T) {
	now := time.Unix(1777000000, 0)
	newAccessToken := accessTokenExpiringAt(t, now.Add(time.Hour))
	idp := newRefreshIDP(t, refreshResponse{
		accessToken:           newAccessToken,
		refreshToken:          "refresh-token-456",
		refreshTokenExpiresIn: 7200,
	})
	defer idp.Close()
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:             idp.URL(),
		IDPClientID:           "client-123",
		AccessToken:           accessTokenExpiringAt(t, now.Add(-time.Minute)),
		RefreshToken:          "refresh-token-123",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour).Unix(),
		Subject:               "subject-123",
		Email:                 "engineer@example.com",
		IssuedAt:              1776999900,
	}}

	token, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      idp.URL(),
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}
	if token != newAccessToken {
		t.Fatalf("AccessToken() = %q, want refreshed token", token)
	}
	if idp.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", idp.refreshCalls)
	}
	if got, want := idp.tokenForm.Get("grant_type"), "refresh_token"; got != want {
		t.Fatalf("grant_type = %q, want %q", got, want)
	}
	if got, want := idp.tokenForm.Get("client_id"), "client-123"; got != want {
		t.Fatalf("client_id = %q, want %q", got, want)
	}
	if got, want := idp.tokenForm.Get("refresh_token"), "refresh-token-123"; got != want {
		t.Fatalf("refresh_token = %q, want %q", got, want)
	}
	if store.saveCalls != 1 {
		t.Fatalf("save calls = %d, want 1", store.saveCalls)
	}
	if got, want := store.saved.AccessToken, newAccessToken; got != want {
		t.Fatalf("saved access token = %q, want %q", got, want)
	}
	if got, want := store.saved.RefreshToken, "refresh-token-456"; got != want {
		t.Fatalf("saved refresh token = %q, want %q", got, want)
	}
	if got, want := store.saved.RefreshTokenExpiresAt, now.Add(7200*time.Second).Unix(); got != want {
		t.Fatalf("saved refresh expiry = %d, want %d", got, want)
	}
	if got, want := store.saved.Email, "engineer@example.com"; got != want {
		t.Fatalf("saved email = %q, want %q", got, want)
	}
}

func TestAccessTokenKeepsRefreshTokenWhenRefreshDoesNotRotate(t *testing.T) {
	now := time.Unix(1777000000, 0)
	newAccessToken := accessTokenExpiringAt(t, now.Add(time.Hour))
	idp := newRefreshIDP(t, refreshResponse{accessToken: newAccessToken})
	defer idp.Close()
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:    idp.URL(),
		IDPClientID:  "client-123",
		AccessToken:  "",
		RefreshToken: "refresh-token-123",
	}}

	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      idp.URL(),
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}
	if got, want := store.saved.RefreshToken, "refresh-token-123"; got != want {
		t.Fatalf("saved refresh token = %q, want %q", got, want)
	}
}

func TestAccessTokenRejectsRefreshedTokenWithoutExpiry(t *testing.T) {
	now := time.Unix(1777000000, 0)
	idp := newRefreshIDP(t, refreshResponse{accessToken: fakeJWT(t, map[string]any{"sub": "subject-123"})})
	defer idp.Close()
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:    idp.URL(),
		IDPClientID:  "client-123",
		AccessToken:  accessTokenExpiringAt(t, now.Add(-time.Minute)),
		RefreshToken: "refresh-token-123",
	}}

	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      idp.URL(),
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("AccessToken() returned nil error")
	}
	if store.saveCalls != 0 {
		t.Fatalf("save calls = %d, want 0", store.saveCalls)
	}
}

func TestAccessTokenRequiresLoginForMissingState(t *testing.T) {
	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      "https://idp.example.com",
		ClientID:    "client-123",
		Store:       &memoryTokenStore{loadErr: tokenstore.ErrNotFound},
	})
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("AccessToken() error = %v, want ErrLoginRequired", err)
	}
}

func TestAccessTokenRequiresLoginForProfileMismatch(t *testing.T) {
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:    "https://old-idp.example.com",
		IDPClientID:  "client-123",
		AccessToken:  accessTokenExpiringAt(t, time.Now().Add(time.Hour)),
		RefreshToken: "refresh-token-123",
	}}

	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      "https://idp.example.com",
		ClientID:    "client-123",
		Store:       store,
	})
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("AccessToken() error = %v, want ErrLoginRequired", err)
	}
	if store.saveCalls != 0 {
		t.Fatalf("save calls = %d, want 0", store.saveCalls)
	}
}

// TestAccessTokenRefreshSurfacesSentinel regression-guards that an IdP-side
// non-2xx on the refresh exchange wraps ErrOAuthRefresh, so wrappers can
// errors.Is against the sentinel rather than substring-match the error text.
func TestAccessTokenRefreshSurfacesSentinel(t *testing.T) {
	now := time.Unix(1777000000, 0)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeDiscoveryDoc(writer, baseURL(request))
		default:
			http.Error(writer, "kaboom", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:    server.URL,
		IDPClientID:  "client-123",
		AccessToken:  accessTokenExpiringAt(t, now.Add(-time.Minute)),
		RefreshToken: "refresh-token-123",
	}}

	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      server.URL,
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if !errors.Is(err, ErrOAuthRefresh) {
		t.Fatalf("AccessToken() error = %v, want errors.Is(ErrOAuthRefresh)", err)
	}
}

func baseURL(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host
}

func TestAccessTokenRequiresLoginForExpiredRefreshToken(t *testing.T) {
	now := time.Unix(1777000000, 0)
	store := &memoryTokenStore{state: tokenstore.State{
		IDPIssuer:             "https://idp.example.com",
		IDPClientID:           "client-123",
		AccessToken:           accessTokenExpiringAt(t, now.Add(-time.Minute)),
		RefreshToken:          "refresh-token-123",
		RefreshTokenExpiresAt: now.Add(-time.Second).Unix(),
	}}

	_, err := AccessToken(context.Background(), AccessTokenOptions{
		ProfileName: "default",
		Issuer:      "https://idp.example.com",
		ClientID:    "client-123",
		Store:       store,
		Now:         func() time.Time { return now },
	})
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("AccessToken() error = %v, want ErrLoginRequired", err)
	}
}

type memoryTokenStore struct {
	state     tokenstore.State
	saved     tokenstore.State
	loadErr   error
	saveErr   error
	saveCalls int
}

func (s *memoryTokenStore) Load(profile string) (tokenstore.State, error) {
	if s.loadErr != nil {
		return tokenstore.State{}, s.loadErr
	}
	return s.state, nil
}

func (s *memoryTokenStore) Save(profile string, state tokenstore.State) error {
	s.saveCalls++
	s.saved = state
	if s.saveErr != nil {
		return s.saveErr
	}
	s.state = state
	return nil
}

type refreshResponse struct {
	accessToken           string
	refreshToken          string
	refreshTokenExpiresIn int64
}

type refreshIDP struct {
	t            *testing.T
	server       *httptest.Server
	response     refreshResponse
	tokenForm    url.Values
	refreshCalls int
}

func newRefreshIDP(t *testing.T, response refreshResponse) *refreshIDP {
	idp := &refreshIDP{t: t, response: response}
	idp.server = httptest.NewServer(http.HandlerFunc(idp.ServeHTTP))
	return idp
}

func (s *refreshIDP) URL() string {
	return s.server.URL
}

func (s *refreshIDP) Close() {
	s.server.Close()
}

func (s *refreshIDP) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.t.Helper()
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		writeDiscoveryDoc(writer, s.server.URL)
	case "/token":
		s.refreshCalls++
		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		s.tokenForm = request.PostForm
		response := map[string]any{
			"access_token": s.response.accessToken,
			"expires_in":   3600,
		}
		if s.response.refreshToken != "" {
			response["refresh_token"] = s.response.refreshToken
		}
		if s.response.refreshTokenExpiresIn > 0 {
			response["refresh_token_expires_in"] = s.response.refreshTokenExpiresIn
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	default:
		http.NotFound(writer, request)
	}
}

func accessTokenExpiringAt(t *testing.T, expiresAt time.Time) string {
	t.Helper()
	return fakeJWT(t, map[string]any{"exp": expiresAt.Unix(), "sub": "subject-123"})
}
