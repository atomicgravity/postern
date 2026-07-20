package oauthlogin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/tokenstore"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestLoginCompletesAuthorizationCodeFlow(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()
	store := &recordingTokenSaver{}
	now := time.Unix(1777000000, 0)

	result, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Audience:      "https://broker.example.com",
		AudienceParam: "resource",
		Scopes:        "postern/cli-access",
		Store:         store,
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got, want := result.DisplayName(), "engineer@example.com"; got != want {
		t.Fatalf("DisplayName() = %q, want %q", got, want)
	}
	if got, want := store.profile, "staging"; got != want {
		t.Fatalf("saved profile = %q, want %q", got, want)
	}
	wantState := tokenstore.State{
		IDPIssuer:             idp.URL(),
		IDPClientID:           "client-123",
		AccessToken:           idp.accessToken,
		RefreshToken:          "refresh-token-123",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour).Unix(),
		Subject:               "subject-123",
		Email:                 "engineer@example.com",
		IssuedAt:              1776999900,
	}
	assertSavedState(t, store.state, wantState)

	authorize := idp.authorizeQuery
	if got, want := authorize.Get("response_type"), "code"; got != want {
		t.Fatalf("response_type = %q, want %q", got, want)
	}
	if got, want := authorize.Get("client_id"), "client-123"; got != want {
		t.Fatalf("client_id = %q, want %q", got, want)
	}
	if got, want := authorize.Get("scope"), "openid email profile postern/cli-access"; got != want {
		t.Fatalf("scope = %q, want %q", got, want)
	}
	if got, want := authorize.Get("resource"), "https://broker.example.com"; got != want {
		t.Fatalf("resource = %q, want %q", got, want)
	}
	if authorize.Get("code_challenge") == "" {
		t.Fatal("authorize URL missing code_challenge")
	}
	if got, want := authorize.Get("code_challenge_method"), "S256"; got != want {
		t.Fatalf("code_challenge_method = %q, want %q", got, want)
	}
	if idp.tokenForm.Get("code_verifier") == "" {
		t.Fatal("token request missing code_verifier")
	}
	if got, want := idp.tokenForm.Get("client_id"), "client-123"; got != want {
		t.Fatalf("token client_id = %q, want %q", got, want)
	}
	if got, want := idp.tokenForm.Get("resource"), "https://broker.example.com"; got != want {
		t.Fatalf("token resource = %q, want %q", got, want)
	}
}

// TestLoginAuthorizeURLUnchangedWithoutAuthParams locks AC #1's
// byte-identical-when-absent guarantee: a nil AuthParams map adds no query
// parameter, so the authorize request carries exactly the flow's own keys and
// nothing else, and each deterministic key keeps its expected value (a values
// regression such as scope mangling would slip past a key-set check alone).
// state and code_challenge are intrinsically random per call, so they are
// asserted present-and-nonempty rather than by value.
func TestLoginAuthorizeURLUnchangedWithoutAuthParams(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()

	_, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Audience:      "https://broker.example.com",
		AudienceParam: "resource",
		Scopes:        "postern/cli-access",
		Store:         &recordingTokenSaver{},
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	q := idp.authorizeQuery
	wantKeys := map[string]struct{}{
		"response_type": {}, "client_id": {}, "redirect_uri": {},
		"scope": {}, "state": {}, "code_challenge": {},
		"code_challenge_method": {}, "access_type": {}, "resource": {},
	}
	for key := range q {
		if _, ok := wantKeys[key]; !ok {
			t.Fatalf("unexpected authorize param %q (absent auth_params must add nothing); query: %v", key, q)
		}
	}
	for key := range wantKeys {
		if _, ok := q[key]; !ok {
			t.Fatalf("authorize query missing expected param %q; query: %v", key, q)
		}
	}

	assertQueryValue(t, q, "response_type", "code")
	assertQueryValue(t, q, "client_id", "client-123")
	assertQueryValue(t, q, "scope", "openid email profile postern/cli-access")
	assertQueryValue(t, q, "access_type", "offline")
	assertQueryValue(t, q, "resource", "https://broker.example.com")
	if redirect := q.Get("redirect_uri"); !strings.HasPrefix(redirect, "http://127.0.0.1:") || !strings.HasSuffix(redirect, "/cb") {
		t.Fatalf("redirect_uri = %q, want loopback http://127.0.0.1:<port>/cb", redirect)
	}
	if q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("state/code_challenge must be present: state=%q code_challenge=%q", q.Get("state"), q.Get("code_challenge"))
	}
}

// TestLoginAuthParamKeysSortedForDeterminism guards Decision 1's
// reproducibility claim: Go map iteration over AuthParams is random, but
// oauth2.AuthCodeURL funnels every param through url.Values.Encode, which sorts
// by key. The produced authorize query's keys must therefore appear in
// ascending order regardless of map-iteration order, making the URL byte-stable
// across runs.
func TestLoginAuthParamKeysSortedForDeterminism(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()

	_, err := Login(context.Background(), Options{
		ProfileName: "staging",
		Issuer:      idp.URL(),
		ClientID:    "client-123",
		Scopes:      "postern/cli-access",
		AuthParams: map[string]string{
			"zeta_param":     "z",
			"idp_identifier": "mydomain.com",
			"alpha_param":    "a",
			"login_hint":     "engineer@mydomain.com",
		},
		Store:         &recordingTokenSaver{},
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	var keys []string
	for _, pair := range strings.Split(idp.authorizeRawQuery, "&") {
		key, _, _ := strings.Cut(pair, "=")
		keys = append(keys, key)
	}
	if !slices.IsSorted(keys) {
		t.Fatalf("authorize query keys not in ascending order (non-deterministic URL): %v", keys)
	}
}

// TestLoginAppendsAuthParamsToAuthorizeURL is the driving use case: an
// operator-configured idp_identifier reaches Cognito's /authorize so the
// enterprise email-first IdP-selection step is skipped.
func TestLoginAppendsAuthParamsToAuthorizeURL(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()

	_, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Scopes:        "postern/cli-access",
		AuthParams:    map[string]string{"idp_identifier": "mydomain.com"},
		Store:         &recordingTokenSaver{},
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got, want := idp.authorizeQuery.Get("idp_identifier"), "mydomain.com"; got != want {
		t.Fatalf("idp_identifier = %q, want %q", got, want)
	}
}

// TestLoginAuthParamsAbsentFromTokenExchange proves AC #4 for the exchange leg:
// an auth_param rides only on the authorize URL, never on the token POST. The
// audience param (resource) still reaches exchange — the one param intentionally
// on both legs — so the assertion distinguishes the two rather than proving the
// exchange form is merely empty.
func TestLoginAuthParamsAbsentFromTokenExchange(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()

	_, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Audience:      "https://broker.example.com",
		AudienceParam: "resource",
		Scopes:        "postern/cli-access",
		AuthParams:    map[string]string{"idp_identifier": "mydomain.com"},
		Store:         &recordingTokenSaver{},
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got := idp.authorizeQuery.Get("idp_identifier"); got != "mydomain.com" {
		t.Fatalf("idp_identifier on authorize = %q, want mydomain.com", got)
	}
	if got := idp.tokenForm.Get("idp_identifier"); got != "" {
		t.Fatalf("idp_identifier leaked onto token exchange = %q, want empty", got)
	}
	if got := idp.tokenForm.Get("resource"); got != "https://broker.example.com" {
		t.Fatalf("resource missing from token exchange = %q, want the audience", got)
	}
}

// TestValidateAuthParams exercises the single-source reserved-param helper:
// each of the eight fixed keys the OAuth flow controls is rejected, the
// effective audience_param is rejected when set, an empty audience_param skips
// only that entry (fixed keys still enforced), and unrelated / empty maps pass.
func TestValidateAuthParams(t *testing.T) {
	fixed := []string{
		"client_id", "redirect_uri", "response_type", "scope", "state",
		"code_challenge", "code_challenge_method", "access_type",
	}
	for _, key := range fixed {
		if err := ValidateAuthParams(map[string]string{key: "x"}, "resource"); !errors.Is(err, ErrOAuthLoginReservedAuthParam) {
			t.Fatalf("ValidateAuthParams(%q) error = %v, want ErrOAuthLoginReservedAuthParam", key, err)
		}
	}

	if err := ValidateAuthParams(map[string]string{"resource": "x"}, "resource"); !errors.Is(err, ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("ValidateAuthParams(resource, audienceParam=resource) error = %v, want reserved", err)
	}
	if err := ValidateAuthParams(map[string]string{"audience": "x"}, "audience"); !errors.Is(err, ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("ValidateAuthParams(audience, audienceParam=audience) error = %v, want reserved", err)
	}

	// Empty audience_param reserves only the fixed keys.
	if err := ValidateAuthParams(map[string]string{"resource": "x"}, ""); err != nil {
		t.Fatalf("ValidateAuthParams(resource, audienceParam=\"\") error = %v, want nil (empty audience param skips that entry)", err)
	}
	if err := ValidateAuthParams(map[string]string{"state": "x"}, ""); !errors.Is(err, ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("ValidateAuthParams(state, audienceParam=\"\") error = %v, want reserved (fixed keys always enforced)", err)
	}

	if err := ValidateAuthParams(map[string]string{"idp_identifier": "mydomain.com"}, "resource"); err != nil {
		t.Fatalf("ValidateAuthParams(idp_identifier) error = %v, want nil", err)
	}
	if err := ValidateAuthParams(nil, "resource"); err != nil {
		t.Fatalf("ValidateAuthParams(nil) error = %v, want nil", err)
	}
}

// TestLoginRejectsReservedAuthParam confirms Login's Options validation wires
// ValidateAuthParams — a reserved key fails fast before any network call,
// guarding the public-API contract for wrappers constructing Options directly.
func TestLoginRejectsReservedAuthParam(t *testing.T) {
	_, err := Login(context.Background(), Options{
		ProfileName:   "default",
		Issuer:        "https://issuer.example.com",
		ClientID:      "client-123",
		Scopes:        "postern/cli-access",
		AuthParams:    map[string]string{"state": "attacker"},
		Store:         &recordingTokenSaver{},
		BrowserOpen:   noopBrowserOpen,
		CallbackPorts: []int{0},
	})
	if !errors.Is(err, ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("Login() error = %v, want errors.Is(ErrOAuthLoginReservedAuthParam)", err)
	}
}

// TestLoginNoBrowserPrintsInstructionsAndSkipsBrowser proves --no-browser
// leaves the loopback flow intact: BrowserOpen is never called, the
// instructions (port + ssh -L hint + URL) reach Prompt, and the redirect
// still completes the exchange when the engineer opens the printed URL.
func TestLoginNoBrowserPrintsInstructionsAndSkipsBrowser(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()
	store := &recordingTokenSaver{}
	now := time.Unix(1777000000, 0)

	browserCalls := 0
	recordBrowser := func(context.Context, string) error {
		browserCalls++
		return nil
	}
	prompt := &browserlessPrompt{idp: idp}

	result, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Scopes:        "postern/cli-access",
		Store:         store,
		BrowserOpen:   recordBrowser,
		CallbackPorts: []int{0},
		NoBrowser:     true,
		Prompt:        prompt,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got, want := result.DisplayName(), "engineer@example.com"; got != want {
		t.Fatalf("DisplayName() = %q, want %q", got, want)
	}
	if browserCalls != 0 {
		t.Fatalf("BrowserOpen calls = %d, want 0 under --no-browser", browserCalls)
	}

	printed := prompt.String()
	for _, want := range []string{"ssh -L ", "127.0.0.1:", idp.URL()} {
		if !strings.Contains(printed, want) {
			t.Fatalf("instructions missing %q:\n%s", want, printed)
		}
	}
}

// TestLoginRejectsUnboundPinnedPort confirms a single unavailable pinned
// port fails fast instead of silently falling through to another port.
func TestLoginRejectsUnboundPinnedPort(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer occupied.Close()
	pinned := occupied.Addr().(*net.TCPAddr).Port

	_, err = Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Store:         &recordingTokenSaver{},
		BrowserOpen:   noopBrowserOpen,
		CallbackPorts: []int{pinned},
	})
	if err == nil {
		t.Fatal("Login() returned nil error binding an occupied pinned port")
	}
	if !strings.Contains(err.Error(), "bind loopback callback") {
		t.Fatalf("Login() error = %v, want bind loopback callback", err)
	}
}

// TestLoginPropagatesIdPCallbackErrorToCLI guards against the OAuth callback
// server swallowing ?error=... redirects, which would leave waitForCallback
// blocked until the engineer Ctrl-Cs. Each error branch in serveCallback
// pushes a typed callbackResponse so the CLI surfaces a real error instead
// of hanging.
func TestLoginPropagatesIdPCallbackErrorToCLI(t *testing.T) {
	cases := []struct {
		name         string
		query        url.Values
		wantSentinel error
	}{
		{
			name:         "error_query_param",
			query:        url.Values{"error": {"access_denied"}, "state": {"unused"}},
			wantSentinel: ErrOAuthCallbackError,
		},
		{
			name:         "state_mismatch",
			query:        url.Values{"state": {"wrong-state"}, "code": {"abc"}},
			wantSentinel: ErrOAuthCallbackStateMismatch,
		},
		{
			name:         "missing_code",
			query:        url.Values{"state": {"expected-state"}},
			wantSentinel: ErrOAuthCallbackMissingCode,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen() error = %v", err)
			}
			defer listener.Close()
			server, result := serveCallback(listener, "expected-state")
			defer shutdownServer(server)

			callbackURL := fmt.Sprintf("http://%s%s?%s", listener.Addr(), callbackPath, tc.query.Encode())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext() error = %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			resp.Body.Close()

			_, err = waitForCallback(ctx, result)
			if !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("waitForCallback() error = %v, want %v", err, tc.wantSentinel)
			}
		})
	}
}

// TestLoginRequiresAudienceParamWhenAudienceSet guards the public-API contract
// for wrappers that construct Options directly: pairing Audience with an empty
// AudienceParam would otherwise build an authorize URL with an empty parameter
// name (silent loss of RFC 8707 resource binding on accepting IdPs).
func TestLoginRequiresAudienceParamWhenAudienceSet(t *testing.T) {
	_, err := Login(context.Background(), Options{
		ProfileName:   "default",
		Issuer:        "https://issuer.example.com",
		ClientID:      "client-123",
		Audience:      "https://broker.example.com",
		AudienceParam: "",
		Store:         &recordingTokenSaver{},
		BrowserOpen:   noopBrowserOpen,
		CallbackPorts: []int{0},
	})
	if !errors.Is(err, ErrOAuthLoginAudienceParamRequired) {
		t.Fatalf("Login() error = %v, want errors.Is(ErrOAuthLoginAudienceParamRequired)", err)
	}
}

// TestLoginRejectsIDTokenWithoutSubject locks the post-verify check:
// a signed id_token that nonetheless lacks the canonical "sub" claim
// fails Login with the typed sentinel. Together with the verifier
// itself (which rejects unsigned / wrong-issuer / expired tokens),
// this prevents the CLI from caching unauthenticated identity data
// in the keychain.
func TestLoginRejectsIDTokenWithoutSubject(t *testing.T) {
	idp := newFakeIDP(t)
	defer idp.Close()
	idp.idClaims = map[string]any{"email": "engineer@example.com"} // no sub

	_, err := Login(context.Background(), Options{
		ProfileName:   "staging",
		Issuer:        idp.URL(),
		ClientID:      "client-123",
		Audience:      "https://broker.example.com",
		AudienceParam: "resource",
		Scopes:        "postern/cli-access",
		Store:         &recordingTokenSaver{},
		BrowserOpen:   idp.OpenBrowser,
		CallbackPorts: []int{0},
	})
	if !errors.Is(err, ErrOAuthLoginIDTokenMissingSubject) {
		t.Fatalf("Login() error = %v, want errors.Is(ErrOAuthLoginIDTokenMissingSubject)", err)
	}
}

// TestLoginSurfacesDiscoveryAndExchangeSentinels regression-guards the
// runtime-side error vocabulary: discovery and exchange branches return
// errors that wrap the matching ErrOAuth* sentinel, so a wrapper distinguishing
// IdP outages from validation failures via errors.Is keeps working.
func TestLoginSurfacesDiscoveryAndExchangeSentinels(t *testing.T) {
	t.Run("discovery_returns_500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			http.Error(writer, "kaboom", http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := Login(context.Background(), Options{
			ProfileName:   "default",
			Issuer:        server.URL,
			ClientID:      "client-123",
			Store:         &recordingTokenSaver{},
			BrowserOpen:   noopBrowserOpen,
			CallbackPorts: []int{0},
		})
		if !errors.Is(err, ErrOAuthDiscovery) {
			t.Fatalf("Login() error = %v, want errors.Is(ErrOAuthDiscovery)", err)
		}
	})

	t.Run("exchange_returns_400", func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.exchangeStatus = http.StatusBadRequest
		idp.exchangeBody = `{"error":"invalid_grant","error_description":"bad code"}`
		defer idp.Close()

		_, err := Login(context.Background(), Options{
			ProfileName:   "default",
			Issuer:        idp.URL(),
			ClientID:      "client-123",
			Store:         &recordingTokenSaver{},
			BrowserOpen:   idp.OpenBrowser,
			CallbackPorts: []int{0},
		})
		if !errors.Is(err, ErrOAuthExchange) {
			t.Fatalf("Login() error = %v, want errors.Is(ErrOAuthExchange)", err)
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Fatalf("Login() error = %q, want body in error chain", err.Error())
		}
	})
}

func noopBrowserOpen(context.Context, string) error {
	return nil
}

func assertQueryValue(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Fatalf("authorize param %q = %q, want %q", key, got, want)
	}
}

// browserlessPrompt captures Login's --no-browser instructions and, on
// seeing the authorization URL, drives the IdP redirect once — standing in
// for the engineer opening the printed URL in a browser elsewhere.
type browserlessPrompt struct {
	idp  *fakeIDP
	mu   sync.Mutex
	buf  strings.Builder
	once sync.Once
}

func (p *browserlessPrompt) Write(b []byte) (int, error) {
	p.mu.Lock()
	n, err := p.buf.Write(b)
	text := p.buf.String()
	p.mu.Unlock()

	if authURL := firstURL(text); authURL != "" {
		p.once.Do(func() {
			go func() { _ = p.idp.OpenBrowser(context.Background(), authURL) }()
		})
	}
	return n, err
}

func (p *browserlessPrompt) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

// firstURL returns the first whitespace-terminated http(s) URL in text, or
// "" if none has been fully written yet.
func firstURL(text string) string {
	idx := strings.Index(text, "http://")
	if idx == -1 {
		idx = strings.Index(text, "https://")
	}
	if idx == -1 {
		return ""
	}
	rest := text[idx:]
	if cut := strings.IndexAny(rest, " \r\n"); cut != -1 {
		return rest[:cut]
	}
	return ""
}

type recordingTokenSaver struct {
	profile string
	state   tokenstore.State
}

func (s *recordingTokenSaver) Save(profile string, state tokenstore.State) error {
	s.profile = profile
	s.state = state
	return nil
}

type fakeIDP struct {
	t                 *testing.T
	server            *httptest.Server
	accessToken       string
	authorizeQuery    url.Values
	authorizeRawQuery string
	tokenForm         url.Values
	codeChallenge     string
	exchangeStatus    int
	exchangeBody      string

	signingKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	clientID   string // used as id_token aud; set by tests via WithClientID
	idClaims   map[string]any
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	idp := &fakeIDP{
		t:           t,
		accessToken: fakeJWT(t, map[string]any{"sub": "subject-123", "exp": 1777003600}),
		signingKey:  priv,
		publicKey:   pub,
		keyID:       "fake-idp-key-1",
		clientID:    "client-123",
		idClaims: map[string]any{
			"sub":   "subject-123",
			"email": "engineer@example.com",
			"iat":   1776999900,
		},
	}
	server := httptest.NewServer(http.HandlerFunc(idp.ServeHTTP))
	idp.server = server
	return idp
}

func (s *fakeIDP) URL() string {
	return s.server.URL
}

func (s *fakeIDP) Close() {
	s.server.Close()
}

func (s *fakeIDP) OpenBrowser(ctx context.Context, loginURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("browser flow status %s", resp.Status)
	}
	return nil
}

func (s *fakeIDP) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.t.Helper()
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		writeDiscoveryDoc(writer, s.server.URL)
	case "/.well-known/jwks.json":
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       s.publicKey,
			KeyID:     s.keyID,
			Algorithm: "EdDSA",
			Use:       "sig",
		}}})
	case "/authorize":
		s.authorizeQuery = request.URL.Query()
		s.authorizeRawQuery = request.URL.RawQuery
		s.codeChallenge = s.authorizeQuery.Get("code_challenge")
		redirectURI := s.authorizeQuery.Get("redirect_uri")
		state := s.authorizeQuery.Get("state")
		if redirectURI == "" || state == "" || s.codeChallenge == "" {
			http.Error(writer, "bad authorize request", http.StatusBadRequest)
			return
		}
		callback, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query := callback.Query()
		query.Set("code", "auth-code-123")
		query.Set("state", state)
		callback.RawQuery = query.Encode()
		http.Redirect(writer, request, callback.String(), http.StatusFound)
	case "/token":
		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		s.tokenForm = request.PostForm
		if s.exchangeStatus != 0 {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(s.exchangeStatus)
			_, _ = writer.Write([]byte(s.exchangeBody))
			return
		}
		if got, want := request.PostForm.Get("grant_type"), "authorization_code"; got != want {
			http.Error(writer, "bad grant_type", http.StatusBadRequest)
			return
		}
		if got, want := request.PostForm.Get("code"), "auth-code-123"; got != want {
			http.Error(writer, "bad code", http.StatusBadRequest)
			return
		}
		if got, want := challengeForVerifier(request.PostForm.Get("code_verifier")), s.codeChallenge; got != want {
			http.Error(writer, "bad code_verifier", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token":             s.accessToken,
			"id_token":                 s.signIDToken(),
			"refresh_token":            "refresh-token-123",
			"expires_in":               3600,
			"refresh_token_expires_in": 86400,
		})
	default:
		http.NotFound(writer, request)
	}
}

// writeDiscoveryDoc serves a complete-enough OIDC discovery doc for
// oidc.NewProvider's strict-validation pass — the library checks that the
// issuer matches the URL it was given, and rejects docs missing
// id_token_signing_alg_values_supported, subject_types_supported, or
// response_types_supported.
func writeDiscoveryDoc(writer http.ResponseWriter, issuer string) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"code"},
	})
}

func challengeForVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// signIDToken returns an EdDSA-signed id_token whose claims are
// s.idClaims plus the iss/aud/exp values go-oidc requires. Tests that
// want to vary the claims (e.g. drop "sub") mutate s.idClaims before
// calling Login.
func (s *fakeIDP) signIDToken() string {
	s.t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: s.signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.keyID),
	)
	if err != nil {
		s.t.Fatalf("jose.NewSigner() error = %v", err)
	}
	claims := map[string]any{
		"iss": s.server.URL,
		"aud": s.clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range s.idClaims {
		claims[k] = v
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		s.t.Fatalf("jwt.Signed().Serialize() error = %v", err)
	}
	return token
}

// fakeJWT signs a JWT with HS256 against a throwaway key. The production
// accessTokenExpiry parses with UnsafeClaimsWithoutVerification — it never
// verifies the signature, only reads `exp` — so the key value is irrelevant
// to test outcomes. HS256 is the simplest alg go-jose v4 accepts; the test
// fixtures need to be go-jose-parseable, which `alg=none` is not.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("test-fixture-throwaway-key-32-bytes")},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func assertSavedState(t *testing.T, got tokenstore.State, want tokenstore.State) {
	t.Helper()
	if got != want {
		t.Fatalf("saved state = %#v, want %#v", got, want)
	}
}
