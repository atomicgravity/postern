package idp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestHasScopeSupportsScopeAndSCPClaims(t *testing.T) {
	if !hasScope("openid email postern/ssh", nil, "postern/ssh") {
		t.Fatal("hasScope() returned false for scope string")
	}
	if !hasScope("", []string{"openid", "postern/ssh"}, "postern/ssh") {
		t.Fatal("hasScope() returned false for scp array")
	}
	if hasScope("openid email", []string{"profile"}, "postern/ssh") {
		t.Fatal("hasScope() returned true for missing scope")
	}
}

func TestMergedGroupsDeduplicatesProviderClaims(t *testing.T) {
	got := mergedGroups([]string{"sre", "postern-engineers"}, []string{"postern-engineers", "ops"})
	want := []string{"sre", "postern-engineers", "ops"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergedGroups() = %v, want %v", got, want)
	}
}

// TestVerifyAccessTokenRejectsEmptyToken locks the cheap pre-flight rejection
// before the verifier is consulted. Don't delete: regression guard against the
// pre-flight branch being moved or removed.
// TestNewOIDCVerifierRequiresAudienceOrScope locks the wrapping-contract
// invariant: NewOIDCVerifier rejects a config with both Audience and
// RequiredScope empty so a wrapper that bypasses Config.Validate still
// can't end up with an unconstrained verifier (which would accept any
// token from the correct issuer, including those minted for other apps
// sharing the IdP client).
func TestNewOIDCVerifierRequiresAudienceOrScope(t *testing.T) {
	_, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer: "https://idp.example.com",
	})
	if !errors.Is(err, ErrAudienceOrScopeRequired) {
		t.Fatalf("NewOIDCVerifier() error = %v, want ErrAudienceOrScopeRequired", err)
	}
}

func TestVerifyAccessTokenRejectsEmptyToken(t *testing.T) {
	fixture := newOIDCFixture(t)
	verifier := fixture.newVerifier(t, "https://broker.example.com", "postern/ssh")

	for _, token := range []string{"", "   ", "\t\n"} {
		_, err := verifier.VerifyAccessToken(context.Background(), token)
		if err == nil {
			t.Fatalf("VerifyAccessToken(%q) returned nil error", token)
		}
		if !strings.Contains(err.Error(), "access token is required") {
			t.Fatalf("VerifyAccessToken(%q) error = %v, want contains %q", token, err, "access token is required")
		}
	}
}

// TestVerifyAccessTokenAcceptsValidToken is the happy-path locking test:
// well-formed access token with correct token_use, audience, and scope yields
// CallerClaims populated from the token.
func TestVerifyAccessTokenAcceptsValidToken(t *testing.T) {
	fixture := newOIDCFixture(t)
	verifier := fixture.newVerifier(t, "https://broker.example.com", "postern/ssh")

	now := time.Now()
	token := fixture.signToken(t, map[string]any{
		"iss":            fixture.server.URL,
		"sub":            "engineer-1234",
		"email":          "engineer@example.com",
		"aud":            []string{"https://broker.example.com"},
		"scope":          "openid postern/ssh",
		"token_use":      "access",
		"groups":         []string{"sre", "postern-engineers"},
		"cognito:groups": []string{"postern-engineers", "ops"},
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	})

	claims, err := verifier.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got, want := claims.Subject, "engineer-1234"; got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
	if got, want := claims.Email, "engineer@example.com"; got != want {
		t.Fatalf("email = %q, want %q", got, want)
	}
	wantGroups := []string{"sre", "postern-engineers", "ops"}
	if !reflect.DeepEqual(claims.Groups, wantGroups) {
		t.Fatalf("groups = %v, want %v", claims.Groups, wantGroups)
	}
	if claims.Raw["scope"] != "openid postern/ssh" {
		t.Fatalf("raw.scope = %v, want %q", claims.Raw["scope"], "openid postern/ssh")
	}
}

// TestVerifyAccessTokenRejectsMisbuiltTokens covers the five rejection
// branches that defend the broker's primary security boundary. Each case
// re-asserts a load-bearing AGENTS.md decision (EdDSA pin, access-token-only,
// audience binding, scope binding). Don't delete; if any of these branches
// regress, the broker accepts tokens it should not.
func TestVerifyAccessTokenRejectsMisbuiltTokens(t *testing.T) {
	fixture := newOIDCFixture(t)
	now := time.Now()
	baseClaims := func() map[string]any {
		return map[string]any{
			"iss":       fixture.server.URL,
			"sub":       "engineer-1234",
			"email":     "engineer@example.com",
			"aud":       []string{"https://broker.example.com"},
			"scope":     "openid postern/ssh",
			"token_use": "access",
			"iat":       now.Unix(),
			"exp":       now.Add(time.Hour).Unix(),
		}
	}

	cases := []struct {
		name     string
		audience string
		scope    string
		mutate   func(map[string]any)
		signWith ed25519.PrivateKey // nil → fixture.privateKey
		wantSub  string             // substring of error
	}{
		{
			name:     "wrong signature",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			signWith: newOtherEd25519Key(t),
			wantSub:  "failed to verify signature",
		},
		{
			name:     "token_use is id",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate:   func(c map[string]any) { c["token_use"] = "id" },
			wantSub:  "token_use must be access",
		},
		{
			name:     "audience missing required value",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate:   func(c map[string]any) { c["aud"] = []string{"https://wrong.example.com"} },
			wantSub:  "missing required audience",
		},
		{
			// Locks that the broker enforces audience against its
			// resource-server identifier, not go-oidc's default client_id
			// gate (disabled via SkipClientIDCheck). A token whose aud is
			// the IdP client_id would pass the legacy go-oidc check; it
			// must still fail Postern's separate audience match.
			name:     "audience is client-id-shaped value",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate:   func(c map[string]any) { c["aud"] = []string{"some-other-client-id"} },
			wantSub:  "missing required audience",
		},
		{
			name:     "scope missing required value",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate:   func(c map[string]any) { c["scope"] = "openid email" },
			wantSub:  "missing required scope",
		},
		{
			name:     "iat in the future",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate:   func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() },
			wantSub:  "iat is in the future",
		},
		{
			name:     "iat older than 24h",
			audience: "https://broker.example.com",
			scope:    "postern/ssh",
			mutate: func(c map[string]any) {
				c["iat"] = time.Now().Add(-25 * time.Hour).Unix()
				c["exp"] = time.Now().Add(time.Hour).Unix()
			},
			wantSub: "exceeds maximum age",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := fixture.newVerifier(t, tc.audience, tc.scope)
			claims := baseClaims()
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			signKey := fixture.privateKey
			if tc.signWith != nil {
				signKey = tc.signWith
			}
			token := fixture.signTokenWith(t, signKey, claims)

			_, err := verifier.VerifyAccessToken(context.Background(), token)
			if err == nil {
				t.Fatalf("VerifyAccessToken() returned nil error, want %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("VerifyAccessToken() error = %v, want contains %q", err, tc.wantSub)
			}
		})
	}
}

// TestClassifyEvaluatesPredicateForms covers each predicate form, first-match
// ordering, the default fallback, and the client_id read. The token's claim
// map drives classification entirely; no live IdP rule re-derivation happens
// downstream.
func TestClassifyEvaluatesPredicateForms(t *testing.T) {
	cases := []struct {
		name      string
		rules     []PrincipalClassRule
		mutate    func(map[string]any)
		wantClass string
	}{
		{
			name:      "no rules falls back to default user",
			rules:     nil,
			wantClass: "user",
		},
		{
			name: "claim_absent matches Cognito M2M token without username",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimAbsent, Claim: "username"},
			},
			wantClass: "machine",
		},
		{
			name: "claim_absent does not match when username present",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimAbsent, Claim: "username"},
			},
			mutate:    func(c map[string]any) { c["username"] = "alice" },
			wantClass: "user",
		},
		{
			name: "claim_absent treats a present-but-empty-string claim as absent",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimAbsent, Claim: "username"},
			},
			mutate:    func(c map[string]any) { c["username"] = "" },
			wantClass: "machine",
		},
		{
			name: "claim_absent treats a present-but-empty-array claim as absent",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimAbsent, Claim: "username"},
			},
			mutate:    func(c map[string]any) { c["username"] = []any{} },
			wantClass: "machine",
		},
		{
			name: "claim_present does not match a present-but-empty-string claim",
			rules: []PrincipalClassRule{
				{Class: "human", Predicate: PredicateClaimPresent, Claim: "username"},
			},
			mutate:    func(c map[string]any) { c["username"] = "" },
			wantClass: "user",
		},
		{
			name: "claim_present matches when username set",
			rules: []PrincipalClassRule{
				{Class: "human", Predicate: PredicateClaimPresent, Claim: "username"},
			},
			mutate:    func(c map[string]any) { c["username"] = "alice" },
			wantClass: "human",
		},
		{
			name: "claim equals matches Auth0 grant-type marker",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimEquals, Claim: "gty", Value: "client-credentials"},
			},
			mutate:    func(c map[string]any) { c["gty"] = "client-credentials" },
			wantClass: "machine",
		},
		{
			name: "claim equals matches a value inside a string array",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateClaimEquals, Claim: "roles", Value: "service"},
			},
			mutate:    func(c map[string]any) { c["roles"] = []any{"other", "service"} },
			wantClass: "machine",
		},
		{
			name: "scope_contains matches an M2M-only scope in the scope string",
			rules: []PrincipalClassRule{
				{Class: "machine", Predicate: PredicateScopeContains, Value: "postern/m2m"},
			},
			mutate:    func(c map[string]any) { c["scope"] = "openid postern/ssh postern/m2m" },
			wantClass: "machine",
		},
		{
			name: "first matching rule wins over a later rule",
			rules: []PrincipalClassRule{
				{Class: "first", Predicate: PredicateClaimAbsent, Claim: "username"},
				{Class: "second", Predicate: PredicateClaimPresent, Claim: "sub"},
			},
			wantClass: "first",
		},
	}

	fixture := newOIDCFixture(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := fixture.newClassifyingVerifier(t, "", tc.rules)
			now := time.Now()
			claims := map[string]any{
				"iss":       fixture.server.URL,
				"sub":       "caller-1",
				"aud":       []string{"https://broker.example.com"},
				"scope":     "openid postern/ssh",
				"token_use": "access",
				"iat":       now.Unix(),
				"exp":       now.Add(time.Hour).Unix(),
			}
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			token := fixture.signToken(t, claims)

			got, err := verifier.VerifyAccessToken(context.Background(), token)
			if err != nil {
				t.Fatalf("VerifyAccessToken() error = %v", err)
			}
			if got.Class != tc.wantClass {
				t.Fatalf("class = %q, want %q", got.Class, tc.wantClass)
			}
		})
	}
}

// TestClassifyHonorsConfiguredDefault locks the operator-set default class is
// used when no rule matches.
func TestClassifyHonorsConfiguredDefault(t *testing.T) {
	fixture := newOIDCFixture(t)
	verifier := fixture.newClassifyingVerifier(t, "robot", nil)
	now := time.Now()
	token := fixture.signToken(t, map[string]any{
		"iss":       fixture.server.URL,
		"sub":       "caller-1",
		"aud":       []string{"https://broker.example.com"},
		"scope":     "openid postern/ssh",
		"token_use": "access",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})

	got, err := verifier.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got.Class != "robot" {
		t.Fatalf("class = %q, want %q", got.Class, "robot")
	}
}

// TestVerifyAccessTokenReadsClientID locks the standard client_id claim read,
// present and absent.
func TestVerifyAccessTokenReadsClientID(t *testing.T) {
	fixture := newOIDCFixture(t)
	verifier := fixture.newVerifier(t, "https://broker.example.com", "postern/ssh")
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{
			"iss":       fixture.server.URL,
			"sub":       "caller-1",
			"aud":       []string{"https://broker.example.com"},
			"scope":     "openid postern/ssh",
			"token_use": "access",
			"iat":       now.Unix(),
			"exp":       now.Add(time.Hour).Unix(),
		}
	}

	withClient := base()
	withClient["client_id"] = "m2m-client-7"
	got, err := verifier.VerifyAccessToken(context.Background(), fixture.signToken(t, withClient))
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got.ClientID != "m2m-client-7" {
		t.Fatalf("client_id = %q, want %q", got.ClientID, "m2m-client-7")
	}

	got, err = verifier.VerifyAccessToken(context.Background(), fixture.signToken(t, base()))
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got.ClientID != "" {
		t.Fatalf("client_id = %q, want empty when claim absent", got.ClientID)
	}
}

// oidcFixture is a self-hosted EdDSA OIDC provider for verifier tests. It
// publishes discovery + JWKS via httptest.Server and signs tokens with a local
// ed25519 keypair so test cases can exercise each rejection branch without a
// live IdP.
type oidcFixture struct {
	server     *httptest.Server
	privateKey ed25519.PrivateKey
	keyID      string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	keyID := "test-key-1"

	mux := http.NewServeMux()
	fixture := &oidcFixture{privateKey: privateKey, keyID: keyID}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	fixture.server = server

	mux.HandleFunc("/.well-known/openid-configuration", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	})
	mux.HandleFunc("/jwks", func(response http.ResponseWriter, _ *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       publicKey,
			KeyID:     keyID,
			Algorithm: "EdDSA",
			Use:       "sig",
		}}}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(jwks)
	})

	return fixture
}

// newVerifier builds a fresh OIDCVerifier against the fixture. The verifier
// caches keys on the underlying go-oidc provider, so each test that wants a
// distinct audience/scope binding builds its own.
func (f *oidcFixture) newVerifier(t *testing.T, audience string, requiredScope string) *OIDCVerifier {
	t.Helper()
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:        f.server.URL,
		Audience:      audience,
		RequiredScope: requiredScope,
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	return verifier
}

// newClassifyingVerifier builds a verifier with a fixed audience/scope plus a
// principal-class default and rule list, for classification tests.
func (f *oidcFixture) newClassifyingVerifier(t *testing.T, defaultClass string, rules []PrincipalClassRule) *OIDCVerifier {
	t.Helper()
	verifier, err := NewOIDCVerifier(context.Background(), OIDCVerifierConfig{
		Issuer:                f.server.URL,
		Audience:              "https://broker.example.com",
		RequiredScope:         "postern/ssh",
		DefaultPrincipalClass: defaultClass,
		PrincipalClassRules:   rules,
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier() error = %v", err)
	}
	return verifier
}

func (f *oidcFixture) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	return f.signTokenWith(t, f.privateKey, claims)
}

func (f *oidcFixture) signTokenWith(t *testing.T, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.keyID),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Signed().Serialize() error = %v", err)
	}
	return token
}

func newOtherEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}
