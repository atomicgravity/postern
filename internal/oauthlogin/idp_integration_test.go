package oauthlogin_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/oauthlogin"
	"github.com/atomicgravity/postern/internal/tokenstore"
	"github.com/atomicgravity/postern/pkg/cliapp"
)

func TestConfiguredIDPAccessTokenProviderIntegration(t *testing.T) {
	if os.Getenv("POSTERN_IDP_INTEGRATION") != "1" {
		t.Skip("set POSTERN_IDP_INTEGRATION=1 to run against the configured IDP profile")
	}

	profile := loadIntegrationProfile(t)
	store := oauthlogin.TokenStore(tokenstore.NewKeychain(cliapp.DefaultBinaryName))
	if os.Getenv("POSTERN_IDP_FORCE_REFRESH") == "1" {
		store = forceRefreshStore{
			base:         store,
			expiredToken: unsignedJWT(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "sub": "expired-integration-placeholder"}),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := oauthlogin.AccessToken(ctx, oauthlogin.AccessTokenOptions{
		ProfileName: profile.Name,
		Issuer:      profile.Profile.IDP.Issuer,
		ClientID:    profile.Profile.IDP.ClientID,
		Store:       store,
	})
	if err != nil {
		t.Fatalf("AccessToken() error = %v", err)
	}

	claims := decodeJWTClaims(t, token)
	if got, want := stringClaim(claims, "iss"), profile.Profile.IDP.Issuer; got != want {
		t.Fatalf("iss = %q, want %q", got, want)
	}
	if profile.Profile.IDP.Audience != "" && !claimContains(claims["aud"], profile.Profile.IDP.Audience) {
		t.Fatalf("aud = %#v, want %q", claims["aud"], profile.Profile.IDP.Audience)
	}
	if exp, ok := numericClaim(claims, "exp"); !ok || exp <= time.Now().Unix() {
		t.Fatalf("exp = %#v, want future unix timestamp", claims["exp"])
	}
	assertExpectedClaims(t, claims, os.Getenv("POSTERN_IDP_EXPECT_CLAIMS"))

	t.Logf("access token ok: issuer=%s audience=%s subject=%s expected_claims=%s", stringClaim(claims, "iss"), profile.Profile.IDP.Audience, stringClaim(claims, "sub"), os.Getenv("POSTERN_IDP_EXPECT_CLAIMS"))
}

func loadIntegrationProfile(t *testing.T) cliapp.ResolvedProfile {
	t.Helper()
	configPath := strings.TrimSpace(os.Getenv("POSTERN_IDP_CONFIG"))
	if configPath == "" {
		var err error
		configPath, err = cliapp.DefaultConfigPath(cliapp.DefaultBinaryName)
		if err != nil {
			t.Fatalf("DefaultConfigPath() error = %v", err)
		}
	}
	config, err := cliapp.LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile(%q) error = %v", configPath, err)
	}
	profile, err := config.ResolveProfile(cliapp.ResolveProfileOptions{
		ProfileName: strings.TrimSpace(os.Getenv("POSTERN_IDP_PROFILE")),
		EnvPrefix:   cliapp.DefaultEnvPrefix,
		LookupEnv:   os.LookupEnv,
	})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}
	return profile
}

type forceRefreshStore struct {
	base         oauthlogin.TokenStore
	expiredToken string
}

func (s forceRefreshStore) Load(profile string) (tokenstore.State, error) {
	state, err := s.base.Load(profile)
	if err != nil {
		return tokenstore.State{}, err
	}
	state.AccessToken = s.expiredToken
	return state, nil
}

func (s forceRefreshStore) Save(profile string, state tokenstore.State) error {
	return s.base.Save(profile, state)
}

func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("token has %d parts, want at least 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode token claims: %v", err)
	}
	return claims
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func numericClaim(claims map[string]any, name string) (int64, bool) {
	switch value := claims[name].(type) {
	case float64:
		return int64(value), true
	case json.Number:
		number, err := value.Int64()
		return number, err == nil
	default:
		return 0, false
	}
}

func assertExpectedClaims(t *testing.T, claims map[string]any, expected string) {
	t.Helper()
	for _, field := range strings.Fields(expected) {
		name, want, ok := strings.Cut(field, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(want) == "" {
			t.Fatalf("expected claim %q must have form claim=value", field)
		}
		name = strings.TrimSpace(name)
		want = strings.TrimSpace(want)
		if !claimContains(claims[name], want) {
			t.Fatalf("%s = %s, want value %q", name, formatClaim(claims[name]), want)
		}
	}
}

func claimContains(value any, want string) bool {
	switch typed := value.(type) {
	case string:
		return typed == want || strings.Contains(" "+typed+" ", " "+want+" ")
	case []any:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	}
	return false
}

func formatClaim(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(data)
}
