// Package idp provides the broker's TokenVerifier impl. The v1 concrete is a
// generic OIDC access-token verifier built on go-oidc; it works with any
// spec-compliant OIDC provider (Cognito, Auth0, Okta, Keycloak, Azure AD,
// Google Workspace, internal OIDC). Audience and required-scope checks are
// configured per operator.
package idp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrAudienceOrScopeRequired is returned by NewOIDCVerifier when both
// Audience and RequiredScope are empty. The broker can refuse access tokens
// issued for other apps sharing the IdP only when at least one is set.
var ErrAudienceOrScopeRequired = errors.New("OIDCVerifier requires at least one of Audience or RequiredScope")

const (
	// iatFutureSkew tolerates tokens issued slightly in the future (IdP
	// clock briefly ahead of the broker's).
	iatFutureSkew = 5 * time.Minute

	// iatMaxAge bounds presented access tokens — past this age even a
	// future-dated exp can't justify treating the token as a current
	// authentication signal.
	iatMaxAge = 24 * time.Hour

	// Per-field rune caps on IdP-supplied claims. Bound downstream audit
	// rows under CloudWatch's 256KB-per-event limit and the DynamoDB
	// rate-limit partition key's 2KB cap against a misconfigured or
	// malicious IdP.
	maxSubjectRunes = 256
	maxEmailRunes   = 320
	maxGroupEntries = 64
	maxGroupRunes   = 64
)

// OIDCVerifierConfig configures an OIDCVerifier. Issuer is the OIDC issuer
// URL for discovery and JWKs fetch. At least one of Audience or
// RequiredScope must be set.
type OIDCVerifierConfig struct {
	Issuer        string
	Audience      string
	RequiredScope string
}

// OIDCVerifier validates IdP-issued access tokens against the configured
// audience and/or required scope and returns broker.EngineerClaims for
// Policy evaluation.
type OIDCVerifier struct {
	verifier      *oidc.IDTokenVerifier
	audience      string
	requiredScope string
	now           func() time.Time
}

func NewOIDCVerifier(ctx context.Context, config OIDCVerifierConfig) (*OIDCVerifier, error) {
	audience := strings.TrimSpace(config.Audience)
	requiredScope := strings.TrimSpace(config.RequiredScope)
	if audience == "" && requiredScope == "" {
		return nil, ErrAudienceOrScopeRequired
	}

	provider, err := oidc.NewProvider(ctx, strings.TrimSpace(config.Issuer))
	if err != nil {
		return nil, err
	}

	// SkipClientIDCheck disables go-oidc's default `aud == client_id` gate.
	// The broker's audience is its resource-server identifier, not the
	// client_id; the audience match below is what keeps tokens issued for
	// other apps out.
	//
	// SupportedSigningAlgs is asymmetric-only — the OIDC trust model gives
	// the verifier the IdP's public key, so HS* (symmetric, would need a
	// shared secret) and `none` are excluded.
	return &OIDCVerifier{
		verifier: provider.Verifier(&oidc.Config{
			SkipClientIDCheck:    true,
			SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"},
		}),
		audience:      audience,
		requiredScope: requiredScope,
		now:           time.Now,
	}, nil
}

// VerifyAccessToken validates the access token and returns EngineerClaims.
// The token must carry the configured audience and/or required scope;
// Cognito's token_use claim, if present, must be "access" to defend against
// ID-token-as-access-token misuse.
func (v *OIDCVerifier) VerifyAccessToken(ctx context.Context, accessToken string) (broker.EngineerClaims, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return broker.EngineerClaims{}, errors.New("access token is required")
	}

	token, err := v.verifier.Verify(ctx, accessToken)
	if err != nil {
		return broker.EngineerClaims{}, err
	}

	var claims accessTokenClaims
	if err := token.Claims(&claims); err != nil {
		return broker.EngineerClaims{}, err
	}

	var raw map[string]any
	if err := token.Claims(&raw); err != nil {
		return broker.EngineerClaims{}, err
	}

	if claims.TokenUse != "" && claims.TokenUse != "access" {
		return broker.EngineerClaims{}, errors.New("token_use must be access")
	}
	if v.audience != "" && !slices.Contains(token.Audience, v.audience) {
		return broker.EngineerClaims{}, errors.New("access token missing required audience")
	}
	if v.requiredScope != "" && !hasScope(claims.Scope, claims.SCP, v.requiredScope) {
		return broker.EngineerClaims{}, errors.New("access token missing required scope")
	}

	if claims.IssuedAt != 0 {
		iat := time.Unix(claims.IssuedAt, 0)
		now := v.now()
		if iat.After(now.Add(iatFutureSkew)) {
			return broker.EngineerClaims{}, errors.New("access token iat is in the future")
		}
		if iat.Before(now.Add(-iatMaxAge)) {
			return broker.EngineerClaims{}, fmt.Errorf("access token iat exceeds maximum age (%v)", iatMaxAge)
		}
	}

	// Empty sub: RFC 9068 requires sub on access tokens. Without this
	// check engineer_sub propagates as "" through rate-limit / audit /
	// AVP — collapsing identity tracking AND evading the per-engineer
	// rate-limit budget (the conditional UpdateItem would key on an
	// empty partition, shared across all sub-less callers).
	if strings.TrimSpace(claims.Subject) == "" {
		return broker.EngineerClaims{}, errors.New("access token sub claim is required")
	}

	// Reject over-length sub rather than truncating. Silent truncation
	// would let a malicious IdP craft "victim-sub-<long-suffix>" so the
	// first maxSubjectRunes runes collide with a real engineer's identity
	// — the audit row, rate-limit bucket, and cert KeyId would attribute
	// to the victim while AVP saw the attacker's full sub.
	if utf8.RuneCountInString(claims.Subject) > maxSubjectRunes {
		return broker.EngineerClaims{}, fmt.Errorf("access token sub exceeds %d runes", maxSubjectRunes)
	}
	if utf8.RuneCountInString(claims.Email) > maxEmailRunes {
		return broker.EngineerClaims{}, fmt.Errorf("access token email exceeds %d runes", maxEmailRunes)
	}

	return broker.EngineerClaims{
		Subject: claims.Subject,
		Email:   claims.Email,
		Groups:  capGroups(mergedGroups(claims.Groups, claims.CognitoGroups), maxGroupEntries, maxGroupRunes),
		Raw:     raw,
	}, nil
}

// capGroups truncates a groups list at maxEntries with each entry bounded
// at maxRunesPerEntry, bounding worst-case audit row / AVP context size.
func capGroups(groups []string, maxEntries int, maxRunesPerEntry int) []string {
	if len(groups) > maxEntries {
		groups = groups[:maxEntries]
	}
	for i, g := range groups {
		groups[i] = broker.TruncateRunes(g, maxRunesPerEntry)
	}
	return groups
}

type accessTokenClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	Scope         string   `json:"scope"`
	SCP           []string `json:"scp"`
	Groups        []string `json:"groups"`
	CognitoGroups []string `json:"cognito:groups"`
	TokenUse      string   `json:"token_use"`
	IssuedAt      int64    `json:"iat"`
}

func hasScope(scope string, scp []string, required string) bool {
	required = strings.TrimSpace(required)
	if required == "" {
		return true
	}
	for _, value := range strings.Fields(scope) {
		if value == required {
			return true
		}
	}
	return slices.Contains(scp, required)
}

func mergedGroups(groups []string, cognitoGroups []string) []string {
	seen := map[string]bool{}
	merged := make([]string, 0, len(groups)+len(cognitoGroups))
	for _, group := range append(groups, cognitoGroups...) {
		group = strings.TrimSpace(group)
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		merged = append(merged, group)
	}
	return merged
}
