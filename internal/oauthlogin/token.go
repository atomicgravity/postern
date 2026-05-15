package oauthlogin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/tokenstore"
	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const defaultAccessTokenRefreshSkew = time.Minute

// ErrLoginRequired covers conditions where AccessToken can't refresh on its
// own (no cached state, refresh-token expired, profile mismatch). The CLI
// surfaces this as "run `postern login`".
var ErrLoginRequired = errors.New("login required")

var (
	ErrAccessTokenProfileRequired     = errors.New("profile name is required")
	ErrAccessTokenIssuerRequired      = errors.New("issuer is required")
	ErrAccessTokenClientIDRequired    = errors.New("client id is required")
	ErrAccessTokenTokenStoreRequired  = errors.New("token store is required")
	ErrAccessTokenRefreshMissingToken = errors.New("refresh token response missing access_token")
)

// TokenStore is the load+save persistence interface AccessToken needs.
type TokenStore interface {
	Load(profile string) (tokenstore.State, error)
	Save(profile string, state tokenstore.State) error
}

// AccessTokenOptions configures an AccessToken call. ProfileName, Issuer,
// ClientID, and Store are required.
type AccessTokenOptions struct {
	ProfileName string
	Issuer      string
	ClientID    string
	Store       TokenStore
	HTTPClient  *http.Client
	Now         func() time.Time
	RefreshSkew time.Duration
}

// AccessToken returns a fresh access token for the given profile, refreshing
// via the IdP's refresh-token grant if the cached token is stale or close to
// expiry. Returns ErrLoginRequired when no usable cached state exists.
func AccessToken(ctx context.Context, options AccessTokenOptions) (string, error) {
	options = normalizeAccessTokenOptions(options)
	if err := validateAccessTokenOptions(options); err != nil {
		return "", err
	}

	state, err := options.Store.Load(options.ProfileName)
	if err != nil {
		if errors.Is(err, tokenstore.ErrNotFound) {
			return "", fmt.Errorf("%w: profile %q has no cached token state", ErrLoginRequired, options.ProfileName)
		}
		return "", err
	}
	if state.IDPIssuer != options.Issuer || state.IDPClientID != options.ClientID {
		return "", fmt.Errorf("%w: cached token state does not match resolved profile", ErrLoginRequired)
	}

	now := options.Now()
	if accessTokenFresh(state.AccessToken, now, options.RefreshSkew) {
		return state.AccessToken, nil
	}
	if state.RefreshTokenExpiresAt > 0 && state.RefreshTokenExpiresAt <= now.Unix() {
		return "", fmt.Errorf("%w: refresh token expired", ErrLoginRequired)
	}

	discoverCtx, cancelDiscover := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	provider, err := oidc.NewProvider(discoverCtx, options.Issuer)
	cancelDiscover()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrOAuthDiscovery, err)
	}
	cfg := newOAuthConfig(Options{ClientID: options.ClientID}, provider.Endpoint(), "")

	refreshCtx, cancelRefresh := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	tokens, err := cfg.TokenSource(refreshCtx, &oauth2.Token{RefreshToken: state.RefreshToken}).Token()
	cancelRefresh()
	if err != nil {
		return "", wrapTokenError(ErrOAuthRefresh, err)
	}

	if strings.TrimSpace(tokens.AccessToken) == "" {
		return "", ErrAccessTokenRefreshMissingToken
	}
	if _, err := accessTokenExpiry(tokens.AccessToken); err != nil {
		return "", fmt.Errorf("refresh token response access_token: %w", err)
	}

	state.AccessToken = tokens.AccessToken
	if strings.TrimSpace(tokens.RefreshToken) != "" {
		state.RefreshToken = tokens.RefreshToken
	}
	if seconds := refreshTokenExpiresIn(tokens); seconds > 0 {
		state.RefreshTokenExpiresAt = now.Add(time.Duration(seconds) * time.Second).Unix()
	}
	if err := options.Store.Save(options.ProfileName, state); err != nil {
		return "", fmt.Errorf("save refreshed token state: %w", err)
	}
	return state.AccessToken, nil
}

func normalizeAccessTokenOptions(options AccessTokenOptions) AccessTokenOptions {
	options.ProfileName = strings.TrimSpace(options.ProfileName)
	options.Issuer = strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	options.ClientID = strings.TrimSpace(options.ClientID)
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RefreshSkew == 0 {
		options.RefreshSkew = defaultAccessTokenRefreshSkew
	}
	if options.RefreshSkew < 0 {
		options.RefreshSkew = 0
	}
	return options
}

func validateAccessTokenOptions(options AccessTokenOptions) error {
	var errs []error
	if options.ProfileName == "" {
		errs = append(errs, ErrAccessTokenProfileRequired)
	}
	if options.Issuer == "" {
		errs = append(errs, ErrAccessTokenIssuerRequired)
	}
	if options.ClientID == "" {
		errs = append(errs, ErrAccessTokenClientIDRequired)
	}
	if options.Store == nil {
		errs = append(errs, ErrAccessTokenTokenStoreRequired)
	}
	return errors.Join(errs...)
}

func accessTokenFresh(token string, now time.Time, skew time.Duration) bool {
	expiresAt, err := accessTokenExpiry(token)
	if err != nil {
		return false
	}
	return expiresAt.After(now.Add(skew))
}

// accessTokenExpiry reads the JWT's `exp` claim. The token is NOT
// signature-verified here — the broker is the authoritative verifier; this
// reads `exp` only to decide whether to refresh proactively. The accepted-
// algorithm list is permissive on purpose: a wrong-alg token just gets
// rejected by the broker on the next request.
func accessTokenExpiry(token string) (time.Time, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("parse access token: %w", err)
	}
	var claims jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return time.Time{}, fmt.Errorf("decode access token claims: %w", err)
	}
	if claims.Expiry == nil {
		return time.Time{}, errors.New("access token missing exp")
	}
	return claims.Expiry.Time(), nil
}
