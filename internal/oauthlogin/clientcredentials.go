package oauthlogin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	ErrClientCredentialsClientSecretRequired = errors.New("client secret is required for the client-credentials grant")
	ErrClientCredentialsMissingAccessToken   = errors.New("client-credentials token response missing access_token")

	ErrOAuthClientCredentials = errors.New("oauth: client-credentials token request")
)

// ClientCredentialsOptions configures a ClientCredentialsToken call. Issuer,
// ClientID, and ClientSecret are required; one of Audience or Scopes must be
// set so the minted token is bound to the broker. There is no refresh token,
// no browser, and no loopback callback on this path.
type ClientCredentialsOptions struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	Audience      string
	AudienceParam string
	Scopes        string
	HTTPClient    *http.Client
}

// ClientCredentialsToken mints a fresh access token via the OAuth 2.0
// client-credentials grant. It discovers the IdP's token endpoint (the same
// discovery the PKCE path uses), then requests a token carrying the configured
// audience (via AudienceParam, e.g. RFC 8707 "resource") and/or scopes.
//
// Client-credentials grants have no refresh token, so the refresh-token gate
// the PKCE flow enforces does not apply here. Re-minting needs only the
// client_id + secret, so callers re-mint on demand rather than persisting
// refresh state.
func ClientCredentialsToken(ctx context.Context, options ClientCredentialsOptions) (string, error) {
	options = normalizeClientCredentialsOptions(options)
	if err := validateClientCredentialsOptions(options); err != nil {
		return "", err
	}

	discoverCtx, cancelDiscover := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	provider, err := oidc.NewProvider(discoverCtx, options.Issuer)
	cancelDiscover()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrOAuthDiscovery, err)
	}

	cfg := clientcredentials.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		TokenURL:     provider.Endpoint().TokenURL,
		Scopes:       strings.Fields(options.Scopes),
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	if options.Audience != "" {
		cfg.EndpointParams = url.Values{options.AudienceParam: []string{options.Audience}}
	}

	tokenCtx, cancelToken := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	token, err := cfg.Token(tokenCtx)
	cancelToken()
	if err != nil {
		return "", wrapTokenError(ErrOAuthClientCredentials, err)
	}

	if strings.TrimSpace(token.AccessToken) == "" {
		return "", ErrClientCredentialsMissingAccessToken
	}
	if _, err := accessTokenExpiry(token.AccessToken); err != nil {
		return "", fmt.Errorf("client-credentials access token expiry: %w", err)
	}

	return token.AccessToken, nil
}

func normalizeClientCredentialsOptions(options ClientCredentialsOptions) ClientCredentialsOptions {
	options.Issuer = strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	options.ClientID = strings.TrimSpace(options.ClientID)
	options.ClientSecret = strings.TrimSpace(options.ClientSecret)
	options.Audience = strings.TrimSpace(options.Audience)
	options.AudienceParam = strings.TrimSpace(options.AudienceParam)
	options.Scopes = strings.TrimSpace(options.Scopes)
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	return options
}

func validateClientCredentialsOptions(options ClientCredentialsOptions) error {
	var errs []error
	if options.Issuer == "" {
		errs = append(errs, ErrOAuthLoginIssuerRequired)
	}
	if options.ClientID == "" {
		errs = append(errs, ErrOAuthLoginClientIDRequired)
	}
	if options.ClientSecret == "" {
		errs = append(errs, ErrClientCredentialsClientSecretRequired)
	}
	if options.Audience != "" && options.AudienceParam == "" {
		errs = append(errs, ErrOAuthLoginAudienceParamRequired)
	}
	return errors.Join(errs...)
}
