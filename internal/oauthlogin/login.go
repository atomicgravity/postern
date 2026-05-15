// Package oauthlogin runs the CLI's OAuth 2.0 PKCE authorization-code flow
// (discovery, browser launch, loopback callback, token exchange) and
// refreshes cached access tokens via AccessToken.
package oauthlogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/tokenstore"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const callbackPath = "/cb"

const defaultHTTPTimeout = 30 * time.Second

// defaultCallbackPorts are the loopback ports the CLI tries in order when
// binding the OAuth callback listener. IdP redirect-URI allowlists must
// include all of them.
var defaultCallbackPorts = []int{50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010}

var (
	ErrOAuthLoginProfileRequired       = errors.New("profile name is required")
	ErrOAuthLoginIssuerRequired        = errors.New("issuer is required")
	ErrOAuthLoginClientIDRequired      = errors.New("client id is required")
	ErrOAuthLoginTokenStoreRequired    = errors.New("token store is required")
	ErrOAuthLoginAudienceParamRequired = errors.New("audience param is required when audience is set")

	ErrOAuthCallbackError         = errors.New("oauth callback returned error")
	ErrOAuthCallbackStateMismatch = errors.New("oauth callback state mismatch")
	ErrOAuthCallbackMissingCode   = errors.New("oauth callback missing code")

	ErrOAuthLoginMissingAccessToken    = errors.New("token response missing access_token")
	ErrOAuthLoginMissingRefreshToken   = errors.New("token response missing refresh_token")
	ErrOAuthLoginIDTokenMissingSubject = errors.New("id token missing sub")

	ErrOAuthDiscovery = errors.New("oauth: discover OIDC config")
	ErrOAuthExchange  = errors.New("oauth: exchange authorization code")
	ErrOAuthRefresh   = errors.New("oauth: refresh access token")
)

// BrowserOpenFunc launches the user's browser to loginURL.
type BrowserOpenFunc func(context.Context, string) error

// TokenSaver is the persistence half of a tokenstore that Login needs.
type TokenSaver interface {
	Save(profile string, state tokenstore.State) error
}

// Options configures a Login call. ProfileName, Issuer, ClientID, and Store
// are required; the rest fall back to production defaults.
type Options struct {
	ProfileName   string
	Issuer        string
	ClientID      string
	Audience      string
	AudienceParam string
	Scopes        string
	Store         TokenSaver
	HTTPClient    *http.Client
	BrowserOpen   BrowserOpenFunc
	CallbackPorts []int
	Now           func() time.Time
}

// Result is the engineer-identity summary Login returns to the CLI for the
// "Logged in as ..." display line.
type Result struct {
	Email   string
	Subject string
}

func (r Result) DisplayName() string {
	if r.Email != "" {
		return r.Email
	}
	return r.Subject
}

// Login runs the OAuth 2.0 authorization-code-with-PKCE flow end to end and
// persists the resulting state via Options.Store. Returns the verified
// engineer identity for the "Logged in as ..." display.
func Login(ctx context.Context, options Options) (Result, error) {
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return Result{}, err
	}

	listener, redirectURI, err := listenForCallback(options.CallbackPorts)
	if err != nil {
		return Result{}, err
	}
	defer listener.Close()

	state, err := randomURLString(32)
	if err != nil {
		return Result{}, err
	}
	verifier := oauth2.GenerateVerifier()

	discoverCtx, cancelDiscover := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	provider, err := oidc.NewProvider(discoverCtx, options.Issuer)
	cancelDiscover()
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrOAuthDiscovery, err)
	}
	cfg := newOAuthConfig(options, provider.Endpoint(), redirectURI)

	server, callbackResult := serveCallback(listener, state)
	defer shutdownServer(server)

	authOpts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.AccessTypeOffline}
	if options.Audience != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(options.AudienceParam, options.Audience))
	}
	authorizeURL := cfg.AuthCodeURL(state, authOpts...)

	if err := options.BrowserOpen(ctx, authorizeURL); err != nil {
		return Result{}, fmt.Errorf("open browser: %w", err)
	}

	callback, err := waitForCallback(ctx, callbackResult)
	if err != nil {
		return Result{}, err
	}

	exchangeOpts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	if options.Audience != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(options.AudienceParam, options.Audience))
	}
	exchangeCtx, cancelExchange := context.WithTimeout(httpClientCtx(ctx, options.HTTPClient), defaultHTTPTimeout)
	tokens, err := cfg.Exchange(exchangeCtx, callback.Code, exchangeOpts...)
	cancelExchange()
	if err != nil {
		return Result{}, wrapTokenError(ErrOAuthExchange, err)
	}

	if strings.TrimSpace(tokens.RefreshToken) == "" {
		return Result{}, ErrOAuthLoginMissingRefreshToken
	}
	if strings.TrimSpace(tokens.AccessToken) == "" {
		return Result{}, ErrOAuthLoginMissingAccessToken
	}
	if _, err := accessTokenExpiry(tokens.AccessToken); err != nil {
		return Result{}, fmt.Errorf("access token expiry: %w", err)
	}

	idToken, _ := tokens.Extra("id_token").(string)
	if strings.TrimSpace(idToken) == "" {
		return Result{}, errors.New("id token missing from token exchange response")
	}
	// Verify the id_token's signature / issuer / aud against the provider's
	// JWKs before trusting any of its claims — TLS-MITM on the token endpoint
	// could otherwise substitute arbitrary sub/email/iat into the CLI's
	// local keychain metadata and display.
	//
	// No SupportedSigningAlgs pin: the id_token never travels to the broker
	// (broker verifies access tokens). The worst case of alg-substitution
	// here is "wrong name in local display"; broker-side alg policy is
	// where that pin lives.
	idVerifier := provider.Verifier(&oidc.Config{ClientID: options.ClientID})
	verifiedID, err := idVerifier.Verify(ctx, idToken)
	if err != nil {
		return Result{}, fmt.Errorf("verify id token: %w", err)
	}
	var claims idTokenClaims
	if err := verifiedID.Claims(&claims); err != nil {
		return Result{}, fmt.Errorf("decode id token claims: %w", err)
	}
	claims.Subject = strings.TrimSpace(claims.Subject)
	claims.Email = strings.TrimSpace(claims.Email)
	if claims.Subject == "" {
		return Result{}, ErrOAuthLoginIDTokenMissingSubject
	}

	now := options.Now()
	issuedAt := claims.IssuedAt
	if issuedAt == 0 {
		issuedAt = now.Unix()
	}
	refreshExpiresAt := int64(0)
	if seconds := refreshTokenExpiresIn(tokens); seconds > 0 {
		refreshExpiresAt = now.Add(time.Duration(seconds) * time.Second).Unix()
	}

	stateToStore := tokenstore.State{
		IDPIssuer:             options.Issuer,
		IDPClientID:           options.ClientID,
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
		Subject:               claims.Subject,
		Email:                 claims.Email,
		IssuedAt:              issuedAt,
	}
	if err := options.Store.Save(options.ProfileName, stateToStore); err != nil {
		return Result{}, fmt.Errorf("save token state: %w", err)
	}

	return Result{Email: claims.Email, Subject: claims.Subject}, nil
}

// newOAuthConfig builds the per-call oauth2.Config. AuthStyleInParams is
// pinned because the CLI is a public client (no secret) and Basic auth has
// nothing to carry.
func newOAuthConfig(options Options, endpoint oauth2.Endpoint, redirectURI string) *oauth2.Config {
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &oauth2.Config{
		ClientID:    options.ClientID,
		Endpoint:    endpoint,
		RedirectURL: redirectURI,
		Scopes:      scopeList(options.Scopes),
	}
}

func scopeList(extra string) []string {
	scopes := []string{"openid", "email", "profile"}
	return append(scopes, strings.Fields(extra)...)
}

// httpClientCtx threads *http.Client through to oauth2 / go-oidc via the
// oauth2.HTTPClient context key so test fakes and HTTP timeouts take effect.
func httpClientCtx(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

// wrapTokenError joins sentinel with err, preserving any *oauth2.RetrieveError
// body so operators see exactly what the IdP returned.
func wrapTokenError(sentinel, err error) error {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && len(retrieveErr.Body) > 0 {
		return fmt.Errorf("%w: %w: %s", sentinel, err, strings.TrimSpace(string(retrieveErr.Body)))
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

// refreshTokenExpiresIn coerces the non-standard refresh_token_expires_in
// extra (Cognito, Okta) to seconds. Accepts both float64 (oauth2 library
// default JSON decode shape) and json.Number for forward-compat.
func refreshTokenExpiresIn(token *oauth2.Token) int64 {
	switch v := token.Extra("refresh_token_expires_in").(type) {
	case float64:
		return int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return 0
}

func normalizeOptions(options Options) Options {
	options.ProfileName = strings.TrimSpace(options.ProfileName)
	options.Issuer = strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	options.ClientID = strings.TrimSpace(options.ClientID)
	options.Audience = strings.TrimSpace(options.Audience)
	options.AudienceParam = strings.TrimSpace(options.AudienceParam)
	options.Scopes = strings.TrimSpace(options.Scopes)
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	if options.BrowserOpen == nil {
		options.BrowserOpen = openBrowser
	}
	if len(options.CallbackPorts) == 0 {
		options.CallbackPorts = defaultCallbackPorts
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return options
}

func validateOptions(options Options) error {
	var errs []error
	if options.ProfileName == "" {
		errs = append(errs, ErrOAuthLoginProfileRequired)
	}
	if options.Issuer == "" {
		errs = append(errs, ErrOAuthLoginIssuerRequired)
	}
	if options.ClientID == "" {
		errs = append(errs, ErrOAuthLoginClientIDRequired)
	}
	if options.Store == nil {
		errs = append(errs, ErrOAuthLoginTokenStoreRequired)
	}
	if options.Audience != "" && options.AudienceParam == "" {
		errs = append(errs, ErrOAuthLoginAudienceParamRequired)
	}
	return errors.Join(errs...)
}

func listenForCallback(ports []int) (net.Listener, string, error) {
	var lastErr error
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			lastErr = err
			continue
		}
		addr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			_ = listener.Close()
			return nil, "", fmt.Errorf("loopback listener returned non-TCP addr %T", listener.Addr())
		}
		return listener, fmt.Sprintf("http://127.0.0.1:%d%s", addr.Port, callbackPath), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no callback ports configured")
	}
	return nil, "", fmt.Errorf("bind loopback callback: %w", lastErr)
}

type callbackResponse struct {
	Code string
	Err  error
}

func serveCallback(listener net.Listener, expectedState string) (*http.Server, <-chan callbackResponse) {
	result := make(chan callbackResponse, 1)
	pushResult := func(response callbackResponse) {
		select {
		case result <- response:
		default:
		}
	}
	handler := http.NewServeMux()
	handler.HandleFunc(callbackPath, func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		if errText := query.Get("error"); errText != "" {
			http.Error(writer, errText, http.StatusBadRequest)
			pushResult(callbackResponse{Err: fmt.Errorf("%w: %s", ErrOAuthCallbackError, errText)})
			return
		}
		if query.Get("state") != expectedState {
			http.Error(writer, "invalid state", http.StatusBadRequest)
			pushResult(callbackResponse{Err: ErrOAuthCallbackStateMismatch})
			return
		}
		code := strings.TrimSpace(query.Get("code"))
		if code == "" {
			http.Error(writer, "missing code", http.StatusBadRequest)
			pushResult(callbackResponse{Err: ErrOAuthCallbackMissingCode})
			return
		}
		_, _ = io.WriteString(writer, "Login complete. You can close this tab.\n")
		pushResult(callbackResponse{Code: code})
	})
	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			pushResult(callbackResponse{Err: fmt.Errorf("callback server: %w", err)})
		}
	}()
	return server, result
}

func waitForCallback(ctx context.Context, result <-chan callbackResponse) (callbackResponse, error) {
	select {
	case callback := <-result:
		if callback.Err != nil {
			return callbackResponse{}, callback.Err
		}
		if callback.Code == "" {
			return callbackResponse{}, ErrOAuthCallbackMissingCode
		}
		return callback, nil
	case <-ctx.Done():
		return callbackResponse{}, ctx.Err()
	}
}

type idTokenClaims struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	IssuedAt int64  `json:"iat"`
}

func randomURLString(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func shutdownServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func openBrowser(ctx context.Context, loginURL string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
		args = []string{loginURL}
	case "windows":
		command = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", loginURL}
	default:
		command = "xdg-open"
		args = []string{loginURL}
	}
	return exec.CommandContext(ctx, command, args...).Start()
}
