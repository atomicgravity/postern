package cliapp

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/brokerclient"
	"github.com/atomicgravity/postern/internal/oauthlogin"
	"github.com/atomicgravity/postern/internal/tokenstore"
	"github.com/spf13/cobra"
)

// defaultTokenStore picks the tokenstore backend, applying precedence
// <PREFIX>_TOKEN_STORE env var > configBackend (the profile's token_store
// field) > default. The default is the OS keychain; "file" selects on-disk
// JSON under ~/.<binary-name>/tokens/ for hosts where the keychain is
// unreachable (no Secret Service, or D-Bus blocked by AppArmor).
//
// Precedence is resolved here rather than in applyEnvOverrides because logout
// selects the backend without full profile resolution and must share the rule.
func defaultTokenStore(binaryName string, configBackend string, envPrefix string, lookupEnv func(string) (string, bool)) (tokenstore.Store, error) {
	backend := strings.TrimSpace(configBackend)
	if value, ok := lookupEnv(EnvName(envPrefix, tokenStoreEnvSuffix)); ok {
		if value = strings.TrimSpace(value); value != "" {
			backend = value
		}
	}

	switch strings.ToLower(backend) {
	case "", "keychain", "keyring":
		return tokenstore.NewKeychain(binaryName), nil
	case "file":
		dir, err := BinaryHomeSubdir(binaryName, "tokens")
		if err != nil {
			return nil, err
		}
		return tokenstore.NewFile(dir), nil
	default:
		return nil, fmt.Errorf("unknown token store backend %q (want \"keychain\" or \"file\")", backend)
	}
}

// defaultProfileResolver wires the YAML-on-disk profile lookup.
func defaultProfileResolver(binaryName string, configPath string, envPrefix string, lookupEnv func(string) (string, bool)) profileResolverFunc {
	return func(command *cobra.Command) (ResolvedProfile, error) {
		resolvedConfigPath, err := resolveConfigPath(binaryName, configPath)
		if err != nil {
			return ResolvedProfile{}, err
		}

		config, err := LoadConfigFile(resolvedConfigPath)
		if err != nil {
			return ResolvedProfile{}, fmt.Errorf("load config %q: %w", resolvedConfigPath, err)
		}

		return config.ResolveProfile(ResolveProfileOptions{
			ProfileName: commandProfileName(command, lookupEnv),
			EnvPrefix:   envPrefix,
			LookupEnv:   lookupEnv,
		})
	}
}

// defaultLoginRunner wires OAuth login.
func defaultLoginRunner(binaryName string, envPrefix string, lookupEnv func(string) (string, bool)) loginRunnerFunc {
	return func(ctx context.Context, profile ResolvedProfile, output io.Writer, opts loginOptions) error {
		store, err := defaultTokenStore(binaryName, profile.Profile.TokenStore, envPrefix, lookupEnv)
		if err != nil {
			return err
		}

		var callbackPorts []int
		if opts.CallbackPort != 0 {
			callbackPorts = []int{opts.CallbackPort}
		}

		result, err := oauthlogin.Login(ctx, oauthlogin.Options{
			ProfileName:   profile.Name,
			Issuer:        profile.Profile.IDP.Issuer,
			ClientID:      profile.Profile.IDP.ClientID,
			Audience:      profile.Profile.IDP.Audience,
			AudienceParam: profile.Profile.IDP.AudienceParam,
			Scopes:        profile.Profile.IDP.Scopes,
			Store:         store,
			CallbackPorts: callbackPorts,
			NoBrowser:     opts.NoBrowser,
			Prompt:        output,
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "Logged in as %s\n", result.DisplayName())
		return err
	}
}

// defaultAccessToken loads / refreshes the cached access token.
func defaultAccessToken(binaryName string, envPrefix string, lookupEnv func(string) (string, bool)) accessTokenFunc {
	return func(ctx context.Context, profile ResolvedProfile) (string, error) {
		store, err := defaultTokenStore(binaryName, profile.Profile.TokenStore, envPrefix, lookupEnv)
		if err != nil {
			return "", err
		}
		return oauthlogin.AccessToken(ctx, oauthlogin.AccessTokenOptions{
			ProfileName: profile.Name,
			Issuer:      profile.Profile.IDP.Issuer,
			ClientID:    profile.Profile.IDP.ClientID,
			Store:       store,
		})
	}
}

func defaultSSHCertRequester(ctx context.Context, profile ResolvedProfile, accessToken string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
	return brokerclient.New(profile.Profile.Broker, nil).MintSSHCert(ctx, accessToken, request)
}

func defaultTimePayloadFetcher(ctx context.Context, profile ResolvedProfile, accessToken, deviceID, nonce string) (string, error) {
	return brokerclient.New(profile.Profile.Broker, nil).RequestTimePayload(ctx, accessToken, deviceID, nonce)
}

func defaultDeleteToken(binaryName string, envPrefix string, lookupEnv func(string) (string, bool)) deleteTokenFunc {
	return func(profile ResolvedProfile) error {
		store, err := defaultTokenStore(binaryName, profile.Profile.TokenStore, envPrefix, lookupEnv)
		if err != nil {
			return err
		}
		return store.Delete(profile.Name)
	}
}
