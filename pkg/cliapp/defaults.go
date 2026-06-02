package cliapp

import (
	"context"
	"fmt"
	"io"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/brokerclient"
	"github.com/atomicgravity/postern/internal/oauthlogin"
	"github.com/atomicgravity/postern/internal/tokenstore"
	"github.com/spf13/cobra"
)

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

// defaultLoginRunner wires OAuth login. Captures binaryName so keychain
// namespacing matches the rest of the tokenstore calls.
func defaultLoginRunner(binaryName string) loginRunnerFunc {
	return func(ctx context.Context, profile ResolvedProfile, output io.Writer, opts loginOptions) error {
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
			Store:         tokenstore.NewKeychain(binaryName),
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
func defaultAccessToken(binaryName string) accessTokenFunc {
	return func(ctx context.Context, profile ResolvedProfile) (string, error) {
		return oauthlogin.AccessToken(ctx, oauthlogin.AccessTokenOptions{
			ProfileName: profile.Name,
			Issuer:      profile.Profile.IDP.Issuer,
			ClientID:    profile.Profile.IDP.ClientID,
			Store:       tokenstore.NewKeychain(binaryName),
		})
	}
}

func defaultSSHCertRequester(ctx context.Context, profile ResolvedProfile, accessToken string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
	return brokerclient.New(profile.Profile.Broker, nil).MintSSHCert(ctx, accessToken, request)
}

func defaultTimePayloadFetcher(ctx context.Context, profile ResolvedProfile, accessToken, deviceID, nonce string) (string, error) {
	return brokerclient.New(profile.Profile.Broker, nil).RequestTimePayload(ctx, accessToken, deviceID, nonce)
}

func defaultDeleteToken(binaryName string) deleteTokenFunc {
	return tokenstore.NewKeychain(binaryName).Delete
}
