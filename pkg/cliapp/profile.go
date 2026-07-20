package cliapp

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/oauthlogin"
	"github.com/spf13/cobra"
)

const (
	// DefaultProfileName is selected when --profile / $<BINARY>_PROFILE are
	// unset.
	DefaultProfileName = "default"

	// DefaultAudienceParam is the OAuth authorize-URL parameter signaling
	// the requested audience (RFC 8707).
	DefaultAudienceParam = "resource"

	// DefaultSSHUser is the fallback ssh user; matches the device's
	// AuthorizedPrincipalsFile convention.
	DefaultSSHUser = "engineer"

	ProfileFlagName = "profile"

	// GrantAuthorizationCode is the default OAuth grant: the browser-based
	// PKCE authorization-code flow for human engineers. An empty grant is
	// treated as this value.
	GrantAuthorizationCode = "authorization_code"

	// GrantClientCredentials selects the OAuth 2.0 client-credentials flow
	// for automated callers (service accounts). It is browserless and needs
	// no cached refresh token: the client_id + secret re-mint on demand.
	GrantClientCredentials = "client_credentials"
)

var (
	ErrBrokerRequired              = errors.New("broker is required")
	ErrBrokerNotHTTPS              = errors.New("broker must use https (the CLI sends the bearer access token to this endpoint; plaintext exposes it to network MITM)")
	ErrIDPIssuerRequired           = errors.New("idp.issuer is required")
	ErrIDPIssuerNotHTTPS           = errors.New("idp.issuer must use https (the CLI fetches discovery + JWKs over this scheme and runs the OAuth flow against it; plaintext exposes the authorization code, refresh token, and tokens to network MITM)")
	ErrIDPClientIDRequired         = errors.New("idp.client_id is required")
	ErrIDPAudienceOrScopesRequired = errors.New("one of idp.audience or idp.scopes is required")
	ErrIDPUnknownGrant             = errors.New("idp.grant must be empty, \"authorization_code\", or \"client_credentials\"")
)

// Profile is a single named CLI profile: broker URL + IdP details.
// DefaultSSHUser is optional; resolveUser falls back at use time.
//
// TokenStore selects the token persistence backend ("keychain" or "file").
// Its POSTERN_TOKEN_STORE env override is resolved in defaultTokenStore, not
// applyEnvOverrides.
type Profile struct {
	Broker         string    `yaml:"broker"`
	IDP            IDPConfig `yaml:"idp"`
	DefaultSSHUser string    `yaml:"default_ssh_user,omitempty"`
	TokenStore     string    `yaml:"token_store,omitempty"`
}

// IDPConfig holds the OIDC client details. At least one of Audience or
// Scopes must be set so the access token can be bound to this broker.
//
// Grant selects the OAuth flow: empty or "authorization_code" runs the
// browser PKCE flow for human engineers; "client_credentials" runs the
// browserless service-account flow. The client secret for the
// client-credentials flow is never read from this struct (or the config
// file) — it is sourced from <PREFIX>_IDP_CLIENT_SECRET at use time.
type IDPConfig struct {
	Issuer        string `yaml:"issuer"`
	ClientID      string `yaml:"client_id"`
	Audience      string `yaml:"audience,omitempty"`
	AudienceParam string `yaml:"audience_param,omitempty"`
	Scopes        string `yaml:"scopes,omitempty"`
	Grant         string `yaml:"grant,omitempty"`
	// AuthParams are extra query parameters appended to the OAuth authorize
	// URL only (browser PKCE flow). Keys colliding with a parameter the flow
	// controls are rejected by Validate. Never sent on token exchange,
	// refresh, or the client-credentials grant. Example: Cognito
	// idp_identifier to skip the enterprise email-first IdP-selection step.
	AuthParams map[string]string `yaml:"auth_params,omitempty"`
}

// usesClientCredentials reports whether the profile selects the
// client-credentials grant.
func (c IDPConfig) usesClientCredentials() bool {
	return c.Grant == GrantClientCredentials
}

// ResolvedProfile is a Profile after name selection, env-override merge,
// default-fill, and validation.
type ResolvedProfile struct {
	Name    string
	Profile Profile
}

// ResolveProfileOptions configures Config.ResolveProfile.
type ResolveProfileOptions struct {
	ProfileName string
	EnvPrefix   string
	LookupEnv   func(string) (string, bool)
}

// CommandProfileName returns the profile name from --profile or
// $<PREFIX>_PROFILE. Whitespace is stripped so downstream callers (cache
// layout, ssh.conf, audit) see a canonical form.
func CommandProfileName(command *cobra.Command) string {
	return commandProfileName(command, os.LookupEnv)
}

func commandProfileName(command *cobra.Command, lookupEnv func(string) (string, bool)) string {
	if command != nil {
		if value, err := command.Flags().GetString(ProfileFlagName); err == nil {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}

	envPrefix := DefaultEnvPrefix
	if command != nil {
		if root := command.Root(); root != nil {
			envPrefix = EnvPrefixForBinaryName(root.Name())
		}
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if value, ok := lookupEnv(EnvName(envPrefix, profileEnvSuffix)); ok {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}

	return DefaultProfileName
}

// ResolveProfile selects a profile, applies env overrides, fills defaults,
// and validates. ResolvedProfile.Name is whitespace-trimmed.
func (c Config) ResolveProfile(options ResolveProfileOptions) (ResolvedProfile, error) {
	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	envPrefix := normalizeEnvPrefix(options.EnvPrefix)
	if envPrefix == "" {
		envPrefix = DefaultEnvPrefix
	}

	// Profile-name precedence: explicit → $<PREFIX>_PROFILE → default.
	profileName := strings.TrimSpace(options.ProfileName)
	if profileName == "" {
		if value, ok := lookupEnv(EnvName(envPrefix, profileEnvSuffix)); ok {
			profileName = strings.TrimSpace(value)
		}
	}
	if profileName == "" {
		profileName = DefaultProfileName
	}

	if len(c.Profiles) == 0 {
		return ResolvedProfile{}, errors.New("no profiles configured")
	}

	profile, ok := c.Profiles[profileName]
	if !ok {
		return ResolvedProfile{}, fmt.Errorf("profile %q not found (available: %s)", profileName, strings.Join(c.ProfileNames(), ", "))
	}

	profile, err := applyEnvOverrides(profile, envPrefix, lookupEnv)
	if err != nil {
		return ResolvedProfile{}, fmt.Errorf("profile %q: %w", profileName, err)
	}
	profile = profile.WithDefaults()
	if err := profile.Validate(); err != nil {
		return ResolvedProfile{}, fmt.Errorf("profile %q: %w", profileName, err)
	}

	return ResolvedProfile{Name: profileName, Profile: profile}, nil
}

// ProfileNames returns the configured profile names sorted alphabetically.
func (c Config) ProfileNames() []string {
	return slices.Sorted(maps.Keys(c.Profiles))
}

// WithDefaults fills default values. Callers run Validate after.
//
// DefaultSSHUser is intentionally NOT populated here. resolveUser owns the
// entire fallback chain so it can distinguish "engineer set
// default_ssh_user explicitly" from "engineer didn't set it and the
// framework filled in the built-in." The implicit case skips emitting
// -l / -o User= at ssh/scp time so a `Host *` wildcard User directive in
// ~/.ssh/config keeps applying — injecting the built-in here would erase
// that signal.
func (p Profile) WithDefaults() Profile {
	if p.IDP.AudienceParam == "" {
		p.IDP.AudienceParam = DefaultAudienceParam
	}
	return p
}

// Validate returns nil if all required fields are set, or joined Err*
// sentinels otherwise. Broker + IDP.Issuer must be https or loopback —
// plaintext on either side exposes the OAuth flow (auth code, refresh
// token, tokens) to any on-path attacker.
func (p Profile) Validate() error {
	var errs []error
	if p.Broker == "" {
		errs = append(errs, ErrBrokerRequired)
	} else if !broker.IsHTTPSOrLoopback(p.Broker) {
		errs = append(errs, ErrBrokerNotHTTPS)
	}
	if p.IDP.Issuer == "" {
		errs = append(errs, ErrIDPIssuerRequired)
	} else if !broker.IsHTTPSOrLoopback(p.IDP.Issuer) {
		errs = append(errs, ErrIDPIssuerNotHTTPS)
	}
	if p.IDP.ClientID == "" {
		errs = append(errs, ErrIDPClientIDRequired)
	}
	if p.IDP.Audience == "" && p.IDP.Scopes == "" {
		errs = append(errs, ErrIDPAudienceOrScopesRequired)
	}
	switch p.IDP.Grant {
	case "", GrantAuthorizationCode, GrantClientCredentials:
	default:
		errs = append(errs, ErrIDPUnknownGrant)
	}
	// Reserved-param collisions are rejected here (config validation) using the
	// same set oauthlogin enforces on its Options — a single source of truth so
	// the two views can't drift. Runs after WithDefaults, so AudienceParam holds
	// the effective value (default "resource" or the configured override).
	if err := oauthlogin.ValidateAuthParams(p.IDP.AuthParams, p.IDP.AudienceParam); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
