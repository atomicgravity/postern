package cliapp

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
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
)

var (
	ErrBrokerRequired              = errors.New("broker is required")
	ErrBrokerNotHTTPS              = errors.New("broker must use https (the CLI sends the bearer access token to this endpoint; plaintext exposes it to network MITM)")
	ErrIDPIssuerRequired           = errors.New("idp.issuer is required")
	ErrIDPIssuerNotHTTPS           = errors.New("idp.issuer must use https (the CLI fetches discovery + JWKs over this scheme and runs the OAuth flow against it; plaintext exposes the authorization code, refresh token, and tokens to network MITM)")
	ErrIDPClientIDRequired         = errors.New("idp.client_id is required")
	ErrIDPAudienceOrScopesRequired = errors.New("one of idp.audience or idp.scopes is required")
)

// Profile is a single named CLI profile: broker URL + IdP details.
// DefaultSSHUser is optional; resolveUser falls back at use time.
type Profile struct {
	Broker         string    `yaml:"broker"`
	IDP            IDPConfig `yaml:"idp"`
	DefaultSSHUser string    `yaml:"default_ssh_user,omitempty"`
}

// IDPConfig holds the OIDC client details. At least one of Audience or
// Scopes must be set so the access token can be bound to this broker.
type IDPConfig struct {
	Issuer        string `yaml:"issuer"`
	ClientID      string `yaml:"client_id"`
	Audience      string `yaml:"audience,omitempty"`
	AudienceParam string `yaml:"audience_param,omitempty"`
	Scopes        string `yaml:"scopes,omitempty"`
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

	profile = applyEnvOverrides(profile, envPrefix, lookupEnv).WithDefaults()
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
	return errors.Join(errs...)
}
