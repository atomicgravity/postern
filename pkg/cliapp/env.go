package cliapp

import (
	"strings"
)

const (
	// DefaultEnvPrefix is the env-var prefix used when no binary name is
	// supplied. Wrappers with their own binary name produce a per-binary
	// prefix via EnvPrefixForBinaryName.
	DefaultEnvPrefix = "POSTERN"

	profileEnvSuffix          = "PROFILE"
	brokerEnvSuffix           = "BROKER"
	idpIssuerEnvSuffix        = "IDP_ISSUER"
	idpClientIDEnvSuffix      = "IDP_CLIENT_ID"
	idpAudienceEnvSuffix      = "IDP_AUDIENCE"
	idpAudienceParamEnvSuffix = "IDP_AUDIENCE_PARAM"
	idpScopesEnvSuffix        = "IDP_SCOPES"
	defaultSSHUserEnvSuffix   = "DEFAULT_SSH_USER"
	tokenStoreEnvSuffix       = "TOKEN_STORE"
)

// EnvPrefixForBinaryName derives a POSIX-safe env-var prefix from binaryName
// (e.g. "acme-access" -> "ACME_ACCESS"). An empty binaryName falls back to
// DefaultBinaryName.
func EnvPrefixForBinaryName(binaryName string) string {
	binaryName = strings.TrimSpace(binaryName)
	if binaryName == "" {
		binaryName = DefaultBinaryName
	}
	return normalizeEnvPrefix(binaryName)
}

// EnvName joins a normalized prefix and suffix with an underscore, returning
// e.g. "POSTERN_PROFILE" for prefix="POSTERN" suffix="PROFILE". An empty
// suffix returns the prefix alone.
func EnvName(prefix string, suffix string) string {
	prefix = normalizeEnvPrefix(prefix)
	if prefix == "" {
		prefix = DefaultEnvPrefix
	}
	suffix = normalizeEnvPrefix(suffix)
	if suffix == "" {
		return prefix
	}
	return prefix + "_" + suffix
}

func applyEnvOverrides(profile Profile, envPrefix string, lookupEnv func(string) (string, bool)) Profile {
	setStringFromEnv(&profile.Broker, EnvName(envPrefix, brokerEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Issuer, EnvName(envPrefix, idpIssuerEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.ClientID, EnvName(envPrefix, idpClientIDEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Audience, EnvName(envPrefix, idpAudienceEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.AudienceParam, EnvName(envPrefix, idpAudienceParamEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Scopes, EnvName(envPrefix, idpScopesEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.DefaultSSHUser, EnvName(envPrefix, defaultSSHUserEnvSuffix), lookupEnv)
	return profile
}

func setStringFromEnv(target *string, name string, lookupEnv func(string) (string, bool)) {
	if value, ok := lookupEnv(name); ok {
		if value = strings.TrimSpace(value); value != "" {
			*target = value
		}
	}
}

// normalizeEnvPrefix converts a free-form name into a POSIX-safe env-var prefix:
// uppercase, then any non-[A-Z0-9_] rune is replaced with '_', consecutive
// underscores collapse, and leading/trailing underscores are trimmed.
func normalizeEnvPrefix(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	value = builder.String()
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}
