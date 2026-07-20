package cliapp

import (
	"fmt"
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
	idpAuthParamsEnvSuffix    = "IDP_AUTH_PARAMS"
	idpScopesEnvSuffix        = "IDP_SCOPES"
	idpClientSecretEnvSuffix  = "IDP_CLIENT_SECRET"
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

func applyEnvOverrides(profile Profile, envPrefix string, lookupEnv func(string) (string, bool)) (Profile, error) {
	setStringFromEnv(&profile.Broker, EnvName(envPrefix, brokerEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Issuer, EnvName(envPrefix, idpIssuerEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.ClientID, EnvName(envPrefix, idpClientIDEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Audience, EnvName(envPrefix, idpAudienceEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.AudienceParam, EnvName(envPrefix, idpAudienceParamEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.IDP.Scopes, EnvName(envPrefix, idpScopesEnvSuffix), lookupEnv)
	setStringFromEnv(&profile.DefaultSSHUser, EnvName(envPrefix, defaultSSHUserEnvSuffix), lookupEnv)

	authParamsEnv := EnvName(envPrefix, idpAuthParamsEnvSuffix)
	if params, ok, err := authParamsFromEnv(authParamsEnv, lookupEnv); err != nil {
		return profile, err
	} else if ok {
		profile.IDP.AuthParams = params
	}

	return profile, nil
}

// authParamsFromEnv parses a <PREFIX>_IDP_AUTH_PARAMS override of the form
// "k=v,k=v". Pairs are comma-separated; each pair splits on its first '=' so
// values may contain '='. Keys and values are whitespace-trimmed. Empty (or
// whitespace-only) comma segments are skipped, which tolerates a trailing
// comma. A blank/unset env var returns ok=false, leaving any file-configured
// map intact; a non-blank value replaces the file map wholesale (per-field
// override semantics, matching the scalar fields and the broker's whole-block
// principal_classes override). A segment with no '=' or an empty key is a hard
// error — a typo like "idp_identifier" (missing "=value") must not silently
// no-op and send the engineer to the wrong IdP screen.
func authParamsFromEnv(name string, lookupEnv func(string) (string, bool)) (map[string]string, bool, error) {
	raw, ok := lookupEnv(name)
	if !ok {
		return nil, false, nil
	}
	if strings.TrimSpace(raw) == "" {
		return nil, false, nil
	}

	params := make(map[string]string)
	for _, segment := range strings.Split(raw, ",") {
		if strings.TrimSpace(segment) == "" {
			continue
		}
		key, value, found := strings.Cut(segment, "=")
		if !found {
			return nil, false, fmt.Errorf("%s: malformed entry %q (expected key=value)", name, segment)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, false, fmt.Errorf("%s: entry %q has an empty key", name, segment)
		}
		params[key] = strings.TrimSpace(value)
	}

	return params, true, nil
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
