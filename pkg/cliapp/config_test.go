package cliapp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigParsesProfiles(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
staging:
  broker: https://staging.example.com
  idp:
    issuer: https://idp-staging.example.com
    client_id: client-456
    scopes: postern/cli-access
`)

	if got, want := config.Profiles["default"].Broker, "https://postern.example.com"; got != want {
		t.Fatalf("default broker = %q, want %q", got, want)
	}
	if got, want := config.Profiles["staging"].IDP.Scopes, "postern/cli-access"; got != want {
		t.Fatalf("staging scopes = %q, want %q", got, want)
	}
}

// TestLoadConfigAcceptsUnknownFields locks in forward-compat: human-edited
// YAML is permitted to carry fields the current binary does not know about
// (e.g. older or newer config schemas; comments-as-fields).
func TestLoadConfigAcceptsUnknownFields(t *testing.T) {
	config, err := LoadConfig(strings.NewReader(`
default:
  broker: https://postern.example.com
  surprise: true
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil for unknown field", err)
	}
	if got, want := config.Profiles["default"].Broker, "https://postern.example.com"; got != want {
		t.Fatalf("default broker = %q, want %q", got, want)
	}
}

func TestLoadConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	if got, want := config.Profiles["default"].IDP.ClientID, "client-123"; got != want {
		t.Fatalf("client id = %q, want %q", got, want)
	}
}

func TestResolveProfileUsesDefaultProfile(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: emptyEnv})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}
	if got, want := resolved.Name, DefaultProfileName; got != want {
		t.Fatalf("resolved name = %q, want %q", got, want)
	}
	if got, want := resolved.Profile.IDP.AudienceParam, DefaultAudienceParam; got != want {
		t.Fatalf("audience param = %q, want %q", got, want)
	}
}

func TestResolveProfileSelectionPrecedence(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://default.example.com
  idp:
    issuer: https://idp-default.example.com
    client_id: default-client
    audience: https://default.example.com
env:
  broker: https://env.example.com
  idp:
    issuer: https://idp-env.example.com
    client_id: env-client
    audience: https://env.example.com
flag:
  broker: https://flag.example.com
  idp:
    issuer: https://idp-flag.example.com
    client_id: flag-client
    audience: https://flag.example.com
`)

	fromEnv, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{EnvName(DefaultEnvPrefix, profileEnvSuffix): "env"})})
	if err != nil {
		t.Fatalf("ResolveProfile(env) error = %v", err)
	}
	if got, want := fromEnv.Name, "env"; got != want {
		t.Fatalf("env-selected profile = %q, want %q", got, want)
	}

	fromFlag, err := config.ResolveProfile(ResolveProfileOptions{
		ProfileName: "flag",
		LookupEnv:   mapEnv(map[string]string{EnvName(DefaultEnvPrefix, profileEnvSuffix): "env"}),
	})
	if err != nil {
		t.Fatalf("ResolveProfile(flag) error = %v", err)
	}
	if got, want := fromFlag.Name, "flag"; got != want {
		t.Fatalf("flag-selected profile = %q, want %q", got, want)
	}
}

func TestResolveProfileAppliesEnvOverrides(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://file.example.com
  idp:
    issuer: https://idp-file.example.com
    client_id: file-client
    audience: https://file.example.com
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, brokerEnvSuffix):           " https://env.example.com ",
		EnvName(DefaultEnvPrefix, idpIssuerEnvSuffix):        "https://idp-env.example.com",
		EnvName(DefaultEnvPrefix, idpClientIDEnvSuffix):      "env-client",
		EnvName(DefaultEnvPrefix, idpAudienceEnvSuffix):      "https://audience-env.example.com",
		EnvName(DefaultEnvPrefix, idpAudienceParamEnvSuffix): "audience",
		EnvName(DefaultEnvPrefix, idpScopesEnvSuffix):        "postern/env-access",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	profile := resolved.Profile
	assertEqual(t, profile.Broker, "https://env.example.com", "broker")
	assertEqual(t, profile.IDP.Issuer, "https://idp-env.example.com", "issuer")
	assertEqual(t, profile.IDP.ClientID, "env-client", "client id")
	assertEqual(t, profile.IDP.Audience, "https://audience-env.example.com", "audience")
	assertEqual(t, profile.IDP.AudienceParam, "audience", "audience param")
	assertEqual(t, profile.IDP.Scopes, "postern/env-access", "scopes")
}

// TestResolveProfileDefaultSSHUserWirePaths covers the wire paths the
// DefaultSSHUser field rides on: the YAML scalar "default_ssh_user" and
// the env override "<PREFIX>_DEFAULT_SSH_USER". When neither is set,
// the field stays blank after ResolveProfile — the built-in
// DefaultSSHUser fallback happens later, in resolveUser, so the
// explicit/implicit distinction survives down to the ssh / scp
// argv-emit decision.
func TestResolveProfileDefaultSSHUserWirePaths(t *testing.T) {
	yamlConfig := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  default_ssh_user: yaml-ops
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`)

	resolvedYAML, err := yamlConfig.ResolveProfile(ResolveProfileOptions{LookupEnv: emptyEnv})
	if err != nil {
		t.Fatalf("ResolveProfile(yaml) error = %v", err)
	}
	if got, want := resolvedYAML.Profile.DefaultSSHUser, "yaml-ops"; got != want {
		t.Fatalf("YAML default_ssh_user = %q, want %q", got, want)
	}

	resolvedEnv, err := yamlConfig.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, defaultSSHUserEnvSuffix): "env-ops",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile(env) error = %v", err)
	}
	if got, want := resolvedEnv.Profile.DefaultSSHUser, "env-ops"; got != want {
		t.Fatalf("env default_ssh_user = %q, want %q (env override should win over YAML)", got, want)
	}

	bareConfig := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`)

	resolvedDefault, err := bareConfig.ResolveProfile(ResolveProfileOptions{LookupEnv: emptyEnv})
	if err != nil {
		t.Fatalf("ResolveProfile(default) error = %v", err)
	}
	if got := resolvedDefault.Profile.DefaultSSHUser; got != "" {
		t.Fatalf("default DefaultSSHUser = %q, want blank (WithDefaults must not inject the built-in fallback; resolveUser owns the chain)", got)
	}
}

func TestResolveProfileIgnoresEmptyEnvOverrides(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://file.example.com
  idp:
    issuer: https://idp-file.example.com
    client_id: file-client
    audience: https://file.example.com
    audience_param: audience
    scopes: postern/file-access
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, brokerEnvSuffix):           " ",
		EnvName(DefaultEnvPrefix, idpIssuerEnvSuffix):        "",
		EnvName(DefaultEnvPrefix, idpClientIDEnvSuffix):      "\t",
		EnvName(DefaultEnvPrefix, idpAudienceEnvSuffix):      "\n",
		EnvName(DefaultEnvPrefix, idpAudienceParamEnvSuffix): "  ",
		EnvName(DefaultEnvPrefix, idpScopesEnvSuffix):        "",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	profile := resolved.Profile
	assertEqual(t, profile.Broker, "https://file.example.com", "broker")
	assertEqual(t, profile.IDP.Issuer, "https://idp-file.example.com", "issuer")
	assertEqual(t, profile.IDP.ClientID, "file-client", "client id")
	assertEqual(t, profile.IDP.Audience, "https://file.example.com", "audience")
	assertEqual(t, profile.IDP.AudienceParam, "audience", "audience param")
	assertEqual(t, profile.IDP.Scopes, "postern/file-access", "scopes")
}

func TestResolveProfileUsesCustomEnvPrefix(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://file.example.com
  idp:
    issuer: https://idp-file.example.com
    client_id: file-client
    audience: https://file.example.com
env:
  broker: https://env-file.example.com
  idp:
    issuer: https://idp-env-file.example.com
    client_id: env-file-client
    audience: https://env-file.example.com
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{
		EnvPrefix: "acme-access",
		LookupEnv: mapEnv(map[string]string{
			"ACME_ACCESS_PROFILE":        "env",
			"ACME_ACCESS_BROKER":         "https://env.example.com",
			"ACME_ACCESS_IDP_CLIENT_ID":  "env-client",
			"ACME_ACCESS_IDP_AUDIENCE":   "https://audience-env.example.com",
			"POSTERN_PROFILE":            "default",
			"POSTERN_BROKER":             "https://wrong.example.com",
			"POSTERN_IDP_CLIENT_ID":      "wrong-client",
			"POSTERN_IDP_AUDIENCE":       "https://wrong.example.com",
			"POSTERN_IDP_AUDIENCE_PARAM": "wrong",
		}),
	})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	if got, want := resolved.Name, "env"; got != want {
		t.Fatalf("resolved name = %q, want %q", got, want)
	}
	assertEqual(t, resolved.Profile.Broker, "https://env.example.com", "broker")
	assertEqual(t, resolved.Profile.IDP.ClientID, "env-client", "client id")
	assertEqual(t, resolved.Profile.IDP.Audience, "https://audience-env.example.com", "audience")
	assertEqual(t, resolved.Profile.IDP.AudienceParam, DefaultAudienceParam, "audience param")
}

func TestEnvNaming(t *testing.T) {
	for _, tc := range []struct {
		binaryName string
		want       string
	}{
		{binaryName: "", want: DefaultEnvPrefix},
		{binaryName: "postern", want: "POSTERN"},
		{binaryName: "acme-access", want: "ACME_ACCESS"},
		{binaryName: "Acme Access", want: "ACME_ACCESS"},
		{binaryName: "my.app", want: "MY_APP"},
		{binaryName: "foo+bar", want: "FOO_BAR"},
		{binaryName: "__leading", want: "LEADING"},
	} {
		if got := EnvPrefixForBinaryName(tc.binaryName); got != tc.want {
			t.Fatalf("EnvPrefixForBinaryName(%q) = %q, want %q", tc.binaryName, got, tc.want)
		}
	}

	if got, want := EnvName("acme-access", idpScopesEnvSuffix), "ACME_ACCESS_IDP_SCOPES"; got != want {
		t.Fatalf("EnvName() = %q, want %q", got, want)
	}
}

func TestResolveProfileErrorsForMissingProfile(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
staging:
  broker: https://staging.example.com
  idp:
    issuer: https://idp-staging.example.com
    client_id: client-456
    audience: https://staging.example.com
`)

	_, err := config.ResolveProfile(ResolveProfileOptions{ProfileName: "prod", LookupEnv: emptyEnv})
	if err == nil {
		t.Fatal("ResolveProfile() returned nil error for missing profile")
	}
	for _, want := range []string{`profile "prod" not found`, "default", "staging"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing-profile error missing %q: %v", want, err)
		}
	}
}

func TestResolveProfileValidatesRequiredFields(t *testing.T) {
	config := Config{Profiles: map[string]Profile{
		"default": {
			IDP: IDPConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-123",
			},
		},
	}}

	_, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: emptyEnv})
	if err == nil {
		t.Fatal("ResolveProfile() returned nil error for invalid profile")
	}
	if !errors.Is(err, ErrBrokerRequired) {
		t.Fatalf("validation error = %v, want ErrBrokerRequired", err)
	}
	if !errors.Is(err, ErrIDPAudienceOrScopesRequired) {
		t.Fatalf("validation error = %v, want ErrIDPAudienceOrScopesRequired", err)
	}
}

func TestProfileWithDefaultsFillsAudienceParam(t *testing.T) {
	profile := Profile{
		Broker: "https://postern.example.com",
		IDP: IDPConfig{
			Issuer:   "https://idp.example.com",
			ClientID: "client-123",
			Audience: "https://postern.example.com",
		},
	}.WithDefaults()

	assertEqual(t, profile.IDP.AudienceParam, DefaultAudienceParam, "audience param")
}

func TestProfileValidateReturnsSentinels(t *testing.T) {
	err := Profile{
		IDP: IDPConfig{
			Issuer:   "https://idp.example.com",
			ClientID: "client-123",
		},
	}.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil error for missing required fields")
	}
	if !errors.Is(err, ErrBrokerRequired) {
		t.Fatalf("Validate() error = %v, want ErrBrokerRequired", err)
	}
	if !errors.Is(err, ErrIDPAudienceOrScopesRequired) {
		t.Fatalf("Validate() error = %v, want ErrIDPAudienceOrScopesRequired", err)
	}
}

func TestDefaultConfigPathUsesBinaryName(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	path, err := DefaultConfigPath("acme-access")
	if err != nil {
		t.Fatalf("DefaultConfigPath() error = %v", err)
	}
	if got, want := path, filepath.Join(homeDir, ".acme-access", "config.yaml"); got != want {
		t.Fatalf("DefaultConfigPath() = %q, want %q", got, want)
	}
}

func loadConfigForTest(t *testing.T, content string) Config {
	t.Helper()
	config, err := LoadConfig(strings.NewReader(content))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	return config
}

func emptyEnv(string) (string, bool) {
	return "", false
}

func mapEnv(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func assertEqual(t *testing.T, got string, want string, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", label, got, want)
	}
}
