package cliapp

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomicgravity/postern/internal/oauthlogin"
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

// TestLoadConfigParsesTokenStore locks the YAML wire path for the token_store
// field: it must survive LoadConfig and be whitespace-trimmed by trimProfile.
// If the yaml tag or the trimProfile line is dropped, config-file backend
// selection silently becomes a no-op (engineer sets token_store: file, gets
// the keychain anyway, with no error).
func TestLoadConfigParsesTokenStore(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
  token_store: "  file  "
`)

	assertEqual(t, config.Profiles["default"].TokenStore, "file", "token_store")
}

// TestSaveConfigRoundTripsTokenStore proves token_store survives a
// SaveConfig → LoadConfig round trip, and that an empty value emits no key
// (the omitempty tag) so existing configs don't grow a spurious token_store
// line on rewrite.
func TestSaveConfigRoundTripsTokenStore(t *testing.T) {
	config := Config{Profiles: map[string]Profile{
		"file-host": {
			Broker:     "https://postern.example.com",
			IDP:        IDPConfig{Issuer: "https://idp.example.com", ClientID: "c", Audience: "https://postern.example.com"},
			TokenStore: "file",
		},
		"plain": {
			Broker: "https://postern.example.com",
			IDP:    IDPConfig{Issuer: "https://idp.example.com", ClientID: "c", Audience: "https://postern.example.com"},
		},
	}}

	var buf strings.Builder
	if err := SaveConfig(&buf, config); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	reloaded, err := LoadConfig(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	assertEqual(t, reloaded.Profiles["file-host"].TokenStore, "file", "round-tripped token_store")
	assertEqual(t, reloaded.Profiles["plain"].TokenStore, "", "absent token_store")

	if strings.Contains(buf.String(), "token_store") && !strings.Contains(buf.String(), "token_store: file") {
		t.Fatalf("SaveConfig emitted an unexpected token_store key:\n%s", buf.String())
	}
}

// TestResolveProfileDoesNotApplyTokenStoreEnv guards that token_store is not
// merged by applyEnvOverrides: the env var is applied later, in
// defaultTokenStore, so the resolved profile must carry only the config-file
// value. If token_store is ever added to applyEnvOverrides, the env value
// double-applies and this test fails first. Do not delete this test.
func TestResolveProfileDoesNotApplyTokenStoreEnv(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
  token_store: keychain
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, tokenStoreEnvSuffix): "file",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	assertEqual(t, resolved.Profile.TokenStore, "keychain", "resolved token_store (env must not leak in)")
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

// TestProfileValidateGrant exercises the grant field: empty and the two known
// grants pass; an unknown grant fails with the typed sentinel. The
// client-credentials grant still requires client_id and one of
// audience/scopes (the secret is never a YAML field).
func TestProfileValidateGrant(t *testing.T) {
	base := func(grant string) Profile {
		return Profile{
			Broker: "https://postern.example.com",
			IDP: IDPConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-123",
				Audience: "https://postern.example.com",
				Grant:    grant,
			},
		}
	}

	for _, grant := range []string{"", GrantAuthorizationCode, GrantClientCredentials} {
		if err := base(grant).Validate(); err != nil {
			t.Fatalf("Validate() grant %q error = %v, want nil", grant, err)
		}
	}

	if err := base("device_code").Validate(); !errors.Is(err, ErrIDPUnknownGrant) {
		t.Fatalf("Validate() unknown grant error = %v, want ErrIDPUnknownGrant", err)
	}

	missingClientID := base(GrantClientCredentials)
	missingClientID.IDP.ClientID = ""
	if err := missingClientID.Validate(); !errors.Is(err, ErrIDPClientIDRequired) {
		t.Fatalf("Validate() client_credentials without client_id error = %v, want ErrIDPClientIDRequired", err)
	}

	missingBinding := base(GrantClientCredentials)
	missingBinding.IDP.Audience = ""
	missingBinding.IDP.Scopes = ""
	if err := missingBinding.Validate(); !errors.Is(err, ErrIDPAudienceOrScopesRequired) {
		t.Fatalf("Validate() client_credentials without audience/scopes error = %v, want ErrIDPAudienceOrScopesRequired", err)
	}
}

// TestLoadConfigParsesAuthParams locks the YAML wire path for auth_params: the
// map must survive LoadConfig and be whitespace-trimmed by trimProfile. If the
// yaml tag or the trimAuthParams line is dropped, operator-configured
// authorize-URL params silently vanish.
func TestLoadConfigParsesAuthParams(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
    auth_params:
      idp_identifier: "  mydomain.com  "
      login_hint: engineer@mydomain.com
`)

	want := map[string]string{"idp_identifier": "mydomain.com", "login_hint": "engineer@mydomain.com"}
	assertAuthParams(t, config.Profiles["default"].IDP.AuthParams, want)
}

// TestSaveConfigOmitsEmptyAuthParams proves the omitempty tag keeps an absent
// map out of the serialized YAML, so existing configs don't grow a spurious
// auth_params line on rewrite.
func TestSaveConfigOmitsEmptyAuthParams(t *testing.T) {
	var buf bytes.Buffer
	err := SaveConfig(&buf, Config{Profiles: map[string]Profile{
		"default": {
			Broker: "https://postern.example.com",
			IDP: IDPConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-123",
				Audience: "https://postern.example.com",
			},
		},
	}})
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	if strings.Contains(buf.String(), "auth_params") {
		t.Fatalf("serialized config contains auth_params when none was set:\n%s", buf.String())
	}
}

// TestResolveProfileParsesAuthParamsEnv covers the POSTERN_IDP_AUTH_PARAMS
// k=v,k=v override: keys/values are trimmed, and each pair splits on its first
// '=' so a value may itself contain '='.
func TestResolveProfileParsesAuthParamsEnv(t *testing.T) {
	config := authParamsBaseConfig(t)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, idpAuthParamsEnvSuffix): "idp_identifier=mydomain.com, login_hint = a@b.com ,token=x=y=z",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	want := map[string]string{
		"idp_identifier": "mydomain.com",
		"login_hint":     "a@b.com",
		"token":          "x=y=z",
	}
	assertAuthParams(t, resolved.Profile.IDP.AuthParams, want)
}

// TestResolveProfileAuthParamsEnvReplacesFileMap confirms the per-field
// override replaces the file map wholesale (no per-key merge): the file's
// "extra" key is gone once the env var is set.
func TestResolveProfileAuthParamsEnvReplacesFileMap(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
    auth_params:
      idp_identifier: file-domain.com
      extra: keep-me
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, idpAuthParamsEnvSuffix): "idp_identifier=env-domain.com",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	assertAuthParams(t, resolved.Profile.IDP.AuthParams, map[string]string{"idp_identifier": "env-domain.com"})
}

// TestResolveProfileAuthParamsEnvBlankKeepsFileMap confirms a blank/whitespace
// env value is treated as unset, leaving the file-configured map intact.
func TestResolveProfileAuthParamsEnvBlankKeepsFileMap(t *testing.T) {
	config := loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
    auth_params:
      idp_identifier: file-domain.com
`)

	resolved, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
		EnvName(DefaultEnvPrefix, idpAuthParamsEnvSuffix): "   ",
	})})
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}

	assertAuthParams(t, resolved.Profile.IDP.AuthParams, map[string]string{"idp_identifier": "file-domain.com"})
}

// TestResolveProfileAuthParamsEnvMalformed proves a malformed override fails
// fast at profile resolution with an error naming the env var — a typo must
// not silently no-op.
func TestResolveProfileAuthParamsEnvMalformed(t *testing.T) {
	config := authParamsBaseConfig(t)

	cases := map[string]string{
		"no_equals": "idp_identifier",
		"empty_key": "=mydomain.com",
		"mixed_bad": "idp_identifier=ok,broken",
	}
	for name, envVal := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.ResolveProfile(ResolveProfileOptions{LookupEnv: mapEnv(map[string]string{
				EnvName(DefaultEnvPrefix, idpAuthParamsEnvSuffix): envVal,
			})})
			if err == nil {
				t.Fatalf("ResolveProfile() error = nil, want malformed-env error for %q", envVal)
			}
			if !strings.Contains(err.Error(), "IDP_AUTH_PARAMS") {
				t.Fatalf("ResolveProfile() error = %v, want it to name IDP_AUTH_PARAMS", err)
			}
		})
	}
}

// TestProfileValidateRejectsReservedAuthParams is the AC #6 gate: a reserved
// authorize-URL parameter in auth_params is rejected at config validation with
// the shared oauthlogin sentinel — for each of the eight fixed keys and for the
// effective audience_param (both the default "resource" and an explicit
// override). A non-reserved param passes.
func TestProfileValidateRejectsReservedAuthParams(t *testing.T) {
	base := func() Profile {
		return Profile{
			Broker: "https://postern.example.com",
			IDP: IDPConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-123",
				Audience: "https://postern.example.com",
			},
		}.WithDefaults()
	}

	fixed := []string{
		"client_id", "redirect_uri", "response_type", "scope", "state",
		"code_challenge", "code_challenge_method", "access_type",
	}
	for _, key := range fixed {
		p := base()
		p.IDP.AuthParams = map[string]string{key: "x"}
		if err := p.Validate(); !errors.Is(err, oauthlogin.ErrOAuthLoginReservedAuthParam) {
			t.Fatalf("Validate() auth_params[%q] error = %v, want ErrOAuthLoginReservedAuthParam", key, err)
		}
	}

	pDefault := base()
	pDefault.IDP.AuthParams = map[string]string{DefaultAudienceParam: "x"}
	if err := pDefault.Validate(); !errors.Is(err, oauthlogin.ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("Validate() auth_params[%s] error = %v, want reserved (default audience_param)", DefaultAudienceParam, err)
	}

	pExplicit := Profile{
		Broker: "https://postern.example.com",
		IDP: IDPConfig{
			Issuer:        "https://idp.example.com",
			ClientID:      "client-123",
			Audience:      "https://postern.example.com",
			AudienceParam: "audience",
			AuthParams:    map[string]string{"audience": "x"},
		},
	}.WithDefaults()
	if err := pExplicit.Validate(); !errors.Is(err, oauthlogin.ErrOAuthLoginReservedAuthParam) {
		t.Fatalf("Validate() auth_params[audience] with audience_param=audience error = %v, want reserved", err)
	}

	pOK := base()
	pOK.IDP.AuthParams = map[string]string{"idp_identifier": "mydomain.com"}
	if err := pOK.Validate(); err != nil {
		t.Fatalf("Validate() auth_params[idp_identifier] error = %v, want nil", err)
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

func assertAuthParams(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("auth_params = %v, want %v", got, want)
	}
}

func authParamsBaseConfig(t *testing.T) Config {
	t.Helper()
	return loadConfigForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`)
}
