package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureWritesNewProfile(t *testing.T) {
	var stdout bytes.Buffer
	configPath := filepath.Join(t.TempDir(), "postern", "config.yaml")
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv, Stdout: &stdout})

	err := execute(context.Background(), root,
		"configure",
		"--broker", " https://postern.example.com ",
		"--idp-issuer", " https://idp.example.com ",
		"--idp-client-id", " client-123 ",
		"--idp-audience", " https://postern.example.com ",
		"--idp-audience-param", " audience ",
	)
	if err != nil {
		t.Fatalf("Run(configure) returned error: %v", err)
	}

	config, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	profile := config.Profiles[DefaultProfileName]
	assertEqual(t, profile.Broker, "https://postern.example.com", "broker")
	assertEqual(t, profile.IDP.Issuer, "https://idp.example.com", "issuer")
	assertEqual(t, profile.IDP.ClientID, "client-123", "client id")
	assertEqual(t, profile.IDP.Audience, "https://postern.example.com", "audience")
	assertEqual(t, profile.IDP.AudienceParam, "audience", "audience param")

	if !strings.Contains(stdout.String(), `Configured profile "default"`) {
		t.Fatalf("configure output = %q, want configured profile message", stdout.String())
	}
	assertFileMode(t, configPath, 0o600)
	assertFileMode(t, filepath.Dir(configPath), 0o700)
}

func TestConfigureMergesExistingProfile(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: old-client
    audience: https://postern.example.com
    audience_param: audience
staging:
  broker: https://staging.example.com
  idp:
    issuer: https://idp-staging.example.com
    client_id: staging-client
    scopes: postern/staging-access
`)
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root,
		"--profile", "default",
		"configure",
		"--idp-client-id", "new-client",
		"--idp-scopes", "postern/cli-access",
	)
	if err != nil {
		t.Fatalf("Run(configure) returned error: %v", err)
	}

	config, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	profile := config.Profiles["default"]
	assertEqual(t, profile.Broker, "https://postern.example.com", "broker")
	assertEqual(t, profile.IDP.Issuer, "https://idp.example.com", "issuer")
	assertEqual(t, profile.IDP.ClientID, "new-client", "client id")
	assertEqual(t, profile.IDP.Audience, "https://postern.example.com", "audience")
	assertEqual(t, profile.IDP.AudienceParam, "audience", "audience param")
	assertEqual(t, profile.IDP.Scopes, "postern/cli-access", "scopes")
	if _, ok := config.Profiles["staging"]; !ok {
		t.Fatal("staging profile was removed")
	}
}

// TestConfigureMergePreservesTokenStore is a regression guard: a merge-mode
// configure (no --replace) must not drop a field it has no flag for. An
// engineer who pinned token_store: file and later runs `configure
// --idp-client-id ...` must keep the file backend; silently wiping it would
// push them back to the keychain on the next login with no error. If a future
// commit reconstructs the profile from flags instead of merging onto the
// existing one, this test fails first. Do not delete this test.
func TestConfigureMergePreservesTokenStore(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: old-client
    audience: https://postern.example.com
  token_store: file
`)
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root,
		"configure",
		"--idp-client-id", "new-client",
	)
	if err != nil {
		t.Fatalf("Run(configure) returned error: %v", err)
	}

	config, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	profile := config.Profiles["default"]
	assertEqual(t, profile.IDP.ClientID, "new-client", "client id")
	assertEqual(t, profile.TokenStore, "file", "token_store preserved across merge")
}

func TestConfigureReplacesExistingProfile(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
default:
  broker: https://old.example.com
  idp:
    issuer: https://idp-old.example.com
    client_id: old-client
    audience: https://old.example.com
    audience_param: audience
    scopes: postern/old-access
`)
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root,
		"configure",
		"--replace",
		"--broker", "https://new.example.com",
		"--idp-issuer", "https://idp-new.example.com",
		"--idp-client-id", "new-client",
		"--idp-scopes", "postern/new-access",
	)
	if err != nil {
		t.Fatalf("Run(configure) returned error: %v", err)
	}

	config, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	profile := config.Profiles[DefaultProfileName]
	assertEqual(t, profile.Broker, "https://new.example.com", "broker")
	assertEqual(t, profile.IDP.Issuer, "https://idp-new.example.com", "issuer")
	assertEqual(t, profile.IDP.ClientID, "new-client", "client id")
	assertEqual(t, profile.IDP.Audience, "", "audience")
	assertEqual(t, profile.IDP.AudienceParam, "", "audience param")
	assertEqual(t, profile.IDP.Scopes, "postern/new-access", "scopes")
}

// TestConfigureDoesNotPersistDefaultedAudienceParam is a regression guard for
// the validate-before-defaults ordering in runConfigure. The intent: when the
// engineer does not pass --idp-audience-param, the persisted YAML must NOT
// contain a defaulted audience_param: resource line. Defaulting happens only
// at resolve time, so the saved profile preserves the engineer's omission. If
// a future commit reorders to apply defaults before validate, the YAML gains
// an audience_param entry and engineers upgrading would not notice — this
// test fails first. Do not delete this test.
func TestConfigureDoesNotPersistDefaultedAudienceParam(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "postern", "config.yaml")
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root,
		"configure",
		"--broker", "https://postern.example.com",
		"--idp-issuer", "https://idp.example.com",
		"--idp-client-id", "client-123",
		"--idp-audience", "https://postern.example.com",
	)
	if err != nil {
		t.Fatalf("Run(configure) returned error: %v", err)
	}

	// In-memory check: the loaded profile keeps AudienceParam empty because
	// LoadConfigFile doesn't apply defaults — defaults belong to resolve.
	config, err := LoadConfigFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFile() error = %v", err)
	}
	profile := config.Profiles[DefaultProfileName]
	assertEqual(t, profile.IDP.AudienceParam, "", "audience param")

	// Raw-YAML check: omitempty on AudienceParam means the key is absent
	// from the file entirely (not just empty). Reading the file lets us
	// catch a future change that writes `audience_param: ""` literally.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", configPath, err)
	}
	if strings.Contains(string(raw), "audience_param") {
		t.Fatalf("config file contains audience_param key when none was supplied:\n%s", raw)
	}
}

func TestConfigureRejectsInvalidProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	root := New(Options{ConfigPath: configPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root,
		"configure",
		"--broker", "https://postern.example.com",
		"--idp-issuer", "https://idp.example.com",
		"--idp-client-id", "client-123",
	)
	if err == nil {
		t.Fatal("Run(configure) returned nil error for invalid profile")
	}
	if !errors.Is(err, ErrIDPAudienceOrScopesRequired) {
		t.Fatalf("Run(configure) error = %v, want ErrIDPAudienceOrScopesRequired", err)
	}
	if _, statErr := os.Stat(configPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("config file exists after invalid configure: %v", statErr)
	}
}

// assertFileMode is a regression guard. The configure command writes the
// engineer's profile (broker URL, IdP issuer, client_id, optional
// audience/scopes) to ~/.<binary>/config.yaml. The file must be 0600 and the
// directory 0700 so a multi-user host doesn't expose IdP client identifiers
// or broker URLs to other accounts. If TestConfigureWritesNewProfile starts
// failing on the mode assertion, do not loosen the mode — fix the configure
// implementation to restore the tighter bits.
func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %q = %o, want %o", path, got, want)
	}
}
