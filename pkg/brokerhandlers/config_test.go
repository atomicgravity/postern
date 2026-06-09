package brokerhandlers

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadResolvedConfigUsesFileAndEnvOverrides(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_AUDIENCE":         "https://broker-env.example.com",
			"POSTERN_CERT_TTL_OPERATOR":    "10h",
			"POSTERN_TUNNELING_IOT_REGION": "us-west-2",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.IDP.Issuer, "https://idp.example.com"; got != want {
		t.Fatalf("issuer = %q, want %q", got, want)
	}
	if got, want := resolved.Config.IDP.Audience, "https://broker-env.example.com"; got != want {
		t.Fatalf("audience = %q, want %q", got, want)
	}
	if got, want := resolved.Config.CertTTL.Operator.Duration(), 10*time.Hour; got != want {
		t.Fatalf("operator ttl = %s, want %s", got, want)
	}
	if resolved.Config.Tunneling == nil || resolved.Config.Tunneling.IOTRegion != "us-west-2" {
		t.Fatalf("tunneling config = %#v, want us-west-2", resolved.Config.Tunneling)
	}
	if got, want := resolved.Sources["idp.issuer"], configPath; got != want {
		t.Fatalf("issuer source = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["idp.audience"], "POSTERN_IDP_AUDIENCE"; got != want {
		t.Fatalf("audience source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigAllowsEnvOnly(t *testing.T) {
	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.CertTTL.Operator.Duration(), 12*time.Hour; got != want {
		t.Fatalf("operator ttl = %s, want %s", got, want)
	}
	if got, want := resolved.Sources["cert_ttl.operator"], "default"; got != want {
		t.Fatalf("operator ttl source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigAllowsHTTPRegistry(t *testing.T) {
	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_HTTP_URL":          "https://registry.example.com/v1/resolve-device",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Registry.HTTPURL, "https://registry.example.com/v1/resolve-device"; got != want {
		t.Fatalf("registry http url = %q, want %q", got, want)
	}
	if got := resolved.Config.Registry.DynamoDBTable; got != "" {
		t.Fatalf("registry dynamodb table = %q, want empty", got)
	}
	if got, want := resolved.Sources["registry.http_url"], "POSTERN_REGISTRY_HTTP_URL"; got != want {
		t.Fatalf("registry http source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRegistryEnvOverrideSwitchesBackend(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_REGISTRY_HTTP_URL": "https://registry.example.com/v1/resolve-device",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got := resolved.Config.Registry.DynamoDBTable; got != "" {
		t.Fatalf("registry dynamodb table = %q, want empty", got)
	}
	if got, want := resolved.Config.Registry.HTTPURL, "https://registry.example.com/v1/resolve-device"; got != want {
		t.Fatalf("registry http url = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRejectsTwoRegistryBackends(t *testing.T) {
	_, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_REGISTRY_HTTP_URL":          "https://registry.example.com/v1/resolve-device",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
		}),
	})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error")
	}
	if !errors.Is(err, ErrRegistryBackendConflict) {
		t.Fatalf("error = %v, want ErrRegistryBackendConflict", err)
	}
	for _, want := range []string{"POSTERN_REGISTRY_DYNAMODB_TABLE", "POSTERN_REGISTRY_HTTP_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want to name %s", err, want)
		}
	}
}

func TestLoadResolvedConfigListenAddrFromFile(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
listen:
  addr: ":9090"
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Listen.Addr, ":9090"; got != want {
		t.Fatalf("listen.addr = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["listen.addr"], configPath; got != want {
		t.Fatalf("listen.addr source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigListenAddrFromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
listen:
  addr: ":9090"
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_BROKER_ADDR": ":7070",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Listen.Addr, ":7070"; got != want {
		t.Fatalf("listen.addr = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["listen.addr"], "POSTERN_BROKER_ADDR"; got != want {
		t.Fatalf("listen.addr source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigDefaultsListenAddr(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Listen.Addr, DefaultListenAddr; got != want {
		t.Fatalf("listen.addr = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["listen.addr"], "default"; got != want {
		t.Fatalf("listen.addr source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRequiresListenAddr(t *testing.T) {
	config := Config{
		Listen: ListenConfig{Addr: ""},
		IDP: IDPConfig{
			Issuer:   "https://idp.example.com",
			Audience: "https://broker.example.com",
		},
		Signer:    SignerConfig{KMSKeyARN: "arn:aws:kms:us-west-2:123:key/file"},
		Registry:  RegistryConfig{DynamoDBTable: "devices-file"},
		RateLimit: RateLimitConfig{DynamoDBTable: "ratelimit-file"},
		Audit:     AuditConfig{CloudWatchLogGroup: "/postern/audit-file"},
		Policy:    PolicyConfig{AVPPolicyStoreID: "policy-file"},
		CertTTL:   CertTTLConfig{Operator: Duration(8 * time.Hour)},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil error")
	}
	if !errors.Is(err, ErrListenAddrRequired) {
		t.Fatalf("Validate() error = %v, want ErrListenAddrRequired", err)
	}
}

func TestLoadResolvedConfigErrorsForExplicitMissingFile(t *testing.T) {
	_, err := LoadResolvedConfig(LoadConfigOptions{Path: filepath.Join(t.TempDir(), "missing.yaml"), LookupEnv: emptyBrokerEnv})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error")
	}
	if !strings.Contains(err.Error(), "load broker config") {
		t.Fatalf("error = %v, want load broker config", err)
	}
}

func TestLoadResolvedConfigRequiresFields(t *testing.T) {
	_, err := LoadResolvedConfig(LoadConfigOptions{Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")}, LookupEnv: emptyBrokerEnv})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error")
	}
	for _, sentinel := range []error{
		ErrIDPIssuerRequired,
		ErrSignerKMSKeyARNRequired,
		ErrRegistryBackendRequired,
		ErrPolicyStoreIDRequired,
	} {
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, missing sentinel %v", err, sentinel)
		}
	}
}

// TestLoadConfigAcceptsUnknownFields locks in forward-compat: human-edited
// broker config YAML is permitted to carry fields the current binary does not
// know about (e.g. older or newer config schemas; comments-as-fields).
func TestLoadConfigAcceptsUnknownFields(t *testing.T) {
	config, err := LoadConfig(strings.NewReader(`
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
  surprise: from-the-future
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
`))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil for unknown field", err)
	}
	if got, want := config.IDP.Issuer, "https://idp.example.com"; got != want {
		t.Fatalf("idp.issuer = %q, want %q", got, want)
	}
}

// TestLoadResolvedConfigRejectsInvalidDurationEnv locks the file/env-side
// symmetry: a malformed POSTERN_CERT_TTL_OPERATOR (e.g. the typo "12hh")
// must surface as a load error, not silently fall back to the default. The
// file-side Duration.UnmarshalYAML already errors on bad input — env-side
// must too. Don't delete: a regression to silent skip would let operators
// believe they configured a TTL they didn't.
func TestLoadResolvedConfigRejectsInvalidDurationEnv(t *testing.T) {
	_, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
			"POSTERN_CERT_TTL_OPERATOR":          "12hh",
		}),
	})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error for malformed duration")
	}
	if !strings.Contains(err.Error(), "POSTERN_CERT_TTL_OPERATOR") {
		t.Fatalf("error = %v, want to name POSTERN_CERT_TTL_OPERATOR", err)
	}
	if !strings.Contains(err.Error(), "12hh") {
		t.Fatalf("error = %v, want to include the rejected value 12hh", err)
	}
}

func TestLoadResolvedConfigRejectsInvalidIntEnv(t *testing.T) {
	_, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_RATELIMIT_LIMIT":            "lots",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
		}),
	})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error for malformed integer")
	}
	if !strings.Contains(err.Error(), "POSTERN_RATELIMIT_LIMIT") {
		t.Fatalf("error = %v, want to name POSTERN_RATELIMIT_LIMIT", err)
	}
}

// TestLoadResolvedConfigRateLimitDefaults pins the rate-limit defaults: when
// no YAML or env override is supplied, RateLimit.Limit/Window resolve to
// 60-per-minute. The fields are operator-tunable, but the default path must
// keep working without opting in.
func TestLoadResolvedConfigRateLimitDefaults(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.RateLimit.Limit, DefaultRateLimitLimit; got != want {
		t.Fatalf("ratelimit.limit = %d, want %d", got, want)
	}
	if got, want := resolved.Config.RateLimit.Window.Duration(), DefaultRateLimitWindow; got != want {
		t.Fatalf("ratelimit.window = %s, want %s", got, want)
	}
	if got, want := resolved.Sources["ratelimit.limit"], "default"; got != want {
		t.Fatalf("ratelimit.limit source = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["ratelimit.window"], "default"; got != want {
		t.Fatalf("ratelimit.window source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRateLimitFromFile(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
  limit: 200
  window: 5m
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.RateLimit.Limit, 200; got != want {
		t.Fatalf("ratelimit.limit = %d, want %d", got, want)
	}
	if got, want := resolved.Config.RateLimit.Window.Duration(), 5*time.Minute; got != want {
		t.Fatalf("ratelimit.window = %s, want %s", got, want)
	}
	if got, want := resolved.Sources["ratelimit.limit"], configPath; got != want {
		t.Fatalf("ratelimit.limit source = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["ratelimit.window"], configPath; got != want {
		t.Fatalf("ratelimit.window source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRateLimitFromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
  limit: 200
  window: 5m
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_RATELIMIT_LIMIT":  "500",
			"POSTERN_RATELIMIT_WINDOW": "10m",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.RateLimit.Limit, 500; got != want {
		t.Fatalf("ratelimit.limit = %d, want %d", got, want)
	}
	if got, want := resolved.Config.RateLimit.Window.Duration(), 10*time.Minute; got != want {
		t.Fatalf("ratelimit.window = %s, want %s", got, want)
	}
	if got, want := resolved.Sources["ratelimit.limit"], "POSTERN_RATELIMIT_LIMIT"; got != want {
		t.Fatalf("ratelimit.limit source = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["ratelimit.window"], "POSTERN_RATELIMIT_WINDOW"; got != want {
		t.Fatalf("ratelimit.window source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRejectsNonPositiveRateLimit(t *testing.T) {
	config := Config{
		Listen: ListenConfig{Addr: ":8080"},
		IDP: IDPConfig{
			Issuer:   "https://idp.example.com",
			Audience: "https://broker.example.com",
		},
		Signer:    SignerConfig{KMSKeyARN: "arn:aws:kms:us-west-2:123:key/file"},
		Registry:  RegistryConfig{DynamoDBTable: "devices-file"},
		RateLimit: RateLimitConfig{DynamoDBTable: "ratelimit-file", Limit: -1, Window: Duration(-time.Second)},
		Audit:     AuditConfig{CloudWatchLogGroup: "/postern/audit-file"},
		Policy:    PolicyConfig{AVPPolicyStoreID: "policy-file"},
		CertTTL:   CertTTLConfig{Operator: Duration(8 * time.Hour)},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil error")
	}
	if !errors.Is(err, ErrRateLimitLimitInvalid) {
		t.Fatalf("Validate() error = %v, want ErrRateLimitLimitInvalid", err)
	}
	if !errors.Is(err, ErrRateLimitWindowInvalid) {
		t.Fatalf("Validate() error = %v, want ErrRateLimitWindowInvalid", err)
	}
}

// TestValidateRejectsNonPositiveClassTTL locks that a per-class cert-TTL
// ceiling must be a positive duration, mirroring the operator-default check.
func TestValidateRejectsNonPositiveClassTTL(t *testing.T) {
	config := Config{
		Listen:    ListenConfig{Addr: ":8080"},
		IDP:       IDPConfig{Issuer: "https://idp.example.com", Audience: "https://broker.example.com"},
		Signer:    SignerConfig{KMSKeyARN: "arn:aws:kms:us-west-2:123:key/file"},
		Registry:  RegistryConfig{DynamoDBTable: "devices-file"},
		RateLimit: RateLimitConfig{DynamoDBTable: "ratelimit-file", Limit: 60, Window: Duration(time.Minute)},
		Audit:     AuditConfig{CloudWatchLogGroup: "/postern/audit-file"},
		Policy:    PolicyConfig{AVPPolicyStoreID: "policy-file"},
		CertTTL: CertTTLConfig{
			Operator: Duration(12 * time.Hour),
			ByClass:  map[string]Duration{"machine": Duration(0)},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil error")
	}
	if !errors.Is(err, ErrCertTTLClassPositive) {
		t.Fatalf("Validate() error = %v, want ErrCertTTLClassPositive", err)
	}
}

// TestLoadResolvedConfigParsesByClassTTL locks that cert_ttl.by_class parses
// per-class ceilings while the operator default stays the fallback for
// unmapped classes.
func TestLoadResolvedConfigParsesByClassTTL(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 12h
  by_class:
    machine: 1h
    user: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: mapEnv(map[string]string{})})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.CertTTL.Operator.Duration(), 12*time.Hour; got != want {
		t.Fatalf("operator ttl = %s, want %s", got, want)
	}
	if got, want := resolved.Config.CertTTL.ByClass["machine"].Duration(), time.Hour; got != want {
		t.Fatalf("machine ttl = %s, want %s", got, want)
	}
	if got, want := resolved.Config.CertTTL.ByClass["user"].Duration(), 8*time.Hour; got != want {
		t.Fatalf("user ttl = %s, want %s", got, want)
	}
	if _, ok := resolved.Config.CertTTL.ByClass["robot"]; ok {
		t.Fatal("unexpected by_class entry for unmapped class robot")
	}
}

// TestPrintResolvedConfigIncludesSources locks the --print-config output
// shape: the top-level config: block is emitted before the sources: block, so
// operators can rely on stable diffable output across runs. yaml.v3 follows
// struct field order, but a future refactor that flips ResolvedConfig's field
// order would silently break that contract.
func TestPrintResolvedConfigIncludesSources(t *testing.T) {
	var output bytes.Buffer
	err := PrintResolvedConfig(&output, ResolvedConfig{
		Config: Config{
			IDP:     IDPConfig{Issuer: "https://idp.example.com", Audience: "https://broker.example.com"},
			CertTTL: CertTTLConfig{Operator: Duration(12 * time.Hour)},
		},
		Sources: map[string]string{"idp.issuer": "POSTERN_IDP_ISSUER"},
	})
	if err != nil {
		t.Fatalf("PrintResolvedConfig() error = %v", err)
	}

	rendered := output.String()
	configIdx := strings.Index(rendered, "config:")
	sourcesIdx := strings.Index(rendered, "sources:")
	if configIdx == -1 || sourcesIdx == -1 {
		t.Fatalf("print-config output missing config: or sources: block:\n%s", rendered)
	}
	if configIdx >= sourcesIdx {
		t.Fatalf("print-config output has sources: before config: (config@%d, sources@%d):\n%s", configIdx, sourcesIdx, rendered)
	}
	if !strings.Contains(rendered, "idp.issuer: POSTERN_IDP_ISSUER") {
		t.Fatalf("print-config output missing idp.issuer source line:\n%s", rendered)
	}
}

func TestLoadResolvedConfigTrustedProxiesFromFile(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
trusted_proxies:
  - 10.0.0.0/8
  - 192.168.0.0/16
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := len(resolved.Config.TrustedProxies), 2; got != want {
		t.Fatalf("len(trusted_proxies) = %d, want %d", got, want)
	}
	if got, want := resolved.Config.TrustedProxies[0], "10.0.0.0/8"; got != want {
		t.Fatalf("trusted_proxies[0] = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["trusted_proxies"], configPath; got != want {
		t.Fatalf("trusted_proxies source = %q, want %q", got, want)
	}
	parsed, err := resolved.Config.ParsedTrustedProxies()
	if err != nil {
		t.Fatalf("ParsedTrustedProxies() error = %v", err)
	}
	if got, want := len(parsed), 2; got != want {
		t.Fatalf("ParsedTrustedProxies() len = %d, want %d", got, want)
	}
}

func TestLoadResolvedConfigTrustedProxiesFromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_TRUSTED_PROXIES": "10.0.0.0/8, 192.168.0.0/16 ,172.16.0.0/12",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
	if got := resolved.Config.TrustedProxies; len(got) != len(want) {
		t.Fatalf("trusted_proxies = %v, want %v", got, want)
	}
	for index, expected := range want {
		if got := resolved.Config.TrustedProxies[index]; got != expected {
			t.Fatalf("trusted_proxies[%d] = %q, want %q", index, got, expected)
		}
	}
	if got, want := resolved.Sources["trusted_proxies"], "POSTERN_TRUSTED_PROXIES"; got != want {
		t.Fatalf("trusted_proxies source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRejectsMalformedTrustedProxy(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
trusted_proxies:
  - 10.0.0.0/8
  - not-a-cidr
`)

	_, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err == nil {
		t.Fatal("LoadResolvedConfig() returned nil error for malformed CIDR")
	}
	if !errors.Is(err, ErrTrustedProxyInvalid) {
		t.Fatalf("error = %v, want ErrTrustedProxyInvalid", err)
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("error = %v, want to include the rejected CIDR", err)
	}
}

func TestLoadResolvedConfigEmptyTrustedProxiesAllowed(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
cert_ttl:
  operator: 8h
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got := resolved.Config.TrustedProxies; len(got) != 0 {
		t.Fatalf("trusted_proxies = %v, want empty", got)
	}
	if _, present := resolved.Sources["trusted_proxies"]; present {
		t.Fatalf("sources[trusted_proxies] should be absent for empty config")
	}
}

// TestRegistryHTTPAuthBearerValid covers the happy path: bearer mode +
// http_url + bearer_token resolves clean and the source map records all
// three.
func TestRegistryHTTPAuthBearerValid(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  http_url: https://registry.example.com/v1/resolve-device
  http_auth_mode: bearer
  http_bearer_token: supersecret-token
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path:      configPath,
		LookupEnv: emptyBrokerEnv,
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Registry.HTTPAuthMode, "bearer"; got != want {
		t.Fatalf("http_auth_mode = %q, want %q", got, want)
	}
	if got, want := resolved.Config.Registry.HTTPBearerToken, "supersecret-token"; got != want {
		t.Fatalf("http_bearer_token = %q, want %q", got, want)
	}
}

// TestRegistryHTTPAuthSigV4FromEnv covers the typical SigV4 deployment: env
// vars carry the auth mode (and optionally the region) so secrets stay out
// of YAML files.
func TestRegistryHTTPAuthSigV4FromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  http_url: https://registry.example.com/v1/resolve-device
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_REGISTRY_HTTP_AUTH_MODE":  "aws_sigv4",
			"POSTERN_REGISTRY_HTTP_AWS_REGION": "us-east-1",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Registry.HTTPAuthMode, "aws_sigv4"; got != want {
		t.Fatalf("http_auth_mode = %q, want %q", got, want)
	}
	if got, want := resolved.Config.Registry.HTTPAWSRegion, "us-east-1"; got != want {
		t.Fatalf("http_aws_region = %q, want %q", got, want)
	}
	if got := resolved.Sources["registry.http_auth_mode"]; got != "POSTERN_REGISTRY_HTTP_AUTH_MODE" {
		t.Fatalf("source = %q, want env-var source", got)
	}
}

// TestRegistryHTTPTimeoutFromEnv locks the per-call HTTP timeout override
// — operators with Lambda-fronted registries that cold-start slowly raise
// this above the broker's default; operators on tight networks lower it.
func TestRegistryHTTPTimeoutFromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  http_url: https://registry.example.com/v1/resolve-device
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_REGISTRY_HTTP_TIMEOUT": "25s",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Registry.HTTPTimeout.Duration(), 25*time.Second; got != want {
		t.Fatalf("http_timeout = %v, want %v", got, want)
	}
	if got := resolved.Sources["registry.http_timeout"]; got != "POSTERN_REGISTRY_HTTP_TIMEOUT" {
		t.Fatalf("source = %q, want env-var source", got)
	}
}

// TestRegistryHTTPAuthInvalidCombinations covers the validation matrix:
// each invalid combo must produce a specific sentinel error.
func TestRegistryHTTPAuthInvalidCombinations(t *testing.T) {
	baseConfig := func() Config {
		return Config{
			Listen: ListenConfig{Addr: ":8080"},
			IDP: IDPConfig{
				Issuer:        "https://idp.example.com",
				RequiredScope: "postern/ssh",
			},
			Signer:    SignerConfig{KMSKeyARN: "arn:aws:kms:us-west-2:123:key/foo"},
			Registry:  RegistryConfig{HTTPURL: "https://registry.example.com/lookup"},
			RateLimit: RateLimitConfig{DynamoDBTable: "rl", Limit: 60, Window: Duration(time.Minute)},
			Audit:     AuditConfig{CloudWatchLogGroup: "/postern/audit"},
			Policy:    PolicyConfig{AVPPolicyStoreID: "ps-123"},
			CertTTL:   CertTTLConfig{Operator: Duration(12 * time.Hour)},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{
			name: "bearer-mode-missing-token",
			mutate: func(c *Config) {
				c.Registry.HTTPAuthMode = "bearer"
			},
			wantErr: ErrRegistryHTTPBearerTokenRequired,
		},
		{
			name: "bearer-mode-with-aws-region",
			mutate: func(c *Config) {
				c.Registry.HTTPAuthMode = "bearer"
				c.Registry.HTTPBearerToken = "token"
				c.Registry.HTTPAWSRegion = "us-east-1"
			},
			wantErr: ErrRegistryHTTPAWSRegionUnexpected,
		},
		{
			name: "sigv4-mode-with-bearer-token",
			mutate: func(c *Config) {
				c.Registry.HTTPAuthMode = "aws_sigv4"
				c.Registry.HTTPBearerToken = "token"
			},
			wantErr: ErrRegistryHTTPBearerTokenUnexpected,
		},
		{
			name: "auth-mode-without-http-url",
			mutate: func(c *Config) {
				c.Registry.HTTPURL = ""
				c.Registry.DynamoDBTable = "devices"
				c.Registry.HTTPAuthMode = "bearer"
				c.Registry.HTTPBearerToken = "token"
			},
			wantErr: ErrRegistryHTTPAuthModeWithoutURL,
		},
		{
			name: "none-mode-with-bearer-token",
			mutate: func(c *Config) {
				c.Registry.HTTPAuthMode = "none"
				c.Registry.HTTPBearerToken = "token"
			},
			wantErr: ErrRegistryHTTPBearerTokenUnexpected,
		},
		{
			name: "unknown-auth-mode",
			mutate: func(c *Config) {
				c.Registry.HTTPAuthMode = "magic"
			},
			wantErr: ErrRegistryHTTPAuthModeInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := baseConfig()
			tc.mutate(&config)
			err := config.Validate()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestLoadResolvedConfigTunnelingThingNameFormatDefault pins the default
// substitution: with tunneling configured but thing_name_format left empty,
// the broker resolves it to "device-{serial}" so existing operators don't
// have to migrate their config when the field is introduced.
func TestLoadResolvedConfigTunnelingThingNameFormatDefault(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
tunneling:
  iot_region: us-west-2
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if resolved.Config.Tunneling == nil {
		t.Fatalf("tunneling config nil")
	}
	if got, want := resolved.Config.Tunneling.ThingNameFormat, DefaultTunnelingThingNameFormat; got != want {
		t.Fatalf("tunneling.thing_name_format = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["tunneling.thing_name_format"], "default"; got != want {
		t.Fatalf("tunneling.thing_name_format source = %q, want %q", got, want)
	}
}

// TestLoadResolvedConfigTunnelingThingNameFormatFromFile locks the YAML
// override path: an operator-supplied format flows through unchanged.
func TestLoadResolvedConfigTunnelingThingNameFormatFromFile(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
tunneling:
  iot_region: us-west-2
  thing_name_format: "fleet-{serial}-prod"
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.Tunneling.ThingNameFormat, "fleet-{serial}-prod"; got != want {
		t.Fatalf("tunneling.thing_name_format = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["tunneling.thing_name_format"], configPath; got != want {
		t.Fatalf("tunneling.thing_name_format source = %q, want %q", got, want)
	}
}

// TestLoadResolvedConfigTunnelingThingNameFormatFromEnv locks the
// POSTERN_TUNNELING_THING_NAME_FORMAT override, including the lazy-allocate
// path: when the YAML doesn't carry a tunneling section, setting the env
// var alone creates one. (The broker still won't wire the tunneling impl
// without iot_region, so this stays a config-resolution test rather than
// an end-to-end wire test.)
func TestLoadResolvedConfigTunnelingThingNameFormatFromEnv(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`)

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path: configPath,
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_TUNNELING_IOT_REGION":        "us-west-2",
			"POSTERN_TUNNELING_THING_NAME_FORMAT": "{serial}",
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if resolved.Config.Tunneling == nil {
		t.Fatalf("tunneling config nil")
	}
	if got, want := resolved.Config.Tunneling.ThingNameFormat, "{serial}"; got != want {
		t.Fatalf("tunneling.thing_name_format = %q, want %q", got, want)
	}
	if got, want := resolved.Sources["tunneling.thing_name_format"], "POSTERN_TUNNELING_THING_NAME_FORMAT"; got != want {
		t.Fatalf("tunneling.thing_name_format source = %q, want %q", got, want)
	}
}

// TestLoadResolvedConfigTunnelingThingNameFormatInvalid pins validation:
// a format without exactly one {serial} placeholder is rejected via the
// ErrTunnelingThingNameFormatInvalid sentinel. The defense-in-depth pair
// in NewTunnelIssuer relies on this layer catching most bad inputs at
// config load.
func TestLoadResolvedConfigTunnelingThingNameFormatInvalid(t *testing.T) {
	cases := []struct {
		name   string
		format string
	}{
		{name: "no-placeholder", format: "static-thing-name"},
		{name: "two-placeholders", format: "{serial}-{serial}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Listen: ListenConfig{Addr: ":8080"},
				IDP: IDPConfig{
					Issuer:   "https://idp.example.com",
					Audience: "https://broker.example.com",
				},
				Signer:    SignerConfig{KMSKeyARN: "arn:aws:kms:us-west-2:123:key/file"},
				Registry:  RegistryConfig{DynamoDBTable: "devices-file"},
				RateLimit: RateLimitConfig{DynamoDBTable: "ratelimit-file", Limit: 60, Window: Duration(time.Minute)},
				Audit:     AuditConfig{CloudWatchLogGroup: "/postern/audit-file"},
				Policy:    PolicyConfig{AVPPolicyStoreID: "policy-file"},
				CertTTL:   CertTTLConfig{Operator: Duration(8 * time.Hour)},
				Tunneling: &TunnelingConfig{IOTRegion: "us-west-2", ThingNameFormat: tc.format},
			}
			err := config.Validate()
			if err == nil {
				t.Fatalf("Validate() returned nil error for format %q", tc.format)
			}
			if !errors.Is(err, ErrTunnelingThingNameFormatInvalid) {
				t.Fatalf("Validate() error = %v, want ErrTunnelingThingNameFormatInvalid", err)
			}
		})
	}
}

// principalClassConfig builds a minimal valid broker config whose idp block
// carries the supplied principal_classes YAML (already indented under idp).
func principalClassConfig(idpExtra string) string {
	return `
idp:
  issuer: https://idp.example.com
  audience: https://broker.example.com
` + idpExtra + `signer:
  kms_key_arn: arn:aws:kms:us-west-2:123:key/file
registry:
  dynamodb_table: devices-file
ratelimit:
  dynamodb_table: ratelimit-file
audit:
  cloudwatch_log_group: /postern/audit-file
policy:
  avp_policy_store_id: policy-file
`
}

func TestLoadResolvedConfigPrincipalClassesDefaultFill(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    rules:
      - class: machine
        claim_absent: username
`))

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	classes := resolved.Config.IDP.PrincipalClasses
	if classes == nil {
		t.Fatal("principal_classes block is nil")
	}
	if got, want := classes.Default, DefaultPrincipalClass; got != want {
		t.Fatalf("default class = %q, want %q (default-fill)", got, want)
	}
	if len(classes.Rules) != 1 || classes.Rules[0].Class != "machine" {
		t.Fatalf("rules = %#v, want one machine rule", classes.Rules)
	}
}

func TestLoadResolvedConfigPrincipalClassDefaultEnvOverride(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    default: user
    rules:
      - class: machine
        claim_absent: username
`))

	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Path:      configPath,
		LookupEnv: mapEnv(map[string]string{"POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT": "robot"}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if got, want := resolved.Config.IDP.PrincipalClasses.Default, "robot"; got != want {
		t.Fatalf("default class = %q, want %q (env override)", got, want)
	}
	if got, want := resolved.Sources["idp.principal_classes.default"], "POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT"; got != want {
		t.Fatalf("default source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigPrincipalClassesFromEnv(t *testing.T) {
	// The Lambda deployment mounts no config file, so the structured rule list
	// must be configurable via POSTERN_IDP_PRINCIPAL_CLASSES (JSON or YAML).
	resolved, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
			"POSTERN_IDP_PRINCIPAL_CLASSES":      `{"default":"user","rules":[{"class":"machine","claim_absent":"username"}]}`,
		}),
	})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}

	classes := resolved.Config.IDP.PrincipalClasses
	if classes == nil {
		t.Fatal("PrincipalClasses is nil; env block was not parsed")
	}
	if got, want := classes.Default, "user"; got != want {
		t.Fatalf("default class = %q, want %q", got, want)
	}
	if len(classes.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(classes.Rules))
	}
	if got := classes.Rules[0]; got.Class != "machine" || got.ClaimAbsent != "username" {
		t.Fatalf("rule = %+v, want class=machine claim_absent=username", got)
	}
	if got, want := resolved.Sources["idp.principal_classes"], "POSTERN_IDP_PRINCIPAL_CLASSES"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

func TestLoadResolvedConfigRejectsInvalidPrincipalClassesEnv(t *testing.T) {
	// Rules supplied via the env var go through the same validation as a
	// file-provided block — a rule with two predicates is rejected.
	_, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
			"POSTERN_IDP_PRINCIPAL_CLASSES":      `{"rules":[{"class":"machine","claim_absent":"username","scope_contains":"x"}]}`,
		}),
	})
	if !errors.Is(err, ErrPrincipalClassRulePredicate) {
		t.Fatalf("error = %v, want ErrPrincipalClassRulePredicate", err)
	}
}

func TestLoadResolvedConfigRejectsUnknownKeyPrincipalClassesEnv(t *testing.T) {
	// A typo'd `default` key would be silently dropped by a lenient decoder,
	// reverting every caller to the "user" default without an error. Strict
	// decoding rejects it. (A typo'd predicate key is already caught by rule
	// validation; this covers the keys validation can't see.)
	_, err := LoadResolvedConfig(LoadConfigOptions{
		Candidates: []string{filepath.Join(t.TempDir(), "missing.yaml")},
		LookupEnv: mapEnv(map[string]string{
			"POSTERN_IDP_ISSUER":                 "https://idp.example.com",
			"POSTERN_IDP_REQUIRED_SCOPE":         "postern/ssh",
			"POSTERN_SIGNER_KMS_KEY_ARN":         "arn:aws:kms:us-west-2:123:key/env",
			"POSTERN_REGISTRY_DYNAMODB_TABLE":    "devices-env",
			"POSTERN_RATELIMIT_DYNAMODB_TABLE":   "ratelimit-env",
			"POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP": "/postern/audit-env",
			"POSTERN_POLICY_AVP_POLICY_STORE_ID": "policy-env",
			"POSTERN_IDP_PRINCIPAL_CLASSES":      `{"defualt":"robot","rules":[{"class":"machine","claim_absent":"username"}]}`,
		}),
	})
	if err == nil {
		t.Fatal("LoadResolvedConfig() error = nil, want an error for the unknown key \"defualt\"")
	}
	if !strings.Contains(err.Error(), "POSTERN_IDP_PRINCIPAL_CLASSES") {
		t.Fatalf("error = %v, want it to name the env var", err)
	}
}

func TestLoadResolvedConfigRejectsMultiPredicateRule(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    rules:
      - class: machine
        claim_absent: username
        scope_contains: postern/m2m
`))

	_, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if !errors.Is(err, ErrPrincipalClassRulePredicate) {
		t.Fatalf("error = %v, want ErrPrincipalClassRulePredicate", err)
	}
}

func TestLoadResolvedConfigRejectsRuleWithNoPredicate(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    rules:
      - class: machine
`))

	_, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if !errors.Is(err, ErrPrincipalClassRulePredicate) {
		t.Fatalf("error = %v, want ErrPrincipalClassRulePredicate", err)
	}
}

func TestLoadResolvedConfigRejectsEmptyClassName(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    rules:
      - class: ""
        claim_absent: username
`))

	_, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if !errors.Is(err, ErrPrincipalClassNameEmpty) {
		t.Fatalf("error = %v, want ErrPrincipalClassNameEmpty", err)
	}
}

func TestLoadResolvedConfigRejectsOverlongClassName(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(`  principal_classes:
    rules:
      - class: `+strings.Repeat("x", MaxPrincipalClassRunes+1)+`
        claim_absent: username
`))

	_, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if !errors.Is(err, ErrPrincipalClassNameTooLong) {
		t.Fatalf("error = %v, want ErrPrincipalClassNameTooLong", err)
	}
}

// TestLoadResolvedConfigAbsentPrincipalClassesBlock locks back-compat: a config
// with no principal_classes block loads cleanly and leaves the block nil so the
// verifier classifies every caller as the default class.
func TestLoadResolvedConfigAbsentPrincipalClassesBlock(t *testing.T) {
	configPath := writeBrokerConfigForTest(t, principalClassConfig(""))

	resolved, err := LoadResolvedConfig(LoadConfigOptions{Path: configPath, LookupEnv: emptyBrokerEnv})
	if err != nil {
		t.Fatalf("LoadResolvedConfig() error = %v", err)
	}
	if resolved.Config.IDP.PrincipalClasses != nil {
		t.Fatalf("principal_classes = %#v, want nil when block absent", resolved.Config.IDP.PrincipalClasses)
	}
}

func writeBrokerConfigForTest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func mapEnv(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func emptyBrokerEnv(string) (string, bool) {
	return "", false
}
