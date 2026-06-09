package brokerhandlers

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atomicgravity/postern/internal/broker"
	"gopkg.in/yaml.v3"
)

// Broker config defaults and env-var names. Defaults apply when neither
// the YAML file nor the env override sets a field.
const (
	DefaultEnvPrefix           = "POSTERN"
	BrokerConfigEnv            = "POSTERN_BROKER_CONFIG"
	DefaultBrokerConfigPath    = "/etc/postern/broker.yaml"
	LocalBrokerConfigPath      = "./broker.yaml"
	DefaultOperatorCertTTLText = "12h"
	DefaultOperatorCertTTL     = 12 * time.Hour
	DefaultListenAddr          = "127.0.0.1:8080"
	DefaultRateLimitLimit      = 60
	DefaultRateLimitWindow     = time.Minute

	// DefaultPrincipalClass is the class assigned when no principal-class rule
	// matches and the operator didn't set idp.principal_classes.default.
	DefaultPrincipalClass = "user"

	// MaxPrincipalClassRunes bounds a configured class name so a misconfigured
	// rule can't bloat the audit row or Cedar context.
	MaxPrincipalClassRunes = 64
)

// Sentinel errors for config validation. Validate joins these via
// errors.Join so callers distinguish per-field misses with errors.Is.
var (
	ErrIDPIssuerRequired                  = errors.New("idp.issuer is required")
	ErrIDPIssuerNotHTTPS                  = errors.New("idp.issuer must use https (the broker fetches JWKs over this scheme; plaintext exposes signing keys to network MITM)")
	ErrIDPAudienceOrRequiredScopeRequired = errors.New("one of idp.audience or idp.required_scope is required")
	ErrPrincipalClassNameEmpty            = errors.New("idp.principal_classes rule class name must be non-empty")
	ErrPrincipalClassNameTooLong          = errors.New("idp.principal_classes class name exceeds the maximum length")
	ErrPrincipalClassRulePredicate        = errors.New("idp.principal_classes rule must set exactly one predicate (claim_present, claim_absent, claim+equals, or scope_contains)")
	ErrSignerKMSKeyARNRequired            = errors.New("signer.kms_key_arn is required")
	ErrRegistryBackendRequired            = errors.New("one of registry.dynamodb_table or registry.http_url is required")
	ErrRegistryBackendConflict            = errors.New("only one of registry.dynamodb_table or registry.http_url may be set")
	ErrRegistryHTTPAuthModeInvalid        = errors.New("registry.http_auth_mode must be one of: none, bearer, aws_sigv4")
	ErrRegistryHTTPAuthModeWithoutURL     = errors.New("registry.http_auth_mode requires registry.http_url to be set")
	ErrRegistryHTTPURLNotHTTPS            = errors.New("registry.http_url must use https when http_auth_mode is bearer (bearer tokens transmitted in plaintext over http expose the registry credential to any on-path attacker)")
	ErrRegistryHTTPBearerTokenRequired    = errors.New("registry.http_bearer_token is required when registry.http_auth_mode is bearer")
	ErrRegistryHTTPBearerTokenUnexpected  = errors.New("registry.http_bearer_token is only valid when registry.http_auth_mode is bearer")
	ErrRegistryHTTPAWSRegionUnexpected    = errors.New("registry.http_aws_region is only valid when registry.http_auth_mode is aws_sigv4")
	ErrRateLimitTableRequired             = errors.New("ratelimit.dynamodb_table is required")
	ErrRateLimitLimitInvalid              = errors.New("ratelimit.limit must be positive")
	ErrRateLimitWindowInvalid             = errors.New("ratelimit.window must be positive")
	ErrAuditLogGroupRequired              = errors.New("audit.cloudwatch_log_group is required")
	ErrPolicyStoreIDRequired              = errors.New("policy.avp_policy_store_id is required")
	ErrCertTTLOperatorPositive            = errors.New("cert_ttl.operator must be positive")
	ErrCertTTLClassPositive               = errors.New("cert_ttl.by_class ceiling must be positive")
	ErrListenAddrRequired                 = errors.New("listen.addr is required")
	ErrTrustedProxyInvalid                = errors.New("trusted_proxies entry is not a valid CIDR")
	ErrTunnelingThingNameFormatInvalid    = errors.New("tunneling.thing_name_format must contain exactly one {serial} placeholder")
)

// DefaultTunnelingThingNameFormat is the fallback when
// tunneling.thing_name_format is empty.
const DefaultTunnelingThingNameFormat = "device-{serial}"

// TunnelingThingNameSerialPlaceholder is the substring replaced with the
// resolved device serial; must appear exactly once.
const TunnelingThingNameSerialPlaceholder = "{serial}"

// Config is the broker's resolved YAML shape.
type Config struct {
	Listen    ListenConfig     `yaml:"listen"`
	IDP       IDPConfig        `yaml:"idp"`
	Signer    SignerConfig     `yaml:"signer"`
	Registry  RegistryConfig   `yaml:"registry"`
	RateLimit RateLimitConfig  `yaml:"ratelimit"`
	Audit     AuditConfig      `yaml:"audit"`
	Tunneling *TunnelingConfig `yaml:"tunneling,omitempty"`
	Policy    PolicyConfig     `yaml:"policy"`
	CertTTL   CertTTLConfig    `yaml:"cert_ttl"`

	// TrustedProxies are the reverse-proxy CIDRs the broker trusts to append
	// the engineer's address to X-Forwarded-For. Empty means direct deploy;
	// non-empty derives the engineer IP as the rightmost-non-trusted XFF
	// entry.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

type ListenConfig struct {
	Addr string `yaml:"addr"`
}

// IDPConfig configures the OIDC verifier. At least one of Audience or
// RequiredScope must be set so the broker refuses tokens issued for other
// apps sharing the IdP client.
//
// PrincipalClasses is optional: an absent block classifies every caller as the
// default class ("user"), preserving back-compat for deployments that don't
// distinguish automated callers.
type IDPConfig struct {
	Issuer           string                  `yaml:"issuer"`
	Audience         string                  `yaml:"audience,omitempty"`
	RequiredScope    string                  `yaml:"required_scope,omitempty"`
	PrincipalClasses *PrincipalClassesConfig `yaml:"principal_classes,omitempty"`
}

// PrincipalClassesConfig is the operator-configurable classification block.
// Default is the class stamped when no rule matches (empty resolves to
// "user"). Rules is an ordered first-match list; the verifier evaluates them
// top-to-bottom against the access token's claim map.
type PrincipalClassesConfig struct {
	Default string               `yaml:"default,omitempty"`
	Rules   []PrincipalClassRule `yaml:"rules,omitempty"`
}

// PrincipalClassRule maps a single claim predicate to a class name. Exactly
// one predicate field must be set per rule; Equals pairs with Claim.
//
//   - ClaimPresent: <name>     — claim key exists and is non-empty
//   - ClaimAbsent: <name>      — claim key missing or empty (Cognito M2M signal)
//   - Claim: <name> + Equals   — claim is a string == Equals, or array containing it
//   - ScopeContains: <value>   — the scope/scp claim contains <value>
type PrincipalClassRule struct {
	Class         string `yaml:"class"`
	ClaimPresent  string `yaml:"claim_present,omitempty"`
	ClaimAbsent   string `yaml:"claim_absent,omitempty"`
	Claim         string `yaml:"claim,omitempty"`
	Equals        string `yaml:"equals,omitempty"`
	ScopeContains string `yaml:"scope_contains,omitempty"`
}

// predicateCount reports how many predicate forms the rule sets. A valid rule
// sets exactly one: claim_present, claim_absent, claim (paired with equals),
// or scope_contains. The claim+equals pair counts as a single predicate.
func (r PrincipalClassRule) predicateCount() int {
	count := 0
	if strings.TrimSpace(r.ClaimPresent) != "" {
		count++
	}
	if strings.TrimSpace(r.ClaimAbsent) != "" {
		count++
	}
	if strings.TrimSpace(r.Claim) != "" {
		count++
	}
	if strings.TrimSpace(r.ScopeContains) != "" {
		count++
	}
	return count
}

// validatePrincipalClasses checks each rule sets exactly one predicate and
// carries a non-empty, length-bounded class name; it also bounds the default
// class name. An absent block is valid (every caller is the default class).
func validatePrincipalClasses(classes *PrincipalClassesConfig) []error {
	if classes == nil {
		return nil
	}

	var errs []error

	if utf8.RuneCountInString(strings.TrimSpace(classes.Default)) > MaxPrincipalClassRunes {
		errs = append(errs, ErrPrincipalClassNameTooLong)
	}

	for index, rule := range classes.Rules {
		name := strings.TrimSpace(rule.Class)
		if name == "" {
			errs = append(errs, fmt.Errorf("%w (rule %d)", ErrPrincipalClassNameEmpty, index))
		} else if utf8.RuneCountInString(name) > MaxPrincipalClassRunes {
			errs = append(errs, fmt.Errorf("%w (rule %d)", ErrPrincipalClassNameTooLong, index))
		}

		if rule.predicateCount() != 1 {
			errs = append(errs, fmt.Errorf("%w (rule %d)", ErrPrincipalClassRulePredicate, index))
		}
	}

	return errs
}

type SignerConfig struct {
	KMSKeyARN string `yaml:"kms_key_arn"`
}

// RegistryConfig configures the device Registry. Exactly one of DynamoDBTable
// or HTTPURL must be set.
type RegistryConfig struct {
	DynamoDBTable string `yaml:"dynamodb_table"`
	HTTPURL       string `yaml:"http_url"`

	// HTTPAuthMode: "" / "none" / "bearer" / "aws_sigv4".
	HTTPAuthMode string `yaml:"http_auth_mode"`

	// HTTPBearerToken is sent verbatim in Authorization: Bearer when
	// HTTPAuthMode is "bearer". Keep this in env / secret store, not YAML.
	HTTPBearerToken string `yaml:"http_bearer_token"`

	// HTTPAWSRegion names the SigV4 region. Empty falls back to the AWS
	// SDK's default chain (AWS_REGION env, shared config, etc.).
	HTTPAWSRegion string `yaml:"http_aws_region"`

	// HTTPTimeout caps the per-request HTTP call. Zero falls back to
	// registry.DefaultHTTPRegistryTimeout (Lambda cold-start budget).
	HTTPTimeout Duration `yaml:"http_timeout,omitempty"`
}

const (
	RegistryHTTPAuthModeNone   = "none"
	RegistryHTTPAuthModeBearer = "bearer"
	RegistryHTTPAuthModeSigV4  = "aws_sigv4"
)

// RateLimitConfig configures the DynamoDB rate limiter. Only DynamoDBTable
// is required; Limit and Window have defaults.
type RateLimitConfig struct {
	DynamoDBTable string   `yaml:"dynamodb_table"`
	Limit         int      `yaml:"limit,omitempty"`
	Window        Duration `yaml:"window,omitempty"`
}

type AuditConfig struct {
	CloudWatchLogGroup string `yaml:"cloudwatch_log_group"`
}

// TunnelingConfig configures the AWS IoT secure-tunneling backend. An absent
// section makes /ssh/tunnel return 501 — the broker stays usable on stacks
// that don't need the firewalled-device path.
//
// IOTRegion pins the SDK region; it also flows back to the CLI on every
// tunnel-open response so the source proxy can dial the right data-tunneling
// endpoint. DefaultMaxLifetimeMinutes is the engineer-omits-flag fallback,
// capped at 720 (12h AWS ceiling). ThingNameFormat must contain exactly one
// "{serial}" placeholder; empty resolves to "device-{serial}".
type TunnelingConfig struct {
	IOTRegion                 string `yaml:"iot_region"`
	DefaultMaxLifetimeMinutes int32  `yaml:"default_max_lifetime_minutes,omitempty"`
	ThingNameFormat           string `yaml:"thing_name_format,omitempty"`
}

type PolicyConfig struct {
	AVPPolicyStoreID string `yaml:"avp_policy_store_id"`
}

// CertTTLConfig configures the operator-cert validity ceiling. Operator is the
// default ceiling applied to any principal class without a ByClass entry.
// ByClass maps a principal class (the classes configured under
// idp.principal_classes) to its own operator-cert ceiling, e.g.
// {user: 12h, machine: 1h}; an unmapped class falls back to Operator.
type CertTTLConfig struct {
	Operator Duration            `yaml:"operator"`
	ByClass  map[string]Duration `yaml:"by_class,omitempty"`
}

// Duration is a time.Duration that round-trips through YAML as a Go duration
// string ("12h", "30s"). Zero marshals to "".
type Duration time.Duration

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

func (d Duration) MarshalYAML() (any, error) {
	if d == 0 {
		return "", nil
	}
	return d.String(), nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return errors.New("duration must be a string")
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value.Value))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// LoadConfigOptions controls LoadResolvedConfig. Resolution order: Path →
// $POSTERN_BROKER_CONFIG → Candidates (or DefaultConfigPaths).
type LoadConfigOptions struct {
	Path       string
	LookupEnv  func(string) (string, bool)
	Candidates []string
}

// ResolvedConfig is a Config plus a per-field source map for --print-config.
type ResolvedConfig struct {
	Config  Config            `yaml:"config"`
	Sources map[string]string `yaml:"sources"`
}

// DefaultConfigPaths returns the broker config search path:
// /etc/postern/broker.yaml then ./broker.yaml.
func DefaultConfigPaths() []string {
	return []string{DefaultBrokerConfigPath, LocalBrokerConfigPath}
}

// LoadConfig decodes YAML and normalizes whitespace at the decode boundary.
func LoadConfig(reader io.Reader) (Config, error) {
	var config Config
	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	trimConfig(&config)
	return config, nil
}

func trimConfig(config *Config) {
	config.Listen.Addr = strings.TrimSpace(config.Listen.Addr)
	config.IDP.Issuer = strings.TrimSpace(config.IDP.Issuer)
	config.IDP.Audience = strings.TrimSpace(config.IDP.Audience)
	config.IDP.RequiredScope = strings.TrimSpace(config.IDP.RequiredScope)
	config.Signer.KMSKeyARN = strings.TrimSpace(config.Signer.KMSKeyARN)
	config.Registry.DynamoDBTable = strings.TrimSpace(config.Registry.DynamoDBTable)
	config.Registry.HTTPURL = strings.TrimSpace(config.Registry.HTTPURL)
	config.Registry.HTTPAuthMode = strings.ToLower(strings.TrimSpace(config.Registry.HTTPAuthMode))
	config.Registry.HTTPBearerToken = strings.TrimSpace(config.Registry.HTTPBearerToken)
	config.Registry.HTTPAWSRegion = strings.TrimSpace(config.Registry.HTTPAWSRegion)
	config.RateLimit.DynamoDBTable = strings.TrimSpace(config.RateLimit.DynamoDBTable)
	config.Audit.CloudWatchLogGroup = strings.TrimSpace(config.Audit.CloudWatchLogGroup)
	config.Policy.AVPPolicyStoreID = strings.TrimSpace(config.Policy.AVPPolicyStoreID)
	if config.Tunneling != nil {
		config.Tunneling.IOTRegion = strings.TrimSpace(config.Tunneling.IOTRegion)
		config.Tunneling.ThingNameFormat = strings.TrimSpace(config.Tunneling.ThingNameFormat)
	}
}

// LoadConfigFile decodes path's YAML into a Config.
func LoadConfigFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	return LoadConfig(file)
}

// LoadResolvedConfig runs the full resolution path: select file → load →
// defaults → env overrides → validate. The returned ResolvedConfig carries
// per-field source info for --print-config.
func LoadResolvedConfig(options LoadConfigOptions) (ResolvedConfig, error) {
	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	config := Config{}
	sources := map[string]string{}

	path, source, explicit, err := selectedConfigPath(options, lookupEnv)
	if err != nil {
		return ResolvedConfig{}, err
	}

	if path != "" {
		loaded, err := LoadConfigFile(path)
		if err != nil {
			if explicit || !errors.Is(err, os.ErrNotExist) {
				return ResolvedConfig{}, fmt.Errorf("load broker config %q: %w", path, err)
			}
		} else {
			config = loaded
			markFileSources(config, source, sources)
		}
	}

	config.WithDefaults(sources)

	if err := applyEnvOverrides(&config, lookupEnv, sources); err != nil {
		return ResolvedConfig{}, err
	}

	if err := config.Validate(); err != nil {
		return ResolvedConfig{}, annotateValidationError(err, sources)
	}

	return ResolvedConfig{Config: config, Sources: sources}, nil
}

// annotateValidationError adds operator-facing context the validator can't
// see — names the offending env vars on ErrRegistryBackendConflict so the
// operator sees which vars they set rather than a generic message.
func annotateValidationError(err error, sources map[string]string) error {
	if !errors.Is(err, ErrRegistryBackendConflict) {
		return err
	}
	dynamoSrc := sources["registry.dynamodb_table"]
	httpSrc := sources["registry.http_url"]
	if strings.HasPrefix(dynamoSrc, "POSTERN_") && strings.HasPrefix(httpSrc, "POSTERN_") {
		return fmt.Errorf("%w (%s and %s both set)", err, dynamoSrc, httpSrc)
	}
	return err
}

// PrintResolvedConfig writes the resolved config as YAML for --print-config.
func PrintResolvedConfig(writer io.Writer, resolved ResolvedConfig) error {
	encoder := yaml.NewEncoder(writer)
	if err := encoder.Encode(resolved); err != nil {
		_ = encoder.Close()
		return err
	}
	return encoder.Close()
}

// WithDefaults fills in default values. sources is updated so unset fields
// report "default" in PrintResolvedConfig.
func (c *Config) WithDefaults(sources map[string]string) {
	if c.Listen.Addr == "" {
		c.Listen.Addr = DefaultListenAddr
		if sources != nil {
			sources["listen.addr"] = "default"
		}
	}
	if c.CertTTL.Operator == 0 {
		c.CertTTL.Operator = Duration(DefaultOperatorCertTTL)
		if sources != nil {
			sources["cert_ttl.operator"] = "default"
		}
	}
	if c.RateLimit.Limit == 0 {
		c.RateLimit.Limit = DefaultRateLimitLimit
		if sources != nil {
			sources["ratelimit.limit"] = "default"
		}
	}
	if c.RateLimit.Window == 0 {
		c.RateLimit.Window = Duration(DefaultRateLimitWindow)
		if sources != nil {
			sources["ratelimit.window"] = "default"
		}
	}
	if c.Tunneling != nil && c.Tunneling.ThingNameFormat == "" {
		c.Tunneling.ThingNameFormat = DefaultTunnelingThingNameFormat
		if sources != nil {
			sources["tunneling.thing_name_format"] = "default"
		}
	}
	if c.IDP.PrincipalClasses != nil && strings.TrimSpace(c.IDP.PrincipalClasses.Default) == "" {
		c.IDP.PrincipalClasses.Default = DefaultPrincipalClass
		if sources != nil {
			sources["idp.principal_classes.default"] = "default"
		}
	}
}

// Validate returns nil if all required fields are set, or joined Err*
// sentinels otherwise. Trim normalization happens at the decode boundary;
// Validate does not mutate the receiver.
func (c *Config) Validate() error {
	var errs []error
	if c.Listen.Addr == "" {
		errs = append(errs, ErrListenAddrRequired)
	}
	if c.IDP.Issuer == "" {
		errs = append(errs, ErrIDPIssuerRequired)
	} else if !broker.IsHTTPSOrLoopback(c.IDP.Issuer) {
		errs = append(errs, ErrIDPIssuerNotHTTPS)
	}
	if c.IDP.Audience == "" && c.IDP.RequiredScope == "" {
		errs = append(errs, ErrIDPAudienceOrRequiredScopeRequired)
	}
	errs = append(errs, validatePrincipalClasses(c.IDP.PrincipalClasses)...)
	if c.Signer.KMSKeyARN == "" {
		errs = append(errs, ErrSignerKMSKeyARNRequired)
	}
	registrySources := 0
	if c.Registry.DynamoDBTable != "" {
		registrySources++
	}
	if c.Registry.HTTPURL != "" {
		registrySources++
	}
	if registrySources == 0 {
		errs = append(errs, ErrRegistryBackendRequired)
	}
	if registrySources > 1 {
		errs = append(errs, ErrRegistryBackendConflict)
	}
	switch c.Registry.HTTPAuthMode {
	case "", RegistryHTTPAuthModeNone:
		if c.Registry.HTTPBearerToken != "" {
			errs = append(errs, ErrRegistryHTTPBearerTokenUnexpected)
		}
		if c.Registry.HTTPAWSRegion != "" {
			errs = append(errs, ErrRegistryHTTPAWSRegionUnexpected)
		}
	case RegistryHTTPAuthModeBearer:
		if c.Registry.HTTPURL == "" {
			errs = append(errs, ErrRegistryHTTPAuthModeWithoutURL)
		} else if !broker.IsHTTPSOrLoopback(c.Registry.HTTPURL) {
			errs = append(errs, ErrRegistryHTTPURLNotHTTPS)
		}
		if c.Registry.HTTPBearerToken == "" {
			errs = append(errs, ErrRegistryHTTPBearerTokenRequired)
		}
		if c.Registry.HTTPAWSRegion != "" {
			errs = append(errs, ErrRegistryHTTPAWSRegionUnexpected)
		}
	case RegistryHTTPAuthModeSigV4:
		if c.Registry.HTTPURL == "" {
			errs = append(errs, ErrRegistryHTTPAuthModeWithoutURL)
		}
		if c.Registry.HTTPBearerToken != "" {
			errs = append(errs, ErrRegistryHTTPBearerTokenUnexpected)
		}
		// HTTPAWSRegion is optional; brokerwire resolves via the SDK
		// default chain when empty.
	default:
		errs = append(errs, ErrRegistryHTTPAuthModeInvalid)
	}
	if c.RateLimit.DynamoDBTable == "" {
		errs = append(errs, ErrRateLimitTableRequired)
	}
	if c.RateLimit.Limit <= 0 {
		errs = append(errs, ErrRateLimitLimitInvalid)
	}
	if c.RateLimit.Window.Duration() <= 0 {
		errs = append(errs, ErrRateLimitWindowInvalid)
	}
	if c.Audit.CloudWatchLogGroup == "" {
		errs = append(errs, ErrAuditLogGroupRequired)
	}
	if c.Policy.AVPPolicyStoreID == "" {
		errs = append(errs, ErrPolicyStoreIDRequired)
	}
	if c.CertTTL.Operator.Duration() <= 0 {
		errs = append(errs, ErrCertTTLOperatorPositive)
	}
	for class, ttl := range c.CertTTL.ByClass {
		if ttl.Duration() <= 0 {
			errs = append(errs, fmt.Errorf("%w (class %q)", ErrCertTTLClassPositive, class))
		}
	}
	for index, entry := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(entry)); err != nil {
			errs = append(errs, errors.Join(
				ErrTrustedProxyInvalid,
				fmt.Errorf("trusted_proxies[%d] %q: %w", index, entry, err),
			))
		}
	}
	if c.Tunneling != nil && c.Tunneling.ThingNameFormat != "" {
		if strings.Count(c.Tunneling.ThingNameFormat, TunnelingThingNameSerialPlaceholder) != 1 {
			errs = append(errs, errors.Join(
				ErrTunnelingThingNameFormatInvalid,
				fmt.Errorf("tunneling.thing_name_format %q", c.Tunneling.ThingNameFormat),
			))
		}
	}
	return errors.Join(errs...)
}

// ParsedTrustedProxies returns the configured CIDRs as []net.IPNet. Validate
// must succeed first.
func (c *Config) ParsedTrustedProxies() ([]net.IPNet, error) {
	if len(c.TrustedProxies) == 0 {
		return nil, nil
	}
	result := make([]net.IPNet, 0, len(c.TrustedProxies))
	for _, entry := range c.TrustedProxies {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy CIDR %q: %w", entry, err)
		}
		result = append(result, *network)
	}
	return result, nil
}

func selectedConfigPath(options LoadConfigOptions, lookupEnv func(string) (string, bool)) (path string, source string, explicit bool, err error) {
	if value := strings.TrimSpace(options.Path); value != "" {
		return value, value, true, nil
	}
	if value, ok := lookupEnv(BrokerConfigEnv); ok {
		if value = strings.TrimSpace(value); value != "" {
			return value, value, true, nil
		}
	}

	candidates := options.Candidates
	if candidates == nil {
		candidates = DefaultConfigPaths()
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		_, err := os.Stat(candidate)
		if err == nil {
			return candidate, candidate, false, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", "", false, err
		}
	}
	return "", "", false, nil
}

func markFileSources(config Config, source string, sources map[string]string) {
	markSource(sources, "listen.addr", config.Listen.Addr, source)
	markSource(sources, "idp.issuer", config.IDP.Issuer, source)
	markSource(sources, "idp.audience", config.IDP.Audience, source)
	markSource(sources, "idp.required_scope", config.IDP.RequiredScope, source)
	markSource(sources, "signer.kms_key_arn", config.Signer.KMSKeyARN, source)
	markSource(sources, "registry.dynamodb_table", config.Registry.DynamoDBTable, source)
	markSource(sources, "registry.http_url", config.Registry.HTTPURL, source)
	markSource(sources, "registry.http_auth_mode", config.Registry.HTTPAuthMode, source)
	markSource(sources, "registry.http_bearer_token", config.Registry.HTTPBearerToken, source)
	markSource(sources, "registry.http_aws_region", config.Registry.HTTPAWSRegion, source)
	markSource(sources, "ratelimit.dynamodb_table", config.RateLimit.DynamoDBTable, source)
	if config.RateLimit.Limit != 0 {
		sources["ratelimit.limit"] = source
	}
	if config.RateLimit.Window != 0 {
		sources["ratelimit.window"] = source
	}
	markSource(sources, "audit.cloudwatch_log_group", config.Audit.CloudWatchLogGroup, source)
	if config.Tunneling != nil {
		markSource(sources, "tunneling.iot_region", config.Tunneling.IOTRegion, source)
		if config.Tunneling.DefaultMaxLifetimeMinutes != 0 {
			sources["tunneling.default_max_lifetime_minutes"] = source
		}
		markSource(sources, "tunneling.thing_name_format", config.Tunneling.ThingNameFormat, source)
	}
	markSource(sources, "policy.avp_policy_store_id", config.Policy.AVPPolicyStoreID, source)
	if config.CertTTL.Operator != 0 {
		sources["cert_ttl.operator"] = source
	}
	if len(config.TrustedProxies) > 0 {
		sources["trusted_proxies"] = source
	}
}

func markSource(sources map[string]string, field string, value string, source string) {
	if value != "" {
		sources[field] = source
	}
}

func applyEnvOverrides(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) error {
	setStringFromEnv(&config.Listen.Addr, "POSTERN_BROKER_ADDR", lookupEnv, sources, "listen.addr")
	setStringFromEnv(&config.IDP.Issuer, "POSTERN_IDP_ISSUER", lookupEnv, sources, "idp.issuer")
	setStringFromEnv(&config.IDP.Audience, "POSTERN_IDP_AUDIENCE", lookupEnv, sources, "idp.audience")
	setStringFromEnv(&config.IDP.RequiredScope, "POSTERN_IDP_REQUIRED_SCOPE", lookupEnv, sources, "idp.required_scope")
	if err := setPrincipalClassesFromEnv(config, lookupEnv, sources); err != nil {
		return err
	}
	setPrincipalClassDefaultFromEnv(config, lookupEnv, sources)
	setStringFromEnv(&config.Signer.KMSKeyARN, "POSTERN_SIGNER_KMS_KEY_ARN", lookupEnv, sources, "signer.kms_key_arn")
	setRegistryFromEnv(config, lookupEnv, sources)
	setStringFromEnv(&config.Registry.HTTPAuthMode, "POSTERN_REGISTRY_HTTP_AUTH_MODE", lookupEnv, sources, "registry.http_auth_mode")
	config.Registry.HTTPAuthMode = strings.ToLower(config.Registry.HTTPAuthMode)
	setStringFromEnv(&config.Registry.HTTPBearerToken, "POSTERN_REGISTRY_HTTP_BEARER_TOKEN", lookupEnv, sources, "registry.http_bearer_token")
	setStringFromEnv(&config.Registry.HTTPAWSRegion, "POSTERN_REGISTRY_HTTP_AWS_REGION", lookupEnv, sources, "registry.http_aws_region")
	if err := setDurationFromEnv(&config.Registry.HTTPTimeout, "POSTERN_REGISTRY_HTTP_TIMEOUT", lookupEnv, sources, "registry.http_timeout"); err != nil {
		return err
	}
	setStringFromEnv(&config.RateLimit.DynamoDBTable, "POSTERN_RATELIMIT_DYNAMODB_TABLE", lookupEnv, sources, "ratelimit.dynamodb_table")
	if err := setIntFromEnv(&config.RateLimit.Limit, "POSTERN_RATELIMIT_LIMIT", lookupEnv, sources, "ratelimit.limit"); err != nil {
		return err
	}
	if err := setDurationFromEnv(&config.RateLimit.Window, "POSTERN_RATELIMIT_WINDOW", lookupEnv, sources, "ratelimit.window"); err != nil {
		return err
	}
	setStringFromEnv(&config.Audit.CloudWatchLogGroup, "POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP", lookupEnv, sources, "audit.cloudwatch_log_group")
	setTunnelingRegionFromEnv(config, lookupEnv, sources)
	if err := setTunnelingMaxLifetimeFromEnv(config, lookupEnv, sources); err != nil {
		return err
	}
	setTunnelingThingNameFormatFromEnv(config, lookupEnv, sources)
	setStringFromEnv(&config.Policy.AVPPolicyStoreID, "POSTERN_POLICY_AVP_POLICY_STORE_ID", lookupEnv, sources, "policy.avp_policy_store_id")
	if err := setDurationFromEnv(&config.CertTTL.Operator, "POSTERN_CERT_TTL_OPERATOR", lookupEnv, sources, "cert_ttl.operator"); err != nil {
		return err
	}
	setStringSliceFromEnv(&config.TrustedProxies, "POSTERN_TRUSTED_PROXIES", lookupEnv, sources, "trusted_proxies")
	return nil
}

// setPrincipalClassesFromEnv loads the whole principal_classes block from
// POSTERN_IDP_PRINCIPAL_CLASSES, decoded as YAML (which also accepts JSON).
// This is how a deployment with no config file — the Lambda — configures the
// rule list. It replaces any file-provided block; POSTERN_IDP_PRINCIPAL_CLASS_-
// DEFAULT then overrides the default class on top. Unknown keys are rejected so
// a misspelled predicate or class key fails loudly rather than silently
// classifying every caller as the default.
func setPrincipalClassesFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) error {
	value, ok := lookupEnv("POSTERN_IDP_PRINCIPAL_CLASSES")
	if !ok || strings.TrimSpace(value) == "" {
		return nil
	}

	var parsed PrincipalClassesConfig
	decoder := yaml.NewDecoder(strings.NewReader(value))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return fmt.Errorf("POSTERN_IDP_PRINCIPAL_CLASSES: %w", err)
	}

	config.IDP.PrincipalClasses = &parsed
	sources["idp.principal_classes"] = "POSTERN_IDP_PRINCIPAL_CLASSES"
	return nil
}

// setPrincipalClassDefaultFromEnv overrides the default principal class,
// lazy-allocating the PrincipalClasses block when the env var is set but the
// section was absent from the file. With no rules, this default applies to
// every caller.
func setPrincipalClassDefaultFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) {
	if value, ok := lookupEnv("POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT"); ok {
		if value = strings.TrimSpace(value); value != "" {
			if config.IDP.PrincipalClasses == nil {
				config.IDP.PrincipalClasses = &PrincipalClassesConfig{}
			}
			config.IDP.PrincipalClasses.Default = value
			sources["idp.principal_classes.default"] = "POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT"
		}
	}
}

func setTunnelingRegionFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) {
	if value, ok := lookupEnv("POSTERN_TUNNELING_IOT_REGION"); ok {
		if value = strings.TrimSpace(value); value != "" {
			if config.Tunneling == nil {
				config.Tunneling = &TunnelingConfig{}
			}
			config.Tunneling.IOTRegion = value
			sources["tunneling.iot_region"] = "POSTERN_TUNNELING_IOT_REGION"
		}
	}
}

// setTunnelingThingNameFormatFromEnv lazy-allocates TunnelingConfig when
// the env var is set but the section was absent from the file.
func setTunnelingThingNameFormatFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) {
	if value, ok := lookupEnv("POSTERN_TUNNELING_THING_NAME_FORMAT"); ok {
		if value = strings.TrimSpace(value); value != "" {
			if config.Tunneling == nil {
				config.Tunneling = &TunnelingConfig{}
			}
			config.Tunneling.ThingNameFormat = value
			sources["tunneling.thing_name_format"] = "POSTERN_TUNNELING_THING_NAME_FORMAT"
		}
	}
}

// setTunnelingMaxLifetimeFromEnv lazy-allocates TunnelingConfig when the
// env var is set but the section was absent from the file.
func setTunnelingMaxLifetimeFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) error {
	value, ok := lookupEnv("POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES")
	if !ok {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES=%q: invalid integer: %w", value, err)
	}
	if config.Tunneling == nil {
		config.Tunneling = &TunnelingConfig{}
	}
	config.Tunneling.DefaultMaxLifetimeMinutes = int32(parsed)
	sources["tunneling.default_max_lifetime_minutes"] = "POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES"
	return nil
}

func setRegistryFromEnv(config *Config, lookupEnv func(string) (string, bool), sources map[string]string) {
	dynamoDBTable, hasDynamoDBTable := lookupTrimmedEnv("POSTERN_REGISTRY_DYNAMODB_TABLE", lookupEnv)
	httpURL, hasHTTPURL := lookupTrimmedEnv("POSTERN_REGISTRY_HTTP_URL", lookupEnv)
	if hasDynamoDBTable {
		config.Registry.DynamoDBTable = dynamoDBTable
		sources["registry.dynamodb_table"] = "POSTERN_REGISTRY_DYNAMODB_TABLE"
	}
	if hasHTTPURL {
		config.Registry.HTTPURL = httpURL
		sources["registry.http_url"] = "POSTERN_REGISTRY_HTTP_URL"
	}
	if hasDynamoDBTable && !hasHTTPURL {
		config.Registry.HTTPURL = ""
		delete(sources, "registry.http_url")
	}
	if hasHTTPURL && !hasDynamoDBTable {
		config.Registry.DynamoDBTable = ""
		delete(sources, "registry.dynamodb_table")
	}
}

func lookupTrimmedEnv(envName string, lookupEnv func(string) (string, bool)) (string, bool) {
	value, ok := lookupEnv(envName)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func setStringFromEnv(target *string, envName string, lookupEnv func(string) (string, bool), sources map[string]string, field string) {
	if value, ok := lookupEnv(envName); ok {
		if value = strings.TrimSpace(value); value != "" {
			*target = value
			sources[field] = envName
		}
	}
}

// setDurationFromEnv applies a duration env override. Parse failures are
// reported so operators see the rejected value rather than silent fallback.
func setDurationFromEnv(target *Duration, envName string, lookupEnv func(string) (string, bool), sources map[string]string, field string) error {
	value, ok := lookupEnv(envName)
	if !ok {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s=%q: invalid duration: %w", envName, value, err)
	}
	*target = Duration(parsed)
	sources[field] = envName
	return nil
}

// setStringSliceFromEnv applies a comma-separated env override, trimming
// each element and dropping empties.
func setStringSliceFromEnv(target *[]string, envName string, lookupEnv func(string) (string, bool), sources map[string]string, field string) {
	value, ok := lookupEnv(envName)
	if !ok {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return
	}
	*target = out
	sources[field] = envName
}

// setIntFromEnv applies an int env override. Parse failures are reported
// so operators see the rejected value.
func setIntFromEnv(target *int, envName string, lookupEnv func(string) (string, bool), sources map[string]string, field string) error {
	value, ok := lookupEnv(envName)
	if !ok {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%s=%q: invalid integer: %w", envName, value, err)
	}
	*target = parsed
	sources[field] = envName
	return nil
}
