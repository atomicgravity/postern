// Package brokerwire constructs the broker's default abstraction impls from
// a resolved Config and an aws.Config. Both cmd/broker (long-running) and
// cmd/broker-lambda wire from here so the dep stacks stay identical.
package brokerwire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/audit"
	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/idp"
	"github.com/atomicgravity/postern/internal/policy"
	"github.com/atomicgravity/postern/internal/ratelimit"
	"github.com/atomicgravity/postern/internal/registry"
	"github.com/atomicgravity/postern/internal/signer"
	"github.com/atomicgravity/postern/internal/tunneling"
	"github.com/atomicgravity/postern/pkg/brokerhandlers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/realclientip/realclientip-go"
)

// BuildDeps wires brokerhandlers.Deps from a resolved Config + aws.Config.
// The OIDC verifier hits the IdP discovery endpoint and the KMS signer
// fetches the CA public key during construction; ctx is the init-time
// context bounding both.
func BuildDeps(ctx context.Context, awsConfig aws.Config, config brokerhandlers.Config) (brokerhandlers.Deps, error) {
	defaultClass, classRules := principalClassConfig(config.IDP.PrincipalClasses)
	tokenVerifier, err := idp.NewOIDCVerifier(ctx, idp.OIDCVerifierConfig{
		Issuer:                config.IDP.Issuer,
		Audience:              config.IDP.Audience,
		RequiredScope:         config.IDP.RequiredScope,
		DefaultPrincipalClass: defaultClass,
		PrincipalClassRules:   classRules,
	})
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build OIDC verifier: %w", err)
	}

	certSigner, err := signer.NewKMSSignerFromConfig(ctx, awsConfig, config.Signer.KMSKeyARN)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build KMS signer: %w", err)
	}

	deviceRegistry, err := buildRegistry(awsConfig, config.Registry)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build device registry: %w", err)
	}

	rateLimiter, err := ratelimit.NewDynamoDBRateLimiterFromConfig(awsConfig, config.RateLimit.DynamoDBTable, config.RateLimit.Limit, config.RateLimit.Window.Duration())
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build rate limiter: %w", err)
	}

	authorizer, err := policy.NewAVPPolicyFromConfig(awsConfig, config.Policy.AVPPolicyStoreID)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build AVP policy: %w", err)
	}

	auditSink, err := audit.NewCloudWatchAuditFromConfig(awsConfig, config.Audit.CloudWatchLogGroup)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build CloudWatch audit: %w", err)
	}

	pipelineDeps := broker.PipelineDeps{
		TokenVerifier: tokenVerifier,
		Registry:      deviceRegistry,
		Policy:        authorizer,
		RateLimiter:   rateLimiter,
		Audit:         auditSink,
	}

	sshCertIssuer, err := broker.NewSSHCertIssuer(broker.SSHCertIssuerDeps{
		PipelineDeps:       pipelineDeps,
		Signer:             certSigner,
		OperatorTTL:        config.CertTTL.Operator.Duration(),
		OperatorTTLByClass: operatorTTLByClass(config.CertTTL.ByClass),
	})
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build SSH cert issuer: %w", err)
	}

	timePayloadIssuer, err := broker.NewTimePayloadIssuer(broker.TimePayloadIssuerDeps{
		PipelineDeps: pipelineDeps,
		Signer:       certSigner,
	})
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build time payload issuer: %w", err)
	}

	tunnelIssuer, err := buildTunnelIssuer(awsConfig, config.Tunneling, pipelineDeps)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build tunnel issuer: %w", err)
	}

	clientIPStrategy, err := buildClientIPStrategy(&config)
	if err != nil {
		return brokerhandlers.Deps{}, fmt.Errorf("build client-IP strategy: %w", err)
	}

	deps := brokerhandlers.Deps{
		SSHCertIssuer:     sshCertIssuer,
		TimePayloadIssuer: timePayloadIssuer,
		ClientIPStrategy:  clientIPStrategy,
	}
	if tunnelIssuer != nil {
		deps.TunnelIssuer = tunnelIssuer
	}

	return deps, nil
}

// buildTunnelIssuer wires the optional AWS IoT Secure Tunneling backend.
// Returns (nil, nil) when the broker YAML omits the tunneling section —
// /ssh/tunnel returns 501 on operator stacks that don't need it.
func buildTunnelIssuer(awsConfig aws.Config, config *brokerhandlers.TunnelingConfig, pipelineDeps broker.PipelineDeps) (*broker.TunnelIssuer, error) {
	if config == nil || config.IOTRegion == "" {
		return nil, nil
	}

	tun, err := tunneling.NewAWSIoTTunnelingFromConfig(awsConfig, config.IOTRegion)
	if err != nil {
		return nil, fmt.Errorf("build AWS IoT tunneling: %w", err)
	}

	return broker.NewTunnelIssuer(broker.TunnelIssuerDeps{
		PipelineDeps:              pipelineDeps,
		Tunneling:                 tun,
		DefaultMaxLifetimeMinutes: config.DefaultMaxLifetimeMinutes,
		ThingNameFormat:           config.ThingNameFormat,
	})
}

// buildClientIPStrategy returns the strategy that derives each engineer's
// source IP. Empty trusted_proxies short-circuits to the connecting socket
// address; otherwise the chain walks X-Forwarded-For rightmost-to-leftmost
// skipping trusted CIDRs and falls back to RemoteAddr.
func buildClientIPStrategy(config *brokerhandlers.Config) (realclientip.Strategy, error) {
	ranges, err := config.ParsedTrustedProxies()
	if err != nil {
		return nil, fmt.Errorf("parse trusted proxies: %w", err)
	}
	if len(ranges) == 0 {
		return realclientip.RemoteAddrStrategy{}, nil
	}

	rightmost, err := realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", ranges)
	if err != nil {
		return nil, fmt.Errorf("build client-ip strategy: %w", err)
	}

	return realclientip.NewChainStrategy(rightmost, realclientip.RemoteAddrStrategy{}), nil
}

func buildRegistry(awsConfig aws.Config, config brokerhandlers.RegistryConfig) (broker.Registry, error) {
	if config.HTTPURL == "" {
		return registry.NewDynamoDBRegistryFromConfig(awsConfig, config.DynamoDBTable)
	}

	httpClient := &http.Client{Timeout: registryHTTPTimeout(config)}

	authClient, err := buildRegistryHTTPClient(awsConfig, config, httpClient)
	if err != nil {
		return nil, err
	}
	if authClient == nil {
		return registry.NewHTTPRegistryWithClient(httpClient, config.HTTPURL)
	}

	return registry.NewHTTPRegistryWithClient(authClient, config.HTTPURL)
}

// registryHTTPTimeout resolves the Registry HTTP timeout, falling back to
// the package default. The default is generous (~15s) to accommodate
// Lambda-fronted registries with cold-start latency.
func registryHTTPTimeout(config brokerhandlers.RegistryConfig) time.Duration {
	if d := config.HTTPTimeout.Duration(); d > 0 {
		return d
	}
	return registry.DefaultHTTPRegistryTimeout
}

// buildRegistryHTTPClient wraps inner with the auth layer matching
// RegistryConfig. Returns (nil, nil) when no auth is configured.
func buildRegistryHTTPClient(awsConfig aws.Config, config brokerhandlers.RegistryConfig, inner registry.HTTPClient) (registry.HTTPClient, error) {
	switch config.HTTPAuthMode {
	case "", brokerhandlers.RegistryHTTPAuthModeNone:
		return nil, nil
	case brokerhandlers.RegistryHTTPAuthModeBearer:
		return registry.NewBearerAuthClient(inner, config.HTTPBearerToken), nil
	case brokerhandlers.RegistryHTTPAuthModeSigV4:
		region := config.HTTPAWSRegion
		if region == "" {
			region = awsConfig.Region
		}
		if region == "" {
			return nil, errors.New("registry.http_aws_region empty and AWS SDK could not resolve a region for SigV4 signing")
		}
		return registry.NewSigV4AuthClient(inner, awsConfig.Credentials, region), nil
	default:
		return nil, fmt.Errorf("unknown registry.http_auth_mode %q", config.HTTPAuthMode)
	}
}

// operatorTTLByClass maps the config's per-class cert-TTL ceilings to the
// plain time.Duration map the issuer consumes. Config.Validate has already
// rejected non-positive entries.
func operatorTTLByClass(byClass map[string]brokerhandlers.Duration) map[string]time.Duration {
	if len(byClass) == 0 {
		return nil
	}
	out := make(map[string]time.Duration, len(byClass))
	for class, ttl := range byClass {
		out[class] = ttl.Duration()
	}
	return out
}

// principalClassConfig maps the broker config's principal-classes block to the
// verifier's default class + ordered rule list. A nil block yields an empty
// default (the verifier substitutes "user") and no rules, so every caller is
// classified as the default class. Config.Validate has already confirmed each
// rule sets exactly one predicate; the predicate-form selection here mirrors
// that one-of contract.
func principalClassConfig(classes *brokerhandlers.PrincipalClassesConfig) (string, []idp.PrincipalClassRule) {
	if classes == nil {
		return "", nil
	}

	rules := make([]idp.PrincipalClassRule, 0, len(classes.Rules))
	for _, rule := range classes.Rules {
		rules = append(rules, principalClassRule(rule))
	}
	return classes.Default, rules
}

// principalClassRule maps one config rule to a verifier rule, selecting the
// predicate kind from whichever predicate field is set.
func principalClassRule(rule brokerhandlers.PrincipalClassRule) idp.PrincipalClassRule {
	out := idp.PrincipalClassRule{Class: strings.TrimSpace(rule.Class)}
	switch {
	case strings.TrimSpace(rule.ClaimPresent) != "":
		out.Predicate = idp.PredicateClaimPresent
		out.Claim = strings.TrimSpace(rule.ClaimPresent)
	case strings.TrimSpace(rule.ClaimAbsent) != "":
		out.Predicate = idp.PredicateClaimAbsent
		out.Claim = strings.TrimSpace(rule.ClaimAbsent)
	case strings.TrimSpace(rule.Claim) != "":
		out.Predicate = idp.PredicateClaimEquals
		out.Claim = strings.TrimSpace(rule.Claim)
		out.Value = rule.Equals
	case strings.TrimSpace(rule.ScopeContains) != "":
		out.Predicate = idp.PredicateScopeContains
		out.Value = strings.TrimSpace(rule.ScopeContains)
	}
	return out
}
