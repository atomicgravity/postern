package broker

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
)

// PrincipalType is the SSH cert principal kind requested by the engineer.
// Values cross the wire (JSON `principal_type` on /ssh/cert).
type PrincipalType string

const (
	PrincipalTypeOperator PrincipalType = "operator"
	PrincipalTypeTimefix  PrincipalType = "timefix"
)

// Mode labels the operation a request represents, scoping Policy and
// RateLimiter rules. ModeTunnel keys /ssh/tunnel; no SSH cert is produced
// there so it has no PrincipalType counterpart.
const (
	ModeOperator = "operator"
	ModeTimefix  = "timefix"
	ModeTunnel   = "tunnel"
)

// AuditEvent.Event values. Operators query CloudWatch Insights on these
// literal strings; treat them as a stable wire format.
//
// Each pipeline (cert mint, time payload, tunnel open) emits the same
// authorized / issued / denied triplet. The authorized row is recorded
// before the signing or AWS call and is fail-closed: if audit can't record
// the authorization decision, the signing / AWS call does not happen. The
// issued row is best-effort after the side-effect succeeds — failing to
// record it does not unwind the action (operators reconcile by joining
// authorized vs issued rows on `jti`). The denied row covers every
// early-return path with a stable `denied_reason` literal.
const (
	EventCertAuthorized = "ssh_cert_authorized"
	EventCertIssued     = "ssh_cert_issued"
	EventCertDenied     = "ssh_cert_denied"
)

const (
	EventTimePayloadAuthorized = "time_payload_authorized"
	EventTimePayloadIssued     = "time_payload_issued"
	EventTimePayloadDenied     = "time_payload_denied"
)

const (
	EventTunnelAuthorized = "tunnel_authorized"
	EventTunnelIssued     = "tunnel_issued"
	EventTunnelDenied     = "tunnel_denied"
)

// AuditEvent.DeniedReason values. Stable enum operators filter on (e.g.
// CloudWatch Insights `filter denied_reason = "device_not_found"`).
//
// Every broker request produces exactly one audit row — either a deny with
// one of these reasons or the authorized + issued success pair. New deny
// paths must add a reason here; auditless early returns are a regression.
const (
	// Handler-layer denials, emitted before engineer identity is known.
	DenyReasonMissingBearerToken   = "missing_bearer_token"
	DenyReasonMalformedRequestBody = "malformed_request_body"

	// Pipeline denials. Earlier-stage denials carry fewer known fields on
	// the audit event (invalid_access_token has no engineer_sub;
	// authorization_denied has the full set).
	DenyReasonInvalidPrincipalType = "invalid_principal_type"
	DenyReasonInvalidAccessToken   = "invalid_access_token"
	DenyReasonMissingDeviceID      = "missing_device_id"
	DenyReasonMissingPublicKey     = "missing_public_key"
	DenyReasonInvalidPublicKey     = "invalid_public_key"
	DenyReasonRateLimitExceeded    = "rate_limit_exceeded"
	DenyReasonDeviceNotFound       = "device_not_found"
	DenyReasonRegistryUnavailable  = "registry_unavailable"
	DenyReasonAuthorizationDenied  = "authorization_denied"
	DenyReasonPolicyUnavailable    = "policy_unavailable"

	// Signer failure covers both the cert-mint and time-payload pipelines
	// so operators can filter signer outages without endpoint-specific
	// clauses.
	DenyReasonSignerFailure = "signer_failure"

	// Time-payload nonce shape rejections. `missing_nonce` is whitespace-
	// only / empty; `invalid_nonce` is anything that fails the 32-byte
	// base64url-decoded shape check.
	DenyReasonMissingNonce = "missing_nonce"
	DenyReasonInvalidNonce = "invalid_nonce"

	// Tunnel-pipeline denials. `max_lifetime_exceeds_ceiling` rejects
	// requested TTLs above the 12h AWS ceiling without making an AWS call.
	// `tunneling_unavailable` surfaces non-quota AWS IoT control-plane
	// errors; `tunnel_limit_exceeded` maps AWS LimitExceededException so
	// operators can alert distinctly on quota saturation.
	DenyReasonMaxLifetimeExceedsCeiling = "max_lifetime_exceeds_ceiling"
	DenyReasonTunnelingUnavailable      = "tunneling_unavailable"
	DenyReasonTunnelLimitExceeded       = "tunnel_limit_exceeded"
)

// Cedar action labels referenced by AVP policies. Part of the operator-
// facing policy authoring surface — renaming requires coordinated policy-
// store updates.
const (
	PolicyActionMintOperatorCert = "MintOperatorCert"
	PolicyActionMintTimefixCert  = "MintTimefixCert"
	PolicyActionOpenTunnel       = "OpenTunnel"
)

// HandlerDenial is the metadata the HTTP handler captures for a pre-invocation
// denial. Engineer identity is unknown on this path; the audit row carries
// only what the handler observed.
type HandlerDenial struct {
	DeniedReason string
	DeviceID     string // empty if the request body didn't decode
	SourceIP     string
	UserAgent    string
}

// SSHCertIssueRequest is the broker-domain request to mint an SSH certificate.
// JSON tags pin the wire format on /ssh/cert; the wire and domain shapes
// intentionally coincide.
type SSHCertIssueRequest struct {
	AccessToken   string        `json:"-"`
	DeviceID      string        `json:"device_id"`
	PrincipalType PrincipalType `json:"principal_type"`
	PublicKey     string        `json:"public_key"`
	UserAgent     string        `json:"-"`
	RemoteAddr    string        `json:"-"`
}

// SSHCertIssueResponse is the broker-domain response from a successful mint.
type SSHCertIssueResponse struct {
	SSHCert             string `json:"ssh_cert"`
	CAPubkeyFingerprint string `json:"ca_pubkey_fingerprint"`
}

// EngineerClaims is the verified-engineer identity returned by TokenVerifier.
// Raw exposes the full claim set so the Policy layer can read claims the
// broker domain doesn't itself name.
type EngineerClaims struct {
	Subject string
	Email   string
	Groups  []string
	Raw     map[string]any
}

// DeviceRecord is the resolved device the Registry returns. Serial is the
// canonical immutable identity (hardware serial). Attributes carries
// operator-defined metadata that flows into the Policy entity; values may be
// string, bool, or int64 — other Go types are dropped at the Policy boundary
// rather than guessed at. Extend the Registry impls and the Cedar schema
// together if a new shape is needed.
type DeviceRecord struct {
	Serial     string
	FriendlyID string
	Attributes map[string]any
}

// TokenVerifier verifies the engineer's IdP-issued access token and returns
// the resulting EngineerClaims. The default impl is internal/idp.OIDCVerifier.
type TokenVerifier interface {
	VerifyAccessToken(context.Context, string) (EngineerClaims, error)
}

// Registry resolves a caller-supplied device_id to a DeviceRecord keyed on
// hardware serial. Default impls are internal/registry.DynamoDBRegistry and
// internal/registry.HTTPRegistry.
type Registry interface {
	ResolveDevice(context.Context, string) (DeviceRecord, error)
}

// Policy decides whether the engineer is authorized to perform the requested
// action on the resolved device. The default impl is internal/policy.AVPPolicy.
type Policy interface {
	Allow(context.Context, PolicyRequest) error
}

// RateLimiter enforces the per-engineer per-mode request budget. The default
// impl is internal/ratelimit.DynamoDBRateLimiter.
type RateLimiter interface {
	Allow(context.Context, RateLimitRequest) error
}

// CertSigner returns the broker's CA public key, signs SSH certificates, and
// signs JWS time-payload signing-inputs with the corresponding private key.
// Default impl is internal/signer.KMSSigner.
//
// There is no generic Sign([]byte) on this interface — purpose-specific
// methods preserve the byte-structure domain separation between SSH cert TBS
// bytes and JWS signing-inputs (one CA serves all signing roles). Adding a
// signing role requires a new method plus an explicit non-overlap argument
// against the existing signed-message shapes.
type CertSigner interface {
	PublicKey() ssh.PublicKey
	SignCert(context.Context, *ssh.Certificate) error
	SignTimePayload(context.Context, []byte) ([]byte, error)
}

// AuditSink records the per-issue AuditEvent. The default impl is
// internal/audit.CloudWatchAudit.
type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

// Clock returns the broker's notion of "now". SystemClock is the production
// impl; tests inject a fixed clock to make cert validity windows deterministic.
type Clock interface {
	Now() time.Time
}

// IDGenerator returns a fresh ID for an issued cert. UUIDv7Generator is the
// production impl; tests inject deterministic generators.
type IDGenerator interface {
	NewID(time.Time) (ID, error)
}

// PolicyRequest is the input the broker hands to a Policy at evaluation time.
// AccessToken is forwarded so AVP can call IsAuthorizedWithToken; Timestamp
// threads the broker's Clock through so policy evaluation sees the same
// "now" as audit and cert validity.
//
// Context is an optional bag of per-endpoint Cedar context attributes. The
// /ssh/tunnel pipeline populates it with the requested max_lifetime_minutes
// so operators can author per-fleet TTL ceilings via Cedar `when` clauses.
// The default Policy impl emits each recognized typed value as the matching
// Cedar attribute type; unknown types are dropped.
type PolicyRequest struct {
	AccessToken string
	Engineer    EngineerClaims
	Device      DeviceRecord
	Mode        string
	SourceIP    string
	UserAgent   string
	RequestID   string
	Timestamp   time.Time
	Context     map[string]any
}

// RateLimitRequest is the input the broker hands to a RateLimiter. Engineer
// and Mode key the per-engineer-per-mode counter; the rest is metadata.
type RateLimitRequest struct {
	Engineer  EngineerClaims
	Device    DeviceRecord
	Mode      string
	SourceIP  string
	UserAgent string
	RequestID string
}

// AuditEvent is the structured row an AuditSink persists per pipeline
// lifecycle event. Field names match the JSON shape operators query in
// CloudWatch Logs. Optional fields are absent on deny paths when the value
// isn't yet known (e.g., EngineerSub is empty on an invalid-access-token
// deny). EngineerGroups records IdP-resolved group memberships at decision
// time so incident review can reconstruct the policy basis without joining
// against current IdP state.
type AuditEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Event          string    `json:"event"`
	DeniedReason   string    `json:"denied_reason,omitempty"`
	EngineerSub    string    `json:"engineer_sub,omitempty"`
	EngineerEmail  string    `json:"engineer_email,omitempty"`
	EngineerGroups []string  `json:"engineer_groups,omitempty"`
	DeviceSerial   string    `json:"device_serial,omitempty"`
	DeviceIDUsed   string    `json:"device_id_used,omitempty"`
	PrincipalType  string    `json:"principal_type,omitempty"`
	CertSerial     string    `json:"cert_serial,omitempty"`
	JTI            string    `json:"jti"`
	ValidAfter     int64     `json:"valid_after,omitempty"`
	ValidBefore    int64     `json:"valid_before,omitempty"`
	IssuedAt       int64     `json:"issued_at,omitempty"`
	SourceIP       string    `json:"source_ip,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
}

// SystemClock is the production Clock impl that delegates to time.Now.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}

// Tunneling opens a device tunnel via the configured backend and returns the
// source-side access token the engineer's CLI bridges its localhost listener
// to. Single-method by design: the broker is stateless across tunnel sessions
// and never reads status, closes tunnels, or rotates tokens. Default impl is
// internal/tunneling.AWSIoTTunneling.
type Tunneling interface {
	OpenTunnel(context.Context, TunnelOpenInternal) (TunnelOpenResult, error)
}

// TunnelOpenInternal is the broker-domain request the Tunneling impl consumes,
// composed by the pipeline after preambles resolve the canonical device serial
// and the policy-clamped MaxLifetimeMinutes.
//
// Services is v1-fixed to `["SSH"]`; the field exists so a future multi-
// service tunnel doesn't require an interface change. ThingName is the AWS
// IoT thing-name the destination-side proxy subscribes under, produced by
// substituting the registry-resolved serial into the operator-configured
// tunneling.thing_name_format (default "device-{serial}").
type TunnelOpenInternal struct {
	ThingName          string
	Services           []string
	MaxLifetimeMinutes int32
}

// TunnelOpenResult is the broker-domain response from a successful tunnel
// open. AWS also returns a destination access token; that is intentionally
// dropped here because the destination side receives it via AWS IoT MQTT
// directly, not through the broker.
type TunnelOpenResult struct {
	TunnelID          string
	SourceAccessToken string
	Region            string
}

// TunnelOpenRequest is the HTTP wire-format request to /ssh/tunnel.
//
// MaxLifetimeMinutes is optional (zero/absent → broker's configured default).
// The broker resolves the final TTL as min(engineer_request,
// AVP_policy_ceiling, 12h_AWS_max).
type TunnelOpenRequest struct {
	AccessToken        string `json:"-"`
	DeviceID           string `json:"device_id"`
	MaxLifetimeMinutes int32  `json:"max_lifetime_minutes,omitempty"`
	UserAgent          string `json:"-"`
	RemoteAddr         string `json:"-"`
}

// TunnelOpenResponse is the HTTP wire-format response from /ssh/tunnel.
// Region tells the CLI which AWS region's data-tunneling endpoint to dial;
// the broker is the authority so the CLI doesn't have to know the
// operator's AWS region. MaxLifetimeMinutes is the resolved (post-clamping)
// TTL.
type TunnelOpenResponse struct {
	TunnelID           string `json:"tunnel_id"`
	SourceAccessToken  string `json:"source_access_token"`
	Region             string `json:"region"`
	MaxLifetimeMinutes int32  `json:"max_lifetime_minutes"`
}
