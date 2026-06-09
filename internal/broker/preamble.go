package broker

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Shared preambles for the broker pipelines. verifyEngineer runs the
// engineer-identity gates (TokenVerify + RateLimit) every authenticated
// endpoint owes its callers; resolveDevice runs the device-binding gates
// (Registry + Policy) device-targeted endpoints add on top.
//
// Each preamble returns a typed context on success and a *preambleDenial on
// failure. The denial carries a stable denied_reason literal plus a partial
// AuditEvent template; the endpoint stamps Event and PrincipalType before
// recording. The Event vocabulary (`ssh_cert_authorized` etc.) stays per-
// endpoint — routing it through the preambles would put endpoint-specific
// vocabulary in shared code.

// PipelineDeps holds the dependencies every issuer composes. Each issuer
// embeds PipelineDeps and supplies endpoint-specific extras (Signer for
// cert-mint and time-payload; Tunneling for tunnel-open).
type PipelineDeps struct {
	TokenVerifier TokenVerifier
	Registry      Registry
	Policy        Policy
	RateLimiter   RateLimiter
	Audit         AuditSink
	Clock         Clock
	IDs           IDGenerator
}

// validate reports every missing required dep at once via errors.Join.
func (d PipelineDeps) validate() error {
	var errs []error
	if d.TokenVerifier == nil {
		errs = append(errs, ErrTokenVerifierRequired)
	}
	if d.Registry == nil {
		errs = append(errs, ErrRegistryRequired)
	}
	if d.Policy == nil {
		errs = append(errs, ErrPolicyRequired)
	}
	if d.RateLimiter == nil {
		errs = append(errs, ErrRateLimiterRequired)
	}
	if d.Audit == nil {
		errs = append(errs, ErrAuditRequired)
	}
	return errors.Join(errs...)
}

// withDefaults backfills Clock and IDs with production defaults when the
// caller passes zero values.
func (d PipelineDeps) withDefaults() PipelineDeps {
	if d.Clock == nil {
		d.Clock = SystemClock{}
	}
	if d.IDs == nil {
		d.IDs = UUIDv7Generator{}
	}
	return d
}

// engineerPreambleRequest is the input to verifyEngineer.
type engineerPreambleRequest struct {
	AccessToken string
	Mode        string
	SourceIP    string
	UserAgent   string
}

// engineerContext is the verifyEngineer success output: the resolved engineer
// claims plus per-request metadata downstream steps need without re-deriving.
//
// ID carries the per-request UUID (used as JTI / RequestID / log correlation)
// and the matching 64-bit cert Serial (consumed only by the cert-mint
// endpoint). Both come from one IDGenerator call so the cert-Serial / JTI
// relationship is stable in the audit trail.
type engineerContext struct {
	Caller    CallerClaims
	Now       time.Time
	ID        ID
	JTI       string
	SourceIP  string
	UserAgent string
}

// devicePreambleRequest is the input to resolveDevice.
//
// PolicyContext is optional Cedar-context attributes the per-endpoint pipeline
// may inject. Today only the tunnel pipeline populates it (with the requested
// max_lifetime_minutes so operators can author per-fleet TTL ceilings).
type devicePreambleRequest struct {
	Caller        CallerClaims
	AccessToken   string
	DeviceID      string
	Mode          string
	SourceIP      string
	UserAgent     string
	JTI           string
	Now           time.Time
	PolicyContext map[string]any
}

// deviceContext is the resolveDevice success output.
type deviceContext struct {
	Device DeviceRecord
}

// preambleDenial carries a preamble-level failure back to the endpoint, which
// stamps Event and PrincipalType onto Event before recording.
type preambleDenial struct {
	DeniedReason string
	Event        AuditEvent
	Err          error
}

// verifyEngineer runs TokenVerify + RateLimit and captures the per-request
// metadata downstream steps need. On token-verify failure the denial template
// has only request metadata; on success it carries engineer subject/email/
// groups so a later device-side deny records who the request belonged to.
func (d PipelineDeps) verifyEngineer(ctx context.Context, r engineerPreambleRequest) (engineerContext, *preambleDenial, error) {
	now := d.Clock.Now().UTC()

	id, err := d.IDs.NewID(now)
	if err != nil {
		return engineerContext{}, nil, err
	}

	template := AuditEvent{
		Timestamp: now,
		JTI:       id.UUID,
		SourceIP:  r.SourceIP,
		UserAgent: r.UserAgent,
	}

	caller, err := d.TokenVerifier.VerifyAccessToken(ctx, r.AccessToken)
	if err != nil {
		slog.Warn("verify access token", "err", err, "mode", r.Mode)
		return engineerContext{}, &preambleDenial{
			DeniedReason: DenyReasonInvalidAccessToken,
			Event:        template,
			Err:          Error{StatusCode: http.StatusUnauthorized, Message: "invalid access token"},
		}, nil
	}

	template.EngineerSub = caller.Subject
	template.EngineerEmail = caller.Email
	template.EngineerGroups = caller.Groups
	template.PrincipalClass = caller.Class
	template.ClientID = caller.ClientID

	if err := d.RateLimiter.Allow(ctx, RateLimitRequest{
		Caller:    caller,
		Mode:      r.Mode,
		SourceIP:  r.SourceIP,
		UserAgent: r.UserAgent,
		RequestID: id.UUID,
	}); err != nil {
		return engineerContext{}, &preambleDenial{
			DeniedReason: DenyReasonRateLimitExceeded,
			Event:        template,
			Err:          err,
		}, nil
	}

	return engineerContext{
		Caller:    caller,
		Now:       now,
		ID:        id,
		JTI:       id.UUID,
		SourceIP:  r.SourceIP,
		UserAgent: r.UserAgent,
	}, nil, nil
}

// resolveDevice runs the empty-device_id guard, Registry.ResolveDevice, the
// empty-Serial guard, and Policy.Allow. DeviceSerial is added to the denial
// template once Registry succeeds so a subsequent Policy deny records the
// device the engineer was trying to reach. Cert-shape rejection lives in
// IssueSSHCert's tail — it's a cert-mint request-shape check, not part of
// the shared device-targeting gate.
func (d PipelineDeps) resolveDevice(ctx context.Context, r devicePreambleRequest) (deviceContext, *preambleDenial, error) {
	template := AuditEvent{
		Timestamp:      r.Now,
		JTI:            r.JTI,
		SourceIP:       r.SourceIP,
		UserAgent:      r.UserAgent,
		EngineerSub:    r.Caller.Subject,
		EngineerEmail:  r.Caller.Email,
		EngineerGroups: r.Caller.Groups,
		PrincipalClass: r.Caller.Class,
		ClientID:       r.Caller.ClientID,
	}

	if strings.TrimSpace(r.DeviceID) == "" {
		return deviceContext{}, &preambleDenial{
			DeniedReason: DenyReasonMissingDeviceID,
			Event:        template,
			Err:          Error{StatusCode: http.StatusBadRequest, Message: "device_id is required"},
		}, nil
	}

	device, err := d.Registry.ResolveDevice(ctx, r.DeviceID)
	if err != nil {
		return deviceContext{}, &preambleDenial{
			DeniedReason: registryDenyReason(err),
			Event:        template,
			Err:          err,
		}, nil
	}
	if device.Serial == "" {
		return deviceContext{}, &preambleDenial{
			DeniedReason: DenyReasonRegistryUnavailable,
			Event:        template,
			Err:          Error{StatusCode: http.StatusInternalServerError, Message: "registry returned empty device serial"},
		}, nil
	}
	template.DeviceSerial = device.Serial

	if err := d.Policy.Allow(ctx, PolicyRequest{
		AccessToken: r.AccessToken,
		Caller:      r.Caller,
		Device:      device,
		Mode:        r.Mode,
		SourceIP:    r.SourceIP,
		UserAgent:   r.UserAgent,
		RequestID:   r.JTI,
		Timestamp:   r.Now,
		Context:     r.PolicyContext,
	}); err != nil {
		return deviceContext{}, &preambleDenial{
			DeniedReason: policyDenyReason(err),
			Event:        template,
			Err:          err,
		}, nil
	}

	return deviceContext{Device: device}, nil, nil
}

// recordAuthorized is the fail-closed pre-Sign audit emit shared by the
// device-bound endpoints. A non-nil return MUST abort the caller before any
// Sign / AWS-call — the broker fails closed if it can't record what it would
// otherwise do.
func (d PipelineDeps) recordAuthorized(ctx context.Context, event AuditEvent) error {
	return d.Audit.Record(ctx, event)
}

// registryDenyReason maps a Registry error to an audit-stable reason literal:
// 404 → device_not_found, anything else → registry_unavailable.
func registryDenyReason(err error) string {
	var domainErr Error
	if errors.As(err, &domainErr) && domainErr.StatusCode == http.StatusNotFound {
		return DenyReasonDeviceNotFound
	}
	return DenyReasonRegistryUnavailable
}

// policyDenyReason maps a Policy error to an audit-stable reason literal:
// 403 → authorization_denied, anything else → policy_unavailable.
func policyDenyReason(err error) string {
	var domainErr Error
	if errors.As(err, &domainErr) && domainErr.StatusCode == http.StatusForbidden {
		return DenyReasonAuthorizationDenied
	}
	return DenyReasonPolicyUnavailable
}
