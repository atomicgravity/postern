package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Tunnel-open pipeline. TTL resolution clamps the requested
// max_lifetime_minutes to the 12h AWS ceiling and falls back to the operator
// default when omitted. The broker does NOT consult AVP for a numeric
// ceiling; AVP either allows or denies, and per-fleet TTL tightening is
// expressed as a Cedar `when` clause against
// `context.requested_max_lifetime_minutes`. The 12h hard cap is fixed.

const (
	// MaxTunnelLifetimeMinutes is the AWS IoT Secure Tunneling ceiling
	// (12 hours). Rejecting before the AWS call saves a credentialed
	// round-trip and gives operators a stable denied_reason literal.
	MaxTunnelLifetimeMinutes = int32(12 * 60)

	// DefaultTunnelLifetimeMinutes is the fallback when the engineer
	// doesn't pass --max-lifetime. Eight hours fits a full workday with
	// meeting breaks. Operators override via
	// tunneling.default_max_lifetime_minutes.
	DefaultTunnelLifetimeMinutes = int32(8 * 60)

	tunnelSerialPlaceholder      = "{serial}"
	defaultTunnelThingNameFormat = "device-" + tunnelSerialPlaceholder
)

// ErrTunnelingThingNameFormatInvalid is returned by NewTunnelIssuer when the
// configured ThingNameFormat doesn't contain exactly one {serial} placeholder.
var ErrTunnelingThingNameFormatInvalid = errors.New("tunneling thing-name format must contain exactly one {serial} placeholder")

// TunnelIssuerDeps wires the per-issue dependencies into the tunnel-open
// pipeline. DefaultMaxLifetimeMinutes is the fallback TTL when the engineer
// omits --max-lifetime; zero falls back to DefaultTunnelLifetimeMinutes.
// ThingNameFormat must contain exactly one "{serial}" placeholder; empty
// falls back to "device-{serial}".
//
// TargetFromRegistry makes each tunnel open where the device record says
// (TunnelRoleARNAttribute + TunnelRegionAttribute) instead of in the
// backend's own account; AllowedRoleARNs bounds which roles a registry
// entry may name, must be non-empty in that mode, and every entry must pass
// ValidAllowedRoleARN.
type TunnelIssuerDeps struct {
	PipelineDeps
	Tunneling                 Tunneling
	DefaultMaxLifetimeMinutes int32
	ThingNameFormat           string
	TargetFromRegistry        bool
	AllowedRoleARNs           []string
}

// TunnelIssuer runs /ssh/tunnel's pipeline.
type TunnelIssuer struct {
	PipelineDeps
	tunneling          Tunneling
	defaultMaxLifetime int32
	thingNameFormat    string
	targetFromRegistry bool
	allowedRoleARNs    []string
}

// NewTunnelIssuer constructs a TunnelIssuer. Missing deps return joined Err*
// sentinels; a ThingNameFormat without exactly one {serial} placeholder
// returns ErrTunnelingThingNameFormatInvalid.
func NewTunnelIssuer(deps TunnelIssuerDeps) (*TunnelIssuer, error) {
	pipelineErr := deps.PipelineDeps.validate()

	var tunnelingErr error
	if deps.Tunneling == nil {
		tunnelingErr = ErrTunnelingRequired
	}

	format := deps.ThingNameFormat
	if format == "" {
		format = defaultTunnelThingNameFormat
	}

	var formatErr error
	if strings.Count(format, tunnelSerialPlaceholder) != 1 {
		formatErr = fmt.Errorf("%w: %q", ErrTunnelingThingNameFormatInvalid, format)
	}

	var targetErr error
	if deps.TargetFromRegistry {
		if len(deps.AllowedRoleARNs) == 0 {
			targetErr = ErrTunnelingAllowedRoleARNsRequired
		} else {
			targetErr = validateAllowedRoleARNs(deps.AllowedRoleARNs)
		}
	}

	if joined := errors.Join(pipelineErr, tunnelingErr, formatErr, targetErr); joined != nil {
		return nil, joined
	}

	defaultLifetime := deps.DefaultMaxLifetimeMinutes
	if defaultLifetime <= 0 {
		defaultLifetime = DefaultTunnelLifetimeMinutes
	}
	if defaultLifetime > MaxTunnelLifetimeMinutes {
		defaultLifetime = MaxTunnelLifetimeMinutes
	}

	return &TunnelIssuer{
		PipelineDeps:       deps.PipelineDeps.withDefaults(),
		tunneling:          deps.Tunneling,
		defaultMaxLifetime: defaultLifetime,
		thingNameFormat:    format,
		targetFromRegistry: deps.TargetFromRegistry,
		allowedRoleARNs:    deps.AllowedRoleARNs,
	}, nil
}

// OpenTunnel runs the tunnel-open pipeline end to end and returns the
// AWS-side source access token + tunnel ID + region for the CLI's source
// proxy to dial. Same fail-closed-pre-call / best-effort-post-call audit
// pattern the cert-mint and time-payload pipelines use. On AWS failure
// the deny row's reason is tunnel_limit_exceeded (LimitExceededException),
// tunnel_target_access_denied (a registry target refused the broker), or
// tunneling_unavailable (everything else).
func (i *TunnelIssuer) OpenTunnel(ctx context.Context, request TunnelOpenRequest) (TunnelOpenResponse, error) {
	engineerCtx, denial, err := i.verifyEngineer(ctx, engineerPreambleRequest{
		AccessToken: request.AccessToken,
		Mode:        ModeTunnel,
		SourceIP:    request.RemoteAddr,
		UserAgent:   request.UserAgent,
	})
	if err != nil {
		return TunnelOpenResponse{}, fmt.Errorf("generate tunnel id: %w", err)
	}
	if denial != nil {
		i.recordTunnelDenialFor(ctx, denial.Event, denial.DeniedReason, request)
		return TunnelOpenResponse{}, denial.Err
	}

	requestedLifetime := request.MaxLifetimeMinutes
	if requestedLifetime < 0 {
		i.recordTunnelDenialFor(ctx, denialTemplate(engineerCtx), DenyReasonMaxLifetimeExceedsCeiling, request)
		return TunnelOpenResponse{}, Error{StatusCode: http.StatusBadRequest, Message: "max_lifetime_minutes must be non-negative"}
	}
	if requestedLifetime > MaxTunnelLifetimeMinutes {
		i.recordTunnelDenialFor(ctx, denialTemplate(engineerCtx), DenyReasonMaxLifetimeExceedsCeiling, request)
		return TunnelOpenResponse{}, Error{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("max_lifetime_minutes must be at most %d (AWS 12-hour ceiling)", MaxTunnelLifetimeMinutes)}
	}

	resolvedLifetime := requestedLifetime
	if resolvedLifetime == 0 {
		resolvedLifetime = i.defaultMaxLifetime
	}

	deviceCtx, denial, err := i.resolveDevice(ctx, devicePreambleRequest{
		Caller:      engineerCtx.Caller,
		AccessToken: request.AccessToken,
		DeviceID:    request.DeviceID,
		Mode:        ModeTunnel,
		SourceIP:    engineerCtx.SourceIP,
		UserAgent:   engineerCtx.UserAgent,
		JTI:         engineerCtx.JTI,
		Now:         engineerCtx.Now,
		// Surface the resolved (post-default-substitution) TTL to Cedar.
		// If we passed the raw requested value, an engineer omitting
		// --max-lifetime would bypass per-fleet `context.requested_
		// max_lifetime_minutes <= N` ceilings because zero satisfies
		// the predicate.
		PolicyContext: map[string]any{
			"requested_max_lifetime_minutes": int64(resolvedLifetime),
		},
	})
	if err != nil {
		return TunnelOpenResponse{}, err
	}
	if denial != nil {
		i.recordTunnelDenialFor(ctx, denial.Event, denial.DeniedReason, request)
		return TunnelOpenResponse{}, denial.Err
	}

	// Target checks run after Policy so an unauthorized engineer learns
	// nothing about the device's tunnel configuration.
	var target *TunnelTarget
	if i.targetFromRegistry {
		resolved, targetDenial := resolveTunnelTarget(deviceCtx.Device, i.allowedRoleARNs)
		if targetDenial != nil {
			event := denialTemplate(engineerCtx)
			event.DeviceSerial = deviceCtx.Device.Serial
			i.recordTunnelDenialFor(ctx, event, targetDenial.reason, request)
			slog.Warn("tunnel target rejected",
				slog.String("denied_reason", targetDenial.reason),
				slog.String("detail", targetDenial.detail),
				slog.String("device_serial", deviceCtx.Device.Serial),
				slog.String("jti", engineerCtx.JTI))
			return TunnelOpenResponse{}, targetDenial.err
		}
		target = resolved
	}

	// tunnel_authorized records the resolved TTL by reusing ValidBefore
	// (overloaded as Issue+TTL for tunnel rows). JTI joins authorized↔issued
	// on success or authorized↔denied on AWS failure.
	authorized := AuditEvent{
		Timestamp:      engineerCtx.Now,
		Event:          EventTunnelAuthorized,
		EngineerSub:    engineerCtx.Caller.Subject,
		EngineerEmail:  engineerCtx.Caller.Email,
		EngineerGroups: engineerCtx.Caller.Groups,
		PrincipalClass: engineerCtx.Caller.Class,
		ClientID:       engineerCtx.Caller.ClientID,
		DeviceSerial:   deviceCtx.Device.Serial,
		DeviceIDUsed:   request.DeviceID,
		PrincipalType:  ModeTunnel,
		JTI:            engineerCtx.JTI,
		IssuedAt:       engineerCtx.Now.Unix(),
		ValidBefore:    engineerCtx.Now.Add(time.Duration(resolvedLifetime) * time.Minute).Unix(),
		SourceIP:       engineerCtx.SourceIP,
		UserAgent:      engineerCtx.UserAgent,
	}
	if err := i.recordAuthorized(ctx, authorized); err != nil {
		return TunnelOpenResponse{}, fmt.Errorf("record tunnel audit event: %w", err)
	}

	result, err := i.tunneling.OpenTunnel(ctx, TunnelOpenInternal{
		ThingName:          i.thingName(deviceCtx.Device.Serial),
		Services:           []string{"SSH"},
		MaxLifetimeMinutes: resolvedLifetime,
		Target:             target,
	})
	if err != nil {
		denied := authorized
		denied.Event = EventTunnelDenied
		denied.DeniedReason = tunnelingDenyReason(err)
		i.recordEndpointDenial(ctx, denied, "tunnel")

		// Log the raw backend error before mapping to the generic engineer-
		// facing 5xx. The wire response carries only the deny_reason literal;
		// the operator needs the SDK message (AccessDenied, ResourceNotFound,
		// region misconfiguration, ...) to diagnose.
		attrs := []any{
			slog.String("err", err.Error()),
			slog.String("denied_reason", denied.DeniedReason),
			slog.String("engineer_sub", engineerCtx.Caller.Subject),
			slog.String("device_serial", deviceCtx.Device.Serial),
			slog.String("thing_name", i.thingName(deviceCtx.Device.Serial)),
			slog.String("jti", engineerCtx.JTI),
		}
		if target != nil {
			attrs = append(attrs,
				slog.String("tunnel_role_arn", target.RoleARN),
				slog.String("tunnel_region", target.Region))
		}
		slog.Error("tunneling backend OpenTunnel failed", attrs...)
		return TunnelOpenResponse{}, mapTunnelingError(err)
	}

	// Post-AWS-call audit is best-effort: the tunnel is provisioned and
	// the token is on its way back.
	issued := authorized
	issued.Event = EventTunnelIssued
	if err := i.Audit.Record(ctx, issued); err != nil {
		slog.Error("record tunnel issuance audit event",
			slog.String("err", err.Error()),
			slog.String("engineer_sub", engineerCtx.Caller.Subject),
			slog.String("device_serial", deviceCtx.Device.Serial),
			slog.String("jti", engineerCtx.JTI))
	}
	// The audit row doesn't say which account the tunnel opened in, and the
	// target account's CloudTrail names only the broker; this line joins them.
	if target != nil {
		slog.Info("tunnel opened in target account",
			slog.String("tunnel_id", result.TunnelID),
			slog.String("tunnel_role_arn", target.RoleARN),
			slog.String("tunnel_region", target.Region),
			slog.String("engineer_sub", engineerCtx.Caller.Subject),
			slog.String("device_serial", deviceCtx.Device.Serial),
			slog.String("jti", engineerCtx.JTI))
	}

	return TunnelOpenResponse{
		TunnelID:           result.TunnelID,
		SourceAccessToken:  result.SourceAccessToken,
		Region:             result.Region,
		MaxLifetimeMinutes: resolvedLifetime,
	}, nil
}

// recordTunnelDenialFor stamps the endpoint fields and emits the best-effort
// tunnel_denied audit row.
func (i *TunnelIssuer) recordTunnelDenialFor(ctx context.Context, event AuditEvent, deniedReason string, request TunnelOpenRequest) {
	event.Event = EventTunnelDenied
	event.DeniedReason = deniedReason
	event.DeviceIDUsed = request.DeviceID
	event.PrincipalType = ModeTunnel
	i.recordEndpointDenial(ctx, event, "tunnel")
}

// RecordTunnelHandlerDenial emits the deny audit row for HTTP-handler-layer
// rejections before OpenTunnel runs.
func (i *TunnelIssuer) RecordTunnelHandlerDenial(ctx context.Context, denial HandlerDenial) {
	i.recordEndpointHandlerDenial(ctx, denial, EventTunnelDenied, ModeTunnel, "tunnel")
}

// thingName maps a device serial to the AWS IoT thing name by substituting
// into the configured format. Default "device-{serial}" matches the
// operator/timefix principal naming.
func (i *TunnelIssuer) thingName(serial string) string {
	return strings.Replace(i.thingNameFormat, tunnelSerialPlaceholder, serial, 1)
}

// TunnelingErrorClassifier lets the Tunneling concrete impl surface
// AWS-error-class information without leaking SDK types across the broker
// interface.
type TunnelingErrorClassifier interface {
	TunnelingErrorKind() TunnelingErrorKind
}

// TunnelingErrorKind names the error categories the broker distinguishes
// for tunnel-open backend failures.
type TunnelingErrorKind int

const (
	// TunnelingErrorUnknown maps to tunneling_unavailable / 503.
	TunnelingErrorUnknown TunnelingErrorKind = iota
	// TunnelingErrorLimitExceeded maps the AWS LimitExceededException to
	// tunnel_limit_exceeded / 429 so operators can alert distinctly on
	// quota saturation.
	TunnelingErrorLimitExceeded
	// TunnelingErrorTargetAccessDenied maps a registry-targeted tunnel the
	// target account refuses (the role won't let the broker assume it, or
	// lacks iot:OpenTunnel) to tunnel_target_access_denied / 500: an operator
	// misconfiguration, not an outage worth retrying.
	TunnelingErrorTargetAccessDenied
)

// tunnelingDenyReason maps a Tunneling error to an audit-stable reason
// literal. errors.As preserves classifier routing through fmt.Errorf wraps.
func tunnelingDenyReason(err error) string {
	if err == nil {
		return ""
	}
	switch tunnelingErrorKind(err) {
	case TunnelingErrorLimitExceeded:
		return DenyReasonTunnelLimitExceeded
	case TunnelingErrorTargetAccessDenied:
		return DenyReasonTunnelTargetAccessDenied
	}
	return DenyReasonTunnelingUnavailable
}

// mapTunnelingError maps a Tunneling error to the broker.Error the HTTP
// boundary surfaces: LimitExceeded → 429, TargetAccessDenied → 500,
// everything else → 503.
func mapTunnelingError(err error) error {
	switch tunnelingErrorKind(err) {
	case TunnelingErrorLimitExceeded:
		return Error{StatusCode: http.StatusTooManyRequests, Message: "tunnel quota exceeded; close idle tunnels or contact your operator"}
	case TunnelingErrorTargetAccessDenied:
		return Error{StatusCode: http.StatusInternalServerError, Message: "broker can't open tunnels in the device's account; contact your operator"}
	}
	return Error{StatusCode: http.StatusServiceUnavailable, Message: "tunneling backend unavailable"}
}

// tunnelingErrorKind reads the classifier through fmt.Errorf wraps;
// unclassified errors are TunnelingErrorUnknown.
func tunnelingErrorKind(err error) TunnelingErrorKind {
	var classifier TunnelingErrorClassifier
	if errors.As(err, &classifier) {
		return classifier.TunnelingErrorKind()
	}
	return TunnelingErrorUnknown
}
