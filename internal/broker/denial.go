package broker

import (
	"context"
	"log/slog"
)

// Shared denial-emit helpers for the broker pipelines. The audit-coverage
// invariant — every broker request emits exactly one audit row — relies on
// every per-endpoint denial path going through these helpers.

// denialTemplate builds a partial deny audit row from an engineer context.
// Per-endpoint wrappers fill in Event / PrincipalType / DeviceIDUsed /
// DeniedReason before recording.
func denialTemplate(engineerCtx engineerContext) AuditEvent {
	return AuditEvent{
		Timestamp:      engineerCtx.Now,
		JTI:            engineerCtx.JTI,
		SourceIP:       engineerCtx.SourceIP,
		UserAgent:      engineerCtx.UserAgent,
		EngineerSub:    engineerCtx.Caller.Subject,
		EngineerEmail:  engineerCtx.Caller.Email,
		EngineerGroups: engineerCtx.Caller.Groups,
		PrincipalClass: engineerCtx.Caller.Class,
		ClientID:       engineerCtx.Caller.ClientID,
	}
}

// recordEndpointDenial emits a best-effort deny audit row for an in-pipeline
// denial. Audit-emission failures are logged but do not propagate — the
// request is already failing and we don't want to mask its reason. slogLabel
// is the endpoint name surfaced in broker logs ("SSH cert", "time payload",
// "tunnel").
func (deps PipelineDeps) recordEndpointDenial(ctx context.Context, event AuditEvent, slogLabel string) {
	if err := deps.Audit.Record(ctx, event); err != nil {
		slog.Error("record "+slogLabel+" denial audit event",
			slog.String("err", err.Error()),
			slog.String("denied_reason", event.DeniedReason),
			slog.String("engineer_sub", event.EngineerSub),
			slog.String("device_id_used", event.DeviceIDUsed),
			slog.String("jti", event.JTI))
	}
}

// recordEndpointHandlerDenial emits a best-effort deny audit row for a
// request that failed at the HTTP handler layer before the pipeline could
// run — missing bearer, malformed body, pre-identity field-level rejections.
// Handler-level early returns must call this; in-pipeline denials go via
// recordEndpointDenial. principalType is the constant the endpoint stamps
// for handler-level denials (empty for ssh-cert because the principal type
// rides in the body that failed to parse).
func (deps PipelineDeps) recordEndpointHandlerDenial(ctx context.Context, denial HandlerDenial, eventName, principalType, slogLabel string) {
	now := deps.Clock.Now().UTC()

	var jti string
	if id, err := deps.IDs.NewID(now); err == nil {
		jti = id.UUID
	}

	event := AuditEvent{
		Timestamp:     now,
		Event:         eventName,
		DeniedReason:  denial.DeniedReason,
		PrincipalType: principalType,
		JTI:           jti,
		SourceIP:      denial.SourceIP,
		UserAgent:     denial.UserAgent,
		DeviceIDUsed:  denial.DeviceID,
	}

	if err := deps.Audit.Record(ctx, event); err != nil {
		slog.Error("record "+slogLabel+" pre-invocation denial audit event",
			slog.String("err", err.Error()),
			slog.String("denied_reason", denial.DeniedReason),
			slog.String("source_ip", denial.SourceIP))
	}
}
