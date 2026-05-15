# Broker Security Deep-Dive Audit — Post-Timefix

Date: 2026-05-13
Scope: broker pipeline + HTTP surface + rate-limit + registry + AVP policy + audit sink.
Lens: security only (correctness/quality/docs out of scope).
Inputs: AGENTS.md, DESIGN.md (broker pipeline section), architect-log LD-64/65/80/83/84/90/91 + LD-CORR-6 + LD-M-4/11/20.
Out of scope: CLI, on-device timefix binaries (other auditors' lenses).

## Summary

The broker pipeline is in good shape post-timefix. LD-83's two-preamble split has not weakened the LD-65 audit invariant: every external-call cost (Registry, Policy, KMS) is still gated by TokenVerify + RateLimit, the per-mode dispatch is localized to AVPPolicy, and the recordAuthorized fail-closed contract is honored at both endpoints. LD-90/LD-91's switch to go-jose on both sides removes the highest-risk hand-rolled crypto surface.

No HIGH findings. Three MEDIUM findings cluster around the audit-invariant edge cases the LD-65 wording doesn't cover (no panic-recovery middleware; ID-generator failure path bypasses audit; `/ssh/tunnel` 501 stub is unauthenticated and auditless). Five LOW findings cover error-classification accuracy, secret-redaction gaps in --print-config, and starter-Cedar timefix omission. Eleven INFO items capture defense-in-depth observations and hardening opportunities.

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 3     |
| LOW      | 5     |
| INFO     | 11    |

## High

(none)

## Medium

### F-BRK-M1 — No panic-recovery middleware: panics between TokenVerify and recordAuthorized bypass the audit invariant

`pkg/brokerhandlers/handlers.go` mounts handlers on a stdlib `http.ServeMux` with no panic-recovery wrapper. Go's `net/http` package recovers per-goroutine panics and returns a generic 500, but it does NOT invoke any application code on the recovery path. The implication: a panic anywhere inside `IssueSSHCert` or `IssueTimePayload` after the preambles have started bypasses every `recordDenial` / `recordCertDenial` / `recordTimePayloadDenialFor` call site. The LD-65 "every request → exactly one audit row" invariant assumes the function returns normally on every path; panics are an unhandled escape hatch.

Practical risk: low-probability in production (the pipeline's external calls all return errors, not panics), but a future contributor adding code that can panic (slice index, map-value-of-nil, type assertion without `,ok`, divide by zero from a Cedar attribute coerced wrong) silently breaks the invariant.

Recommendation: wrap the mux with a recovery middleware that, on panic, emits a best-effort `ssh_cert_denied` / `time_payload_denied` audit row with `denied_reason: internal_error` before letting net/http's default panic-to-500 path run. Source IP + JTI are the minimum fields; engineer identity may be unknown if the panic was pre-TokenVerify. Add a stable `DenyReasonInternalError` literal.

### F-BRK-M2 — `IDGenerator.NewID` failure inside verifyEngineer bypasses the audit invariant

`internal/broker/preamble.go` lines 109-112: if `i.deps.IDs.NewID(now)` returns a non-nil error (entropy-source failure on `crypto/rand`), `verifyEngineer` returns `(engineerContext{}, nil, err)`. The endpoint's call sites (sshcert.go:156-158, issuetimepayload.go:130-132) propagate that error to the caller and return 500 with NO audit row emitted.

The "every request → one audit outcome" invariant doesn't hold on this path. Probability in practice is near zero on Linux/macOS (getrandom(2) doesn't fail outside of FIPS-mode boot races), but the gap is structural: there is no fallback to record "we tried to handle this request but couldn't generate an ID."

Recommendation: in this rare failure mode, emit a best-effort `*_denied` row with `denied_reason: internal_error` (same literal as M1) carrying only source IP + user agent before returning. JTI can be omitted or stamped with a sentinel like `"id-gen-failure"`.

### F-BRK-M3 — `/ssh/tunnel` is unauthenticated, auditless, and accepts any HTTP verb

`pkg/brokerhandlers/handlers.go` line 108: `mux.HandleFunc("/ssh/tunnel", unimplementedHandler)`. Unlike `POST /ssh/cert` and `POST /ssh/time-payload`, this route has no method restriction and no auth check; the handler returns a static 501 without consulting the bearer token, without emitting an audit row, and without rate-limit.

Pre-impl placeholder for the tunneling phase, but currently in shipping code. Threat:
- Anonymous attacker can spam `/ssh/tunnel` to amplify Lambda cold-starts / drive synthetic costs.
- The "every broker request → one audit outcome" invariant is silently violated by this endpoint today. Operators correlating across audit + access-log won't see `/ssh/tunnel` probes in audit.
- Mixed verbs (GET/PUT/PATCH/DELETE/OPTIONS) all hit the same handler — no per-verb signaling to operators.

Recommendation: until the tunneling impl lands, restrict to `POST /ssh/tunnel`, require a bearer token (parse + `RecordHandlerDenial` on missing), and emit a best-effort `tunnel_denied` audit row with `denied_reason: unimplemented`. Two new constants: `EventTunnelDenied = "tunnel_denied"`, `DenyReasonUnimplemented = "unimplemented"`. Pairs with the LD-66 APIGW-JWT-authorizer story (optional pre-filter), but the broker layer should not assume the pre-filter is present.

## Low

### F-BRK-L1 — `--print-config` outputs `registry.http_bearer_token` in plaintext

`pkg/brokerhandlers/config.go` `PrintResolvedConfig` serializes the full `Config` struct including `Registry.HTTPBearerToken`. The field's own godoc warns operators against committing it to YAML, but the CLI flag prints it verbatim to stdout (where it lands in operator terminal histories, CI logs, container logs).

Recommendation: in `PrintResolvedConfig`, replace `HTTPBearerToken` with a sentinel like `"<redacted; len=NN, source=POSTERN_REGISTRY_HTTP_BEARER_TOKEN>"` whenever the value is non-empty. Operators get the source + length for sanity-checking without exfiltrating the secret. Same treatment for any future secret-shaped fields (none currently exist).

### F-BRK-L2 — `verifyEngineer` classifies every IdP-side error as `invalid_access_token`

`internal/broker/preamble.go` lines 121-128: any error from `TokenVerifier.VerifyAccessToken` (including network failures during JWKs refresh, context deadline exceeded, OIDC-discovery cache miss + IdP timeout) produces `DenyReasonInvalidAccessToken`. An IdP outage is operationally distinct from a malformed/expired token — the former is an availability incident the operator should be alerted to, the latter is engineer-fault.

Recommendation: introduce a `DenyReasonIDPUnavailable` literal and have `OIDCVerifier.VerifyAccessToken` return a typed error (or a `broker.Error` with StatusCode 502/503) the preamble can `errors.As` to distinguish IdP-side faults from token-side faults. Operators get clean filterable categories in CloudWatch Insights; engineers still get 401 either way.

### F-BRK-L3 — Starter Cedar policy permits `MintOperatorCert` but not `MintTimefixCert`

`terraform/postern-broker/cedar/starter.cedar` only contains a `permit` for `Postern::Action::"MintOperatorCert"`. The timefix path now reaches AVP with action `MintTimefixCert` (per LD-80), which is implicitly denied under Cedar's deny-by-default semantics. Operators copying the starter policy will see all `postern timefix` requests fail with `authorization_denied` and may not realize a second `permit` is required.

Recommendation: add a second `permit` clause for `MintTimefixCert` to the starter (mirroring the operator one), with a comment that the recovery flow generally wants the same population as operator mints unless the operator wants stricter device-clock-recovery gating.

### F-BRK-L4 — Bearer-token parser accepts multiple spaces between scheme and token

`pkg/brokerhandlers/handlers.go` `bearerToken` strips the literal `"bearer "` prefix (single ASCII space) but then `strings.TrimSpace`s the remainder, accepting `Authorization: Bearer  <token>` (two spaces, or a tab) as well as trailing whitespace. RFC 6750 ABNF allows exactly one SP between scheme and token. Not a header-smuggling primitive against Go's parser, but a downstream proxy / WAF that parses headers more strictly may disagree on what constitutes a valid bearer header — bypass surface for any auth-shadow rule.

Recommendation: change `strings.TrimSpace(header[len(scheme):])` to a strict variant that rejects leading whitespace, accepting only `Bearer <token>` with exactly one space and trailing whitespace allowed (or none). Cheaper alternative: compare `header[len(scheme):]` directly against trailing-trimmed value and reject if the leading char is space/tab.

### F-BRK-L5 — `/healthz` 503 message reveals broker misconfiguration to unauthenticated callers

`pkg/brokerhandlers/handlers.go` line 132-134: when `issuer == nil`, the 503 response body is the literal JSON `{"error":"ssh cert issuer is not configured"}`. This tells an anonymous prober that a misconfigured broker is running at this URL, which is more information than "service unavailable" should disclose at an unauthenticated endpoint.

Recommendation: return a generic "unhealthy" message body on both arms of `handleHealthz` (the issuer-nil arm and the HealthChecker-failed arm). Internal logs already capture the actual reason via slog.Error in the wiring path; the public 503 doesn't need to differentiate.

## Info

### F-BRK-I1 — Cert KeyId carries engineer email; visible to compromised devices

`internal/broker/sshcert.go` `keyID` embeds `engineer_sub` and `engineer_email` in the cert's KeyId (URL-escaped). The cert is presented to the device on every SSH connection, so any device's sshd log + a device compromise discloses the engineer's email + subject. This is intentional per DESIGN.md (operators want engineer identity in device-side sshd audit logs), but worth flagging as the operator-side privacy/compliance surface — adding email to a cert that crosses untrusted device boundaries is a deliberate trade-off.

Recommendation: documentation-only. The DESIGN.md cert-fields section already discusses this; consider an explicit "what the device sees about the engineer" subsection.

### F-BRK-I2 — `KeyId` field escaping uses url.PathEscape, not a structured wire format

`internal/broker/sshcert.go` line 438-442: the KeyId is `engineer_sub:<escaped>;engineer_email:<escaped>;jti:<jti>`. `url.PathEscape` correctly escapes `;` and newlines, but the format is bespoke parser-required-on-readback. Operator log queries depending on this shape will silently break if a future contributor changes the separator. The `jti` field is NOT escaped (it's UUIDv7 format with a fixed shape), but a future change to ID-generator shape could introduce a `;` and break the parse-on-readback story.

Recommendation: documentation-only — consider a comment locking the KeyId shape as wire-stable. Alternatively, JSON-encode the map and escape the result (slightly bigger KeyId, simpler parse-on-readback).

### F-BRK-I3 — Audit row size unchecked against CloudWatch 256KB per-event limit

`internal/audit/cloudwatch.go` `Record` marshals the AuditEvent and calls PutLogEvents without a pre-check on byte size. CloudWatch rejects events >256KB and the broker returns a 500 to the engineer. With per-field rune caps from `internal/idp/oidc.go` (subject 256, email 320, 64 groups × 64 chars), plus device_id 256 + user_agent 512 + nonce 256 in handlers.go, the worst-case event is well under 16KB — so this is a defense-in-depth observation, not an exploitable gap.

Recommendation: documentation-only. Optionally add an explicit `if len(encoded) > MaxAuditEventBytes` guard with a `denied_reason: audit_too_large` literal so the failure mode becomes a structured deny rather than a wrapped 500.

### F-BRK-I4 — JWS signing-input domain separation rests on a comment, not a runtime check

`internal/signer/kms.go` `SignTimePayload` accepts arbitrary bytes and signs them with the same KMS key that signs SSH cert TBS. The structural-non-overlap argument (SSH cert TBS starts with a length-prefixed `ssh-ed25519-cert-v01@openssh.com` string; JWS signing-inputs start with `eyJ`) holds, but is a comment-level guarantee. A future caller passing a byte slice that happens to look like an SSH cert TBS prefix would break the domain-separation argument silently.

Recommendation: documentation-only. The current two-method-each-purpose-specific shape is the right discipline; consider adding a runtime `if bytes.HasPrefix(signingInput, []byte("\x00\x00\x00 ssh-ed25519"))` guard inside `SignTimePayload` to reject obvious-cert-shaped inputs.

### F-BRK-I5 — Fixed-window rate limit admits 2*limit burst at window boundaries (per LD-CORR-6)

`internal/ratelimit/dynamodb.go` package comment acknowledges this explicitly: an engineer can fire `limit` requests in the last second of one window plus `limit` requests in the first second of the next. With the default 60/min, an engineer can burst up to 120 requests in ~2 seconds. Accepted per LD-CORR-6 (the design trade-off was fixed-window simplicity over sliding-window correctness).

Recommendation: no change — flagging here for the audit trail. Operators tuning the limit should size for the burst, not the steady-state.

### F-BRK-I6 — Rate-limit budget is per-engineer; multiple stolen credentials bypass the budget

The rate-limit partition key is `engineer_sub`, so an attacker with N stolen access tokens (across N different engineers) gets N*limit budget. Standard credential-compromise model — not a Postern-specific weakness. Operators relying on rate-limit for DoS-class protection should pair it with the LD-66 APIGW JWT authorizer (which can enforce a global token-source rate limit independent of identity).

Recommendation: documentation-only.

### F-BRK-I7 — Timefix rate-limit budget shares its 60/min default with operator mints

`internal/ratelimit/dynamodb.go` uses `request.Mode` as part of the window key, giving operator and timefix separate counters. Both default to 60/min. The timefix recovery scenario is "one engineer trying to fix one device" — 60/min is generous, but an engineer in a tight retry loop against a flaky device could conceivably exhaust it. Probably fine; flagging as something to monitor.

Recommendation: documentation-only — consider documenting recommended timefix limits in the operator-facing config docs.

### F-BRK-I8 — Bearer token forwarded to AVP `IsAuthorizedWithToken`; AVP-side logging visibility

`internal/policy/avp.go` passes the engineer's access token to AVP. AVP's CloudTrail data event captures the auth decision but does NOT log the bearer token (AWS-confirmed behavior). However, operators auditing the broker's outbound traffic (VPC flow logs, egress proxy) would see TLS-encrypted bearer-token traffic to AVP. This is the documented v1 design (AVP needs the token to evaluate Cognito-group claims). Flagging for the AVP-trust threat model.

Recommendation: documentation-only.

### F-BRK-I9 — Trusted-proxies CIDR list is validated at startup but applies globally; no per-route override

`internal/brokerwire/wire.go` `buildClientIPStrategy` applies the parsed trusted-proxies list to every route. If an operator wants `/healthz` to see the LB's IP (for LB health-check counting) but `/ssh/cert` to see the engineer's IP, that's not currently expressible. Probably fine — `/healthz` doesn't audit source IP — but flagging.

Recommendation: documentation-only.

### F-BRK-I10 — Audit emits `EngineerGroups` snapshot at decision time; group-membership changes during the cert validity window don't propagate

`internal/broker/types.go` AuditEvent captures `EngineerGroups` from the IdP claims at decision time. If an engineer is removed from a group after cert issuance but before cert expiry, the cert remains usable — and the audit row reflects the pre-removal group state. This is the documented v1 access model (short-lived certs are the bound on stale-group exposure; the default 12h TTL is the operator's tunable).

Recommendation: documentation-only.

### F-BRK-I11 — Cert Serial collision risk: 64-bit random per LD-M-4

`internal/broker/id.go` `UUIDv7Generator.NewID` generates the cert `Serial` as an independent 64-bit random value. At a rate of 1M certs/day for 30 years (~10^10 certs), birthday-paradox collision probability is ~3*10^-9 — negligible for the SSH KRL revocation model. Re-confirming the calc for the post-timefix-phase audit trail.

Recommendation: no change — LD-M-4's analysis holds.

## Methodology

- Read AGENTS.md + DESIGN.md broker section + architect-log LD-64/65/80/82/83/84/86/90/91 to anchor the locked-decision context.
- Read every broker-pipeline file:
  - `internal/broker/{preamble.go, sshcert.go, issuetimepayload.go, id.go, types.go, errors.go}`
  - `pkg/brokerhandlers/{handlers.go, config.go}`
  - `internal/signer/kms.go`
  - `internal/ratelimit/dynamodb.go`
  - `internal/registry/{dynamodb.go, http.go, serial.go}`
  - `internal/policy/avp.go`
  - `internal/audit/cloudwatch.go`
  - `internal/idp/oidc.go`
  - `internal/brokerwire/wire.go`
  - `cmd/broker/main.go`, `cmd/broker-lambda/main.go`
- Cross-checked the audit invariant against test names in `*_test.go` files (recordAuthorized fail-closed, sign-failure deny, post-sign best-effort).
- Did not audit CLI, on-device binaries, Terraform module, or example configs except where load-bearing for a broker-side finding (starter Cedar in F-BRK-L3).
- Effort: ~60 min. 19 findings (0 HIGH, 3 MEDIUM, 5 LOW, 11 INFO). No code edits.
