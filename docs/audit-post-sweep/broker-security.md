# Broker Security Deep-Dive Audit — Post-Sweep

Date: 2026-05-14
Scope: broker pipeline + HTTP surface + rate-limit + registry + AVP policy + audit sink. Second pass after the `8eb0efd` audit-findings sweep.
Lens: security only (correctness/quality/docs out of scope).
Inputs: AGENTS.md, DESIGN.md (broker pipeline section), architect-log LD-64/65/83/84/90/91 (with the post-sweep restated wording), prior-pass `docs/audit-post-timefix/broker-security.md`.
Out of scope: CLI, on-device timefix binaries (other auditors' lenses).

## Summary

The `8eb0efd` sweep landed the highest-leverage items (Cedar starter for `MintTimefixCert`, OIDC `SupportedSigningAlgs` pin against malicious-IdP HS256 confusion, hand-rolled UUIDv7 replaced with `google/uuid.NewV7()`, hand-rolled JWT parse on the CLI replaced with `go-jose`, LD-65 wording tightened to reference LD-84). Those land as a clear net-positive.

Of the three prior MEDIUMs, **none are closed** in the sweep: F-BRK-M1 (panic-recovery middleware) and F-BRK-M2 (`IDGenerator.NewID` failure bypasses audit) remain identical; F-BRK-M3 (`/ssh/tunnel` unauthenticated stub) remains identical. These are architectural follow-ups the sweep deliberately deferred — restated below as F-BRK2-M1/M2/M3.

Two new MEDIUM-ish surface items surfaced on re-read: F-BRK2-M4 (the `timePayloadOpaqueSigner.Algs()` advertises `EdDSA` but go-jose never gates `SigningKey.Algorithm` against `Algs()` at signer construction — a future caller passing a different `SigningKey.Algorithm` would silently mis-sign) — flagged LOW given the single call site; and F-BRK2-L5 (the JWS `aud` claim is a JSON string, not the RFC 7519-canonical array — both sides agree, but a future verifier-side library upgrade defaulting to array-decode would silently break) — flagged LOW.

The previously-flagged LOW findings have mixed closure: F-BRK-L3 (starter Cedar policy) is CLOSED by F-OQ-H1 in the sweep; F-BRK-L1 (`--print-config` leaks `registry.http_bearer_token` plaintext), F-BRK-L2 (`verifyEngineer` error classification), F-BRK-L4 (Bearer-token parser leniency), and F-BRK-L5 (`/healthz` 503 message reveals misconfig) remain identical and are restated.

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 3     |
| LOW      | 6     |
| INFO     | 10    |

## Prior-pass closure status

| Prior finding | Severity | Status | Notes |
|---|---|---|---|
| F-BRK-M1 (no panic-recovery middleware) | MEDIUM | OPEN | Restated as F-BRK2-M1. Sweep did not touch `pkg/brokerhandlers/handlers.go`'s mux composition. |
| F-BRK-M2 (`IDGenerator.NewID` failure bypasses audit) | MEDIUM | OPEN | Restated as F-BRK2-M2. `id.go` moved to `google/uuid.NewV7()` (F-HR-M1) but the preamble error path remains audit-skipping. |
| F-BRK-M3 (`/ssh/tunnel` unauthenticated 501 stub, no method restriction, auditless) | MEDIUM | OPEN | Restated as F-BRK2-M3. `mux.HandleFunc("/ssh/tunnel", unimplementedHandler)` unchanged. |
| F-BRK-L1 (`--print-config` outputs `registry.http_bearer_token` plaintext) | LOW | OPEN | `pkg/brokerhandlers/config.go` `PrintResolvedConfig` still serializes the full Config. Restated as F-BRK2-L1. |
| F-BRK-L2 (`verifyEngineer` classifies all IdP errors as `invalid_access_token`) | LOW | OPEN | `internal/broker/preamble.go` `verifyEngineer` unchanged. Restated as F-BRK2-L2. |
| F-BRK-L3 (starter Cedar permits `MintOperatorCert` but not `MintTimefixCert`) | LOW | CLOSED | `terraform/postern-broker/cedar/starter.cedar` now permits both actions in a single `permit` (F-OQ-H1 in the sweep). |
| F-BRK-L4 (Bearer-token parser accepts multi-space) | LOW | PARTIALLY OPEN | Sweep tightened scheme matching to `EqualFold` on the literal `"bearer "` prefix, but `strings.TrimSpace(header[len(scheme):])` still accepts a tab or extra whitespace between the single ASCII space and the token. Restated as F-BRK2-L3. |
| F-BRK-L5 (`/healthz` 503 message reveals misconfig) | LOW | OPEN | `pkg/brokerhandlers/handlers.go` line 132 unchanged. Restated as F-BRK2-L4. |
| F-BRK-I1..I11 | INFO | OPEN | All prior INFO items remain valid observations; not re-enumerated except where the post-sweep code shape changed something. |

## High

(none)

## Medium

### F-BRK2-M1 — No panic-recovery middleware (restated from F-BRK-M1)

Unchanged. `pkg/brokerhandlers/handlers.go` `New` mounts handlers on `http.NewServeMux()` and wraps only with `withBodyLimit`. No `defer recover()` at the boundary. A panic anywhere inside `IssueSSHCert` or `IssueTimePayload` after the preambles have started bypasses every `recordDenial` / `recordCertDenial` / `recordTimePayloadDenialFor` call site, breaking the LD-65 / LD-84 "exactly one audit outcome per request" invariant.

Practical-risk note unchanged: low in production today, but a single future contributor adding `nilPtr.Field`, a map-of-nil read, or a `,ok`-less type assertion silently breaks the invariant. The signer paths in particular call into go-jose and KMS, both of which CAN panic on invariants-violation in adversarial-input scenarios.

Recommendation: wrap the mux (or each handler) with recovery middleware that, on panic, emits a best-effort `*_denied` audit row with `denied_reason: internal_error` before letting net/http's default panic-to-500 path run. Source IP + JTI minimum; engineer identity may be unknown if the panic was pre-TokenVerify. Add a stable `DenyReasonInternalError` literal.

### F-BRK2-M2 — `IDGenerator.NewID` failure inside `verifyEngineer` bypasses the audit invariant (restated from F-BRK-M2)

Unchanged in behavior even though `id.go` was rewritten in the sweep (F-HR-M1 — `google/uuid.NewV7()` replaces the hand-roll). `internal/broker/preamble.go` `verifyEngineer` lines 109-112 still propagate a non-nil error from `i.deps.IDs.NewID(now)` without emitting any audit row. The cert-mint and time-payload endpoints both propagate the error to a 500 with NO audit emission on this path (sshcert.go:156-158, issuetimepayload.go:130-132 wrap the error and return).

The sweep's change to `uuid.NewV7()` does NOT increase the probability of this failure — `uuid.NewV7()` reads `crypto/rand` internally and can still fail in entropy-starved environments (FIPS-mode boot races, container without `/dev/urandom`, fork-after-init readers). The independent 8-byte `Serial` `io.ReadFull` on the same `rand.Reader` is a second failure point on the same code path.

Recommendation unchanged: emit a best-effort `*_denied` row with `denied_reason: internal_error` (same literal as F-BRK2-M1) carrying only source IP + user agent before returning. JTI omitted or stamped with a sentinel.

### F-BRK2-M3 — `/ssh/tunnel` unauthenticated 501 stub, auditless, accepts any verb (restated from F-BRK-M3)

Unchanged. `pkg/brokerhandlers/handlers.go` line 107: `mux.HandleFunc("/ssh/tunnel", unimplementedHandler)`. Unlike the `POST /ssh/cert` and `POST /ssh/time-payload` routes which now use Go 1.22 method-routed pattern syntax, `/ssh/tunnel` accepts every HTTP verb and short-circuits to a static 501 without bearer parse, audit emission, or rate-limit.

The tunneling phase is in flight (spec at `docs/phases/tunneling/spec.md`); the stub will be replaced. Until then the broker has an anonymous endpoint that:

- Violates the "every broker request → one audit outcome" invariant for `/ssh/tunnel` traffic. Operators correlating across audit + access-log won't see tunnel probes in audit.
- Lets anonymous attackers spam Lambda cold-starts / synthetic-cost amplification.
- Accepts every verb without operator signaling (a `GET /ssh/tunnel` probe and a `DELETE /ssh/tunnel` probe both look the same in operator logs).

Recommendation unchanged: restrict to `POST /ssh/tunnel`, require a bearer token (parse + `RecordHandlerDenial` on missing), emit a best-effort `tunnel_denied` audit row with `denied_reason: unimplemented`. Two new constants: `EventTunnelDenied`, `DenyReasonUnimplemented`. The tunneling phase will replace this with the real implementation; until then closing the audit / auth gaps takes ~20 LoC.

## Low

### F-BRK2-L1 — `--print-config` outputs `registry.http_bearer_token` in plaintext (restated from F-BRK-L1)

Unchanged. `pkg/brokerhandlers/config.go` `PrintResolvedConfig` serializes the full `Config` including `Registry.HTTPBearerToken`. Field comment warns operators against YAML literals but the `--print-config` flag prints the resolved value (file OR env) verbatim to stdout — operator terminal history, CI logs, container console logs all capture it.

Recommendation unchanged: replace `HTTPBearerToken` with `"<redacted; len=NN, source=POSTERN_REGISTRY_HTTP_BEARER_TOKEN>"` in `PrintResolvedConfig` whenever non-empty.

### F-BRK2-L2 — `verifyEngineer` classifies every IdP-side error as `invalid_access_token` (restated from F-BRK-L2)

Unchanged. `internal/broker/preamble.go` lines 121-128 produce `DenyReasonInvalidAccessToken` for any `TokenVerifier.VerifyAccessToken` error — including network failures during JWKs refresh, context deadline exceeded mid-discovery, OIDC-discovery cache miss + IdP timeout. An IdP outage is operationally distinct from a malformed/expired token.

Recommendation unchanged: introduce `DenyReasonIDPUnavailable`; have the verifier return a typed error the preamble can `errors.As` on.

### F-BRK2-L3 — Bearer-token parser still accepts a tab or multi-space between scheme and token (restated from F-BRK-L4, partially mitigated)

`pkg/brokerhandlers/handlers.go` `bearerToken` was tightened to require a single literal-`"bearer "` prefix (case-insensitive via `strings.EqualFold(header[:len(scheme)], scheme)`) and to reject Unicode whitespace. The header-prefix matching is now strict-ASCII.

However, the body of the function still calls `strings.TrimSpace(header[len(scheme):])`, which strips leading **Unicode** whitespace (tab, vertical tab, etc.) before returning the token. So `Authorization: Bearer\t<token>` is accepted (scheme literal-byte match fails — single space required), but `Authorization: Bearer <whitespace><token>` for `<whitespace>` = additional space or tab is accepted because the leading space matches `len(scheme)` and TrimSpace eats the rest.

Bypass surface against a strict WAF: same as the prior pass. Not a header-smuggling primitive against Go itself.

Recommendation: replace the `strings.TrimSpace` of the suffix with a leading-whitespace rejection — accept only `Bearer <token>` where `<token>` has no leading whitespace. Trailing whitespace is a separate question (RFC 6750 ABNF says no trailing whitespace either; current behavior trims it which is permissive but not exploitable).

### F-BRK2-L4 — `/healthz` 503 message reveals broker misconfiguration to unauthenticated callers (restated from F-BRK-L5)

Unchanged. `pkg/brokerhandlers/handlers.go` line 132: `writeError(response, http.StatusServiceUnavailable, "ssh cert issuer is not configured")`. The HealthChecker-failed arm two lines down returns generic `"unhealthy"`; the issuer-nil arm leaks the specific reason to anonymous probers.

Recommendation unchanged: return `"unhealthy"` on both arms; the actual reason already lands in operational logs via slog at wiring time.

### F-BRK2-L5 — JWS `aud` claim is a JSON string, not the RFC 7519-canonical string-or-array

`internal/broker/issuetimepayload.go` line 84: `timePayloadClaims.Aud` is `string`. On serialize, `json.Marshal` emits `"aud":"device-<serial>-timefix"` (a JSON string). RFC 7519 §4.1.3 says `aud` is "an array of case-sensitive strings, [...] when there is one principal it MAY be a single case-sensitive string." So both sides are spec-compliant today.

The on-device verifier (cmd/timefix-apply/verify.go line 71) also decodes `Aud` as `string`, so the two sides agree.

Risk: a future go-jose or stdlib library upgrade on the verifier side that defaults to array-decode for `aud` (per RFC 7519 §4.1.3 preferring array shape) would silently break verifier parsing. The library-on-both-sides commitment in LD-90/LD-91 mitigates this — both sides use go-jose, which does not interpret `aud` itself (the claim semantics check is the verifier's own struct decode).

Recommendation: documentation-only. Consider a comment in `timePayloadClaims` locking the `aud` string-only shape as wire-stable, mirroring the existing comment on payload field ordering. Alternative: change to `[]string` of length 1 on both sides for forward-compat with stricter array-only RFC 7519 readers; but that's a wire-format change requiring on-device coordination.

### F-BRK2-L6 — `timePayloadOpaqueSigner.Algs()` advertises `EdDSA` but go-jose does not gate `SigningKey.Algorithm` against the OpaqueSigner's `Algs()` at signer construction time

`internal/broker/issuetimepayload.go` lines 212-215: `jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: timePayloadOpaqueSigner{...}}, ...)`. The signer's `Algs()` method returns `[]jose.SignatureAlgorithm{jose.EdDSA}` per lines 357-359 — that's the OpaqueSigner's contract with go-jose advertising which algorithms it can sign with.

go-jose's `NewSigner` uses `SigningKey.Algorithm` as the protected-header `alg` value; it does NOT cross-check that the algorithm is in the OpaqueSigner's `Algs()` list. If a future contributor (or a wrapper composing the broker pipeline at a more granular layer) passes `SigningKey.Algorithm: jose.RS256` to `NewSigner` with this `timePayloadOpaqueSigner`, go-jose will:

- emit the JWS header with `alg=RS256`
- call `SignPayload(payload, jose.RS256)` on the OpaqueSigner — which IGNORES the algorithm argument and calls `s.signer.SignTimePayload(s.ctx, payload)`, which under the v1 default impl returns an Ed25519 KMS signature
- produce a wire-bogus JWS (header claims RS256, signature is Ed25519). The on-device verifier rejects it (LD-91's `[]jose.SignatureAlgorithm{jose.EdDSA}` accepted-algs list — RS256 doesn't match). Fail-closed at verify, so this is a correctness/availability concern only, not a forgery-acceptance concern.

Today there is one production caller in `IssueTimePayload` that uses the right algorithm, so the bug is latent. The single-call-site discipline holds today. Flagging because the OpaqueSigner type is package-public to `internal/broker` and the wrapping surface includes anything in `internal/broker` that wrappers compose past (the `CertSigner` interface in particular).

Recommendation: assert at the top of `SignPayload` that `alg == jose.EdDSA` (the `Algs()` invariant), returning an error if mismatched. Two lines; closes the type-domain gap between `Algs()` advertised and `SignPayload` actually willing to honor.

## Info

### F-BRK2-I1 — UUIDv7 timestamp portion leaks broker clock to engineers (post-sweep)

The sweep replaced the hand-rolled UUIDv7 with `google/uuid.NewV7()`. UUIDv7 by spec carries the broker's `time.Now()` in its first 48 bits at millisecond resolution. The UUID is surfaced to engineers as `jti` in the JWS `time_payload` response and as the SSH cert KeyId's `jti` segment.

Implication: an engineer who receives a freshly-minted cert or time-payload learns the broker's wall-clock to millisecond precision at issuance. That's not a secret today (engineers can call `/healthz` to detect liveness and time the round-trip), and the broker's clock isn't a security boundary against the engineer (the engineer authenticates to the broker, not the reverse). Flagging as a documented property of the UUIDv7 choice — operators tightening their threat model later (e.g., a forensic-investigation scenario where they want to obscure broker decision time) should know this.

Recommendation: documentation-only. UUIDv7 is the right choice for sortable, collision-resistant IDs; the timestamp visibility is a deliberate property.

### F-BRK2-I2 — `google/uuid.NewV7()` uses package-internal `crypto/rand`; the `Rand io.Reader` field on `UUIDv7Generator` only feeds Serial

`internal/broker/id.go` lines 33-44: `g.Rand` (if set) feeds only the independent 64-bit `Serial` read; `uuid.NewV7()` uses `google/uuid`'s package-internal random source (`crypto/rand` by default; configurable globally via `uuid.SetRand`). Tests injecting a deterministic `g.Rand` for `Serial` cannot make the `UUID` deterministic without also reaching into `uuid.SetRand` globally. Not a security gap — flagging because the godoc-comment talks about `Rand` "may be nil; the zero value uses crypto/rand directly" without distinguishing the two random sources.

Recommendation: documentation-only — tighten the godoc to note that `Rand` is consulted only for Serial; the UUIDv7 random portion uses go-uuid's internal source.

### F-BRK2-I3 — `OIDCVerifier.SupportedSigningAlgs` allowlist is the right defense, but excludes ES256K (secp256k1)

`internal/idp/oidc.go` lines 91-94: the allowlist is `[RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, EdDSA]`. That's the standard asymmetric set; correctly excludes HS256/HS384/HS512 (the F-SEC-M1 fix) and `alg=none`. ES256K (secp256k1) is also excluded, which is correct for v1 (only emitted by specific IdPs, not in the v1 supported-IdP set) but flagging in case an operator wires Cognito-with-custom-secp256k1 or a Web3-flavored IdP later.

Recommendation: documentation-only. Adding ES256K is straightforward if a real operator brings an IdP that needs it; resisting the speculative addition is correct.

### F-BRK2-I4 — `validateSerial` regex `[A-Za-z0-9_.-]{1,64}` excludes `:` and `/` — appropriate for SSH principal embedding

`internal/registry/serial.go` line 18: the pattern intentionally rejects characters that could trip log-injection, change shell semantics, or smuggle a different SSH principal past the device-side `AuthorizedPrincipalsFile` match. The dash + dot + underscore + alphanumerics combination is sound. Flagging because the regex is the load-bearing defense against a compromised Registry returning a serial like `valid-serial-operator\ndevice-other-serial-operator` to inject a second principal into the cert — but `\n` is excluded, so the path is closed.

Recommendation: no change. Worth pairing with a doc note in DESIGN.md or the registry package comment that the regex is a security boundary, not a UX nicety.

### F-BRK2-I5 — JWS `iss = "postern.broker"` is constant, not per-operator

`internal/broker/issuetimepayload.go` line 42: `timePayloadIssuer = "postern.broker"`. The on-device verifier checks `iss` matches the expected literal (cmd/timefix-apply/verify.go). Constant across all Postern deployments, so an attacker who compromises operator A's broker can sign a time-payload that operator B's devices would accept by `iss` — but cannot by `aud` (which is `device-<serial>-timefix`, scoped to a specific device the attacker would need to know the serial of), and cannot by signature (different CA private keys per operator).

The defense is the per-device CA pubkey installed at packaging time. `iss` is not a security boundary in this design — it's an audit field. Flagging because operators reading the JWS in CloudWatch may interpret `iss` as a per-deployment identifier; it isn't.

Recommendation: documentation-only — consider a comment naming `iss` as a constant audit label, not a deployment discriminator.

### F-BRK2-I6 — Fixed-window rate limit at LD-CORR-6 (re-confirmed)

Unchanged from prior pass. Documented trade-off; flagging for the audit trail.

### F-BRK2-I7 — Per-engineer rate-limit budget, not per-source-IP (re-confirmed)

Unchanged from prior pass. N stolen credentials → N*limit budget; documented threat model.

### F-BRK2-I8 — Bearer token forwarded to AVP `IsAuthorizedWithToken`; AVP-side handling

Unchanged from prior pass.

### F-BRK2-I9 — `KeyId` field escape uses `url.PathEscape`, not a structured wire format

Unchanged from prior pass. The `jti` segment is now stable-formatted via `google/uuid.NewV7().String()` (canonical lowercase hex with hyphens — no `;` to inject), which strengthens the parse-on-readback story for the JTI portion. Engineer subject and email are still `url.PathEscape`'d. Flagging because the `KeyId` format remains bespoke parser-required-on-readback for operator-side log queries.

### F-BRK2-I10 — Cert Serial collision risk per LD-M-4 (re-confirmed)

Unchanged from prior pass. 64-bit random independent of UUID; LD-M-4 analysis holds.

## Methodology

- Read AGENTS.md, DESIGN.md broker section, architect-log LD-64/65/73/82/83/84/90/91 (with the post-sweep restated wording), and the prior-pass `docs/audit-post-timefix/broker-security.md` end to end.
- Re-read every broker-pipeline file with the sweep's changes in mind:
  - `internal/broker/{preamble.go, sshcert.go, issuetimepayload.go, id.go, types.go, errors.go, runes.go, testsigner.go}`
  - `pkg/brokerhandlers/{handlers.go, config.go}`
  - `internal/signer/kms.go`
  - `internal/ratelimit/dynamodb.go`
  - `internal/registry/{dynamodb.go, http.go, serial.go}`
  - `internal/policy/avp.go`
  - `internal/audit/cloudwatch.go`
  - `internal/idp/oidc.go`
  - `internal/brokerwire/wire.go`
  - `cmd/broker/main.go`, `cmd/broker-lambda/main.go`
- Diffed the `8eb0efd` sweep against each finding in the prior pass to determine closure status.
- Verified the LD-65 invariant wording change (the restated reference to LD-84) is present in the architect log; cross-checked the audit-flow against the recordAuthorized fail-closed contract at both endpoints.
- Did not audit CLI, on-device binaries, Terraform module deeply (only spot-checked `starter.cedar` for F-BRK-L3 closure), or example configs.
- Effort: ~60 min. 19 findings total (0 HIGH, 3 MEDIUM, 6 LOW, 10 INFO). No code edits.
