# Broker Security Deep-Dive Audit — 2026-05-15

Date: 2026-05-15
Scope: broker HTTP surface + cert/time-payload/tunnel pipelines + OIDC verifier + AVP policy + KMS signer + CloudWatch audit + DynamoDB/HTTP registry + DynamoDB rate-limit + AWS IoT tunneling + entrypoints.
Lens: pipeline correctness, authn/authz layering, race conditions, audit-coverage invariants, cryptographic correctness, secret handling, response-shape leaks, input validation, DoS resilience.

This pass focuses on **new** findings only. Items closed or restated in `docs/audit-post-sweep/broker-security.md` (panic-recovery middleware, `IDGenerator.NewID` audit bypass, `/ssh/tunnel` stub — that one is now closed by the real tunnel pipeline in this codebase, `--print-config` plaintext bearer leak, classification of IdP-side failures, bearer-parser leading-whitespace, `/healthz` 503 leak, JWS `aud` shape, OpaqueSigner algorithm gating, UUIDv7 timestamp visibility) are not re-stated. Methodology section at end names what was investigated and found clean.

| Severity | Count |
|---------|-------|
| High     | 2     |
| Medium   | 5     |
| Low      | 7     |
| Informational | 4 |

## High

### BD-1: Client-disconnect during audit emission silently bypasses LD-65 "exactly one audit row per request" invariant

**Location**: `internal/broker/sshcert.go:249`, `internal/broker/issuetimepayload.go:232`, `internal/broker/tunnel.go:246`, `internal/broker/sshcert.go:307-322,336-357`, `internal/broker/issuetimepayload.go:315-353`, `internal/broker/tunnel.go:322-356`, `internal/audit/cloudwatch.go:80`
**Severity**: High
**Invariant or threat**: LD-65 "every request → exactly one audit outcome"; denial-of-audit DoS

**Finding**: Every audit emission inside the pipeline (both the pre-Sign fail-closed `recordAuthorized` and every best-effort `record*Denial` / `RecordHandlerDenial`) uses the incoming `request.Context()` — and `CloudWatchAudit.Record` forwards that context to `PutLogEvents`. A client that disconnects (or aborts the TCP connection) after a `400`/`401`/`403`/`429` codepath is reached cancels the request context before the handler's deferred audit emission runs; PutLogEvents returns `context.Canceled` immediately, the audit sink returns an error, the error is logged-and-ignored on best-effort paths, and **no audit row is written**. An attacker who fires `N` malformed requests and TCP-RSTs each one yields `N` 4xx responses but `0` audit rows — a directly exploitable denial-of-audit primitive on every endpoint.

The same channel bites `recordAuthorized` (fail-closed pre-Sign): a connection canceled between `resolveDevice` success and the audit emit yields `nil` audit row AND a `500` to the engineer with no record of what the broker was about to do. That's the textbook fail-closed-but-no-trace path.

**Recommendation**: Decouple audit emission from request lifetime. Either (a) call `Record` on a detached context (`context.WithoutCancel(ctx)` in Go 1.21+ combined with a bounded timeout), or (b) split audit emission into a buffered fire-and-forget channel with bounded queue + per-emission timeout backed by a long-lived broker-process context. Option (a) is the smaller change; option (b) is the right v2 architecture if audit-pipeline backpressure becomes a concern. Either way, the audit context's lifetime must not be the client's to control.

### BD-2: Registry bearer token transmitted over plaintext when `http_url` is `http://`

**Location**: `internal/registry/http.go:154`, `pkg/brokerhandlers/config.go:408-502` (no Validate scheme check), `internal/registry/http.go:53`
**Severity**: High
**Invariant or threat**: secret handling (HTTP registry bearer token); operator misconfiguration → in-flight credential theft

**Finding**: `NewHTTPRegistryWithClient` accepts both `http://` and `https://` URLs. `Config.Validate` does not require `https` for `registry.http_url`. When `http_auth_mode: bearer` is set, `bearerAuthClient.Do` unconditionally sets `Authorization: Bearer <token>` on every request — including over plaintext HTTP. An operator who configures `http_url: http://internal-registry.corp/lookup` plus `http_auth_mode: bearer` will leak the long-lived registry bearer token to anyone on the path (corporate WiFi, ARP-poisoning attacker on the LAN, transparent proxy operator, etc.). The token is high-value: it grants read access to the device inventory, which the broker uses to authorize SSH cert issuance.

Note the asymmetry: `idp.issuer` IS gated to https-or-loopback in `Validate()` (line 416) precisely because the broker fetches JWKs over that URL. The same reasoning applies to bearer auth on `registry.http_url`, but the equivalent guard is missing.

**Recommendation**: In `Config.Validate()`, require `https` for `registry.http_url` when `http_auth_mode != none`. Loopback `http://` should be allowed for local dev (mirroring `isHTTPSOrLoopback`'s carve-out). The SigV4 auth mode is somewhat self-defending (SigV4 signatures don't leak credentials), but bearer tokens are bearer tokens — anyone who sees one can replay it.

## Medium

### BD-3: OIDC verifier accepts access tokens with empty `sub`; downstream rate-limit denial mis-classifies the failure

**Location**: `internal/idp/oidc.go:107-153`, `internal/ratelimit/dynamodb.go:99-101`, `internal/broker/preamble.go:201-213`
**Severity**: Medium
**Invariant or threat**: identity-resolution correctness; audit-classification stability

**Finding**: `OIDCVerifier.VerifyAccessToken` does not reject claims with empty `Subject`. RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) requires `sub`, but the broker's verifier never enforces this. A misconfigured or malicious IdP can issue an access token with `aud` matching the broker, valid signature, valid `iat`, and no `sub` claim. Verification passes; `verifyEngineer` returns `engineerContext{Engineer: {Subject: ""}}`. The rate limiter then sees `engineerSub == ""` and returns `Error{StatusCode: 401, Message: "engineer subject is required"}` — but classified by `preamble.go` as `DenyReasonRateLimitExceeded` (because any non-nil error from `RateLimiter.Allow` produces that reason). The audit row carries `engineer_sub: ""`, `denied_reason: rate_limit_exceeded`, and no identity context — operators can't trace these requests to an IdP-side bug.

This also means an attacker token with empty `sub` consumes no rate-limit budget (the conditional UpdateItem is never issued), so a steady stream of such tokens evades the per-engineer budget gate. The downstream `Policy.Allow` is never reached because `verifyEngineer` returns the rate-limit denial first.

**Recommendation**: In `VerifyAccessToken`, reject empty `claims.Subject` post-verification with `Error{StatusCode: 401, Message: "invalid access token"}`. The deny will then route through `DenyReasonInvalidAccessToken` (correct classification) and audit will record the same `engineer_sub:""` but with the right deny reason and no rate-limit-side-effect ambiguity.

### BD-4: `verifyEngineer` runs RateLimit AFTER TokenVerify; an unauthenticated token-shape attacker drives unbounded JWKs fetches

**Location**: `internal/broker/preamble.go:187-213`
**Severity**: Medium
**Invariant or threat**: DoS resilience; rate-limit purpose

**Finding**: `verifyEngineer` runs TokenVerify *first*, then RateLimit. TokenVerify performs JWKs fetch / cache lookup against the IdP via go-oidc — an outbound HTTP call when the cache misses (and go-oidc's cache TTL is bounded; under cache-busting kid rotation by an attacker, every request can miss). RateLimit gates only successful token-verify calls; anonymous attackers spraying tokens with novel `kid` values force JWKs re-fetches per request, amplified at the IdP. No rate-limit budget is consumed on this path because rate-limit happens after.

The architectural choice (rate-limit per engineer) means there's nothing to rate-limit pre-identification; that's accepted. But the JWKs-amplification vector is not mitigated by anything in the broker. The LD-66 APIGW JWT-authorizer pre-filter is the documented out-of-band defense, but the broker layer should not assume it.

**Recommendation**: Add a coarse per-source-IP rate limit BEFORE TokenVerify on `/ssh/cert`, `/ssh/time-payload`, `/ssh/tunnel`. Same `RateLimiter` interface can be reused with a different partition key (source IP from the trusted-proxies-aware strategy) and a deliberately-loose budget (e.g., 600/min/IP) so legitimate operators behind shared NAT aren't impacted. Alternatively, document the JWKs-fetch DoS surface as something the LB / APIGW authorizer must mitigate.

### BD-5: `OIDCVerifier.VerifyAccessToken` runs `iat`-future-skew + max-age checks AFTER aud/scope checks but BEFORE returning truncated claims; a malicious IdP can craft truncation-collision

**Location**: `internal/idp/oidc.go:147-152`, `internal/broker/runes.go:12-17`
**Severity**: Medium
**Invariant or threat**: identity-impersonation via post-truncation collision

**Finding**: `VerifyAccessToken` returns `Subject: broker.TruncateRunes(claims.Subject, 256)`. `TruncateRunes` chops at 256 runes, dropping the rest. The truncated value flows into:
- The SSH cert KeyId (visible to compromised devices)
- The rate-limit partition key (engineer_sub)
- The audit row's `engineer_sub` field
- AVP's `IsAuthorizedWithToken` access-token forward (AVP sees the original, not truncated)

A malicious IdP (or a compromised IdP-side claim mapping) could issue tokens with `sub` like `victim-engineer-sub-<260-byte-suffix>` such that the first 256 runes match an existing engineer's truncated identity. AVP authorization uses the access token's full `sub` (no Postern-side truncation forwarded), so the AVP check would correctly evaluate against the attacker's full sub — but the rate-limit budget collides (counts against the victim), the audit row collides (operators see the wrong engineer), and the SSH cert KeyId attributes the action to the victim.

Most IdPs limit `sub` length (Cognito 255 chars, Auth0 100-ish, Okta 100-ish), so the practical exposure depends on the IdP. But there's no broker-side guard — the verifier accepts 4KB-long `sub` values up to the JWT size limit.

**Recommendation**: Reject (rather than truncate) `sub` claims longer than the cap. `claims.Subject` length > 256 runes → `Error{StatusCode: 401, Message: "invalid access token"}`. Truncation of engineer-controlled inputs (UserAgent, DeviceID) is appropriate; truncation of identity claims is not. Same treatment for `email` (currently truncated to 320 — within RFC 5321 max but worth pinning).

### BD-6: AVP `IsAuthorizedWithToken` is called with `request.AccessToken` but AVP does not enforce the broker's `audience` / `required_scope` check; broker's audience match is the ONLY defense against cross-app token misuse

**Location**: `internal/policy/avp.go:82-95`, `internal/idp/oidc.go:130-135`
**Severity**: Medium
**Invariant or threat**: cross-app token misuse (the "never accept ID tokens at broker" sibling threat)

**Finding**: The broker's audience check happens in `OIDCVerifier.VerifyAccessToken` (lines 130-135). After verification, `AccessToken` flows into `PolicyRequest.AccessToken` and is forwarded verbatim to AVP `IsAuthorizedWithToken`. AVP validates the token against the configured AVP identity source (issuer + client-app-id), but the broker's *required-scope* check is NOT mirrored on the AVP side. The AVP identity source enforces issuer + signature + (optionally) client-app-id; it does NOT enforce the broker's `RequiredScope` configuration.

Implication: if an operator configures `audience: postern-broker` AND `required_scope: postern:cert` to defend against a sibling app sharing the same `aud`, the broker enforces the scope, but AVP's authorization happens against the same token — and AVP's policy can be tricked into Allow if the operator's Cedar policies reference a claim the broker would have rejected. In practice this is mostly belt-and-braces (the broker rejects the request before AVP sees it), but a future code change that moves the scope check or skips it for a specific mode opens the door.

Stronger: AVP does NOT validate `iat` future-skew or `iatMaxAge` — those are broker-side. So a stale access token (older than 24h) is rejected by the broker but would be accepted by AVP if forwarded directly. This is fine today, but it locks in the dependency: the broker's verifier MUST run before AVP forwarding, every time.

**Recommendation**: Document the dependency explicitly (a code comment on `Allow` noting that AVP forwarding presumes the broker's verifier has already gated audience/scope/iat). Stretch: add a defensive re-check of `audience` and required-scope inside AVP `Allow` against the raw token (parse the JWT segments; cheap and offline). This would close the door against a future refactor that bypasses the verifier.

### BD-7: `mapTunnelingError` collapses all non-LimitExceeded AWS errors to 503 with generic message; operators get no distinguishing signal at the wire level

**Location**: `internal/broker/tunnel.go:439-445`, `internal/tunneling/awsiot.go:105-111`
**Severity**: Medium
**Invariant or threat**: error-classification correctness; DoS resilience (a transient AWS auth failure vs a permanent misconfig look the same to retrying CLIs)

**Finding**: `classifyError` recognizes only `LimitExceededException`. Every other AWS SDK error (AccessDeniedException, ResourceNotFoundException, ThrottlingException, ServiceUnavailableException, ValidationException, region-mismatch, network failure) routes through `TunnelingErrorUnknown` → `tunneling_unavailable` → 503. The CLI sees a generic `tunneling backend unavailable` message and retries. A misconfigured IAM role producing `AccessDeniedException` is permanent — retries are wasteful and amplify the broker's outbound IAM-deny traffic against AWS. A `ThrottlingException` is retriable but with backoff. The broker can't signal the difference.

Worse for audit: every non-LimitExceeded error gets `denied_reason: tunneling_unavailable`. Operators querying CloudWatch for "permanently broken tunnels" can't distinguish IAM misconfig from transient AWS-IoT outage without joining against the slog line (line 270) — which is fine for operators but provides no signal to the CLI for retry-vs-fail-fast decisions.

**Recommendation**: Add `TunnelingErrorAccessDenied` and `TunnelingErrorThrottling` kinds, route AccessDeniedException to 403 + `tunneling_access_denied` (engineer's CLI shows "broker not authorized to AWS IoT; contact operator"), and route ThrottlingException to 503 with `Retry-After`-style hint via a separate deny reason. The classifier list stays small; the value is in the operator's ability to alert on "permanent" vs "transient" tunnel failures.

## Low

### BD-8: AVP Cedar `context` keys overlap silently with engineer-influenced policy attributes; reserved-key protection covers baseline but not future additions

**Location**: `internal/policy/avp.go:105-133`
**Severity**: Low
**Invariant or threat**: policy-context integrity

**Finding**: `contextMap` reserves four baseline keys (source_ip, user_agent, request_id, timestamp) against shadowing by `request.Context` entries (line 125: `if _, reserved := attributes[trimmedKey]; reserved { continue }`). Today the only `PolicyContext`-using pipeline is the tunnel-open path, which injects `requested_max_lifetime_minutes` from server-side state — no engineer-controlled input flows into `PolicyContext`. So the reserved-key check is currently belt-and-braces.

The risk shape is forward-looking: a future code change that injects an engineer-influenced value into `PolicyContext` (e.g., a request-shape field for a new endpoint) without first checking against the baseline-reserved list would let an engineer-controlled `source_ip: "<attacker IP>"` shadow the broker's resolved value. The reserve check above closes this for the existing four keys but doesn't enforce a "engineer-controlled values must not appear in `Context`" invariant at the type level.

**Recommendation**: Document at the `PolicyContext` struct field (in `internal/broker/types.go`) that only server-derived values may flow through this map. Optionally, split `PolicyContext` into `ServerContext` (trusted) and `EngineerContext` (untrusted) so the AVP impl can route them to distinct Cedar paths if needed. Today this is purely a doc/discipline finding.

### BD-9: Tunnel `requested_max_lifetime_minutes` flows into Cedar as int64 even when DefaultTunnelLifetimeMinutes is substituted; operators can't distinguish "engineer asked" from "broker defaulted"

**Location**: `internal/broker/tunnel.go:189-213`
**Severity**: Low
**Invariant or threat**: policy-evaluation completeness; operator policy authoring

**Finding**: Line 211-213 injects `requested_max_lifetime_minutes` into Cedar context with the *resolved* value — `requestedLifetime` if non-zero, else `i.defaultMaxLifetime`. The code comment (lines 203-210) explains this is deliberate (so omitting `--max-lifetime` doesn't bypass `when context.requested_max_lifetime_minutes <= N` Cedar predicates). Correct.

But Cedar policies can't distinguish "engineer requested 480 minutes" from "engineer omitted the flag and broker defaulted to 480 minutes" — the value lands identically. An operator who wants a tighter Cedar policy ("engineers must explicitly request lifetimes; deny implicit-default opens") can't author it.

**Recommendation**: Add a second Cedar context key `lifetime_explicitly_requested: bool` reflecting `request.MaxLifetimeMinutes > 0`. Two keys allow operators to express both "<= ceiling" and "must be explicit" policies. Wire change is one map entry; AVP-side it's an opt-in.

### BD-10: `HTTPRegistry.ResolveDevice` body decode reads up to 64KB but does NOT enforce `Content-Type: application/json`

**Location**: `internal/registry/http.go:180-201`
**Severity**: Low
**Invariant or threat**: registry response trust boundary

**Finding**: The registry-HTTP client sends `Accept: application/json` (line 180) but does not validate the response's `Content-Type` header before JSON-decoding the body. A misconfigured or compromised registry endpoint that returns `Content-Type: text/html` plus a JSON-shaped HTML payload would parse fine and could feed a malformed `Serial` (caught by `validateSerial`) — or worse, an `Attributes` map that confuses operator Cedar policies expecting registry-specific shapes.

The realistic threat is low (registry is operator-trusted and the validateSerial gate closes the cert-principal injection), but the gap means the broker accepts any successful-status response, regardless of shape semantics.

**Recommendation**: Reject 200 responses whose `Content-Type` doesn't start with `application/json` (or `application/*+json` for vendor variants). One-liner check after the status-code gates.

### BD-11: `SigV4AuthClient.Do` retrieves credentials per request; an IAM credential-provider outage produces a 502 to engineers via wrapped registry-side 5xx

**Location**: `internal/registry/http.go:84-99`, `internal/brokerwire/wire.go:184-192`
**Severity**: Low
**Invariant or threat**: deny-reason classification under AWS control-plane outages

**Finding**: `sigV4AuthClient.Do` calls `provider.Retrieve` (line 91) per request. The AWS SDK provider chain caches IAM role credentials, but cache-miss scenarios (initial fetch, expired creds, IMDS hiccup) hit the underlying STS or IMDS. A transient IMDS failure during cache refresh produces `Retrieve` error → registry call returns wrapped error → `HTTPRegistry.ResolveDevice` returns the wrapped error → `resolveDevice` runs `registryDenyReason(err)` and gets `DenyReasonRegistryUnavailable` (correct), but the engineer-facing error is wrapped through `writeIssueError`'s non-domain path, surfacing as `ssh cert issuer failed` (500, generic).

Two operational consequences: (1) the audit row records `registry_unavailable` for what is actually an IAM-side outage; (2) the operator's CloudWatch alerting on `registry_unavailable` fires for both legitimate registry outages and IAM credential refresh problems, masking the root cause.

**Recommendation**: Add a `DenyReasonIAMCredentialUnavailable` literal and route `provider.Retrieve` errors to it via a typed wrapper at the SigV4 client layer. Same shape as the `TunnelingErrorClassifier` pattern; the registry-side error class flows back to the broker as a classified deny reason.

### BD-12: `OIDCVerifier.now` is unexported and unsubstitutable for unit tests; production code uses `time.Now` literally

**Location**: `internal/idp/oidc.go:65,99,138`
**Severity**: Low
**Invariant or threat**: testability; iat skew test coverage

**Finding**: The `now` field on `OIDCVerifier` is initialized to `time.Now` at construction (line 99) and consulted on every `Verify` call (line 138). It's unexported, so tests in other packages can't substitute a fixed clock. The package's own test file may set it via package-internal access — but a wrapper testing its own OIDC integration end-to-end can't reach in. This results in flaky tests around `iatFutureSkew` and `iatMaxAge` boundaries: tests have to use real `time.Now` against constructed tokens, leaving a ~few-second window in which a slow test environment could produce a false-positive `iat is in the future` rejection.

**Recommendation**: Either export a `NowFunc func() time.Time` field on `OIDCVerifierConfig` (with `time.Now` default), or accept a `Clock broker.Clock` parameter for symmetry with the rate-limit + signer test patterns. Either change is mechanical.

### BD-13: SSHCert response includes `ca_pubkey_fingerprint` even on every issuance; this is benign but the broker has no caching primitive for clients

**Location**: `pkg/brokerhandlers/handlers.go:229`, `internal/broker/sshcert.go:281-284`
**Severity**: Low
**Invariant or threat**: bandwidth/latency efficiency; response-shape consistency

**Finding**: Every `/ssh/cert` 200 response carries `ca_pubkey_fingerprint` (64-byte SHA256 of the CA pubkey). The fingerprint is constant across the broker's lifetime (KMS key doesn't rotate in v1). CLIs re-fetch and re-validate it on every cert mint. This is correct for the CLI's "trust pinning" check, but the broker has no `ETag` / `If-None-Match` semantics to let CLIs skip the fingerprint validation step on the hot path. Not a security gap per se; flagging because the response shape would benefit from a CA-rotation-event signal that doesn't exist today (and won't until a real v2 CA-rotation story arrives).

**Recommendation**: No change. Documenting as a v2 consideration for when CA rotation lands.

### BD-14: `validateSerial` regex allows leading `.` or `-`, which could trip operator-side filename-globbing or shell-expansion in audit consumers

**Location**: `internal/registry/serial.go:18`
**Severity**: Low
**Invariant or threat**: log-consumer-side injection (defense-in-depth)

**Finding**: The serial regex `^[A-Za-z0-9_.-]{1,64}$` accepts strings starting with `.` (hidden-file pattern in Unix) or `-` (option-shell-flag pattern). A serial like `-rf` or `./../etc/passwd` would pass `validateSerial`. The broker's own consumption (cert principal, audit row JSON) is safe. But a downstream operator log-processor that pipes serials through a shell unquoted (`echo $SERIAL`) would parse `-rf` as a flag. The principal-side risk (smuggling `device-.something-operator`) doesn't break SSH cert matching because OpenSSH's `AuthorizedPrincipalsFile` doesn't perform glob expansion on principal names.

**Recommendation**: Tighten the regex to require an alphanumeric first character: `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`. This blocks the `--rf` / `.hidden` patterns while remaining permissive for real hardware serials.

## Informational

### BD-15: Three pipelines duplicate the audit deny template + record helper trio

**Location**: `internal/broker/sshcert.go:291-371`, `internal/broker/issuetimepayload.go:295-368`, `internal/broker/tunnel.go:303-370`
**Severity**: Informational
**Invariant or threat**: maintainability of the audit-coverage invariant

**Finding**: Each of `SSHCertIssuer`, `TimePayloadIssuer`, `TunnelIssuer` defines its own near-identical `*denialTemplate` + `record*DenialFor` + `Record*HandlerDenial` + `record*Denial` quartet. ~70 LoC of structural duplication per pipeline. A future contributor adding a fourth endpoint will copy-paste — and a future contributor changing the deny-row shape (adding a field, normalizing user agent across endpoints, etc.) must remember to update all three. Drift between the three has bitten Postern before (LD-65 ↔ LD-84 wording in the audit-post-sweep findings).

**Recommendation**: Doc-only flag. A refactor that lifts the deny-row recording into a generic helper on `PipelineDeps` (parameterized on the per-endpoint Event constant + PrincipalType + DenyReason) would shrink the three pipelines by ~50 lines each and turn drift into a compile-time error. Not a security finding; the existing duplication is correct today.

### BD-16: Per-endpoint rate-limit buckets share the DynamoDB table but key on `mode:<bucket>`; a noisy timefix engineer doesn't burn operator-cert budget

**Location**: `internal/ratelimit/dynamodb.go:104-110`
**Severity**: Informational
**Invariant or threat**: rate-limit fairness across endpoints

**Finding**: The composite key is `(engineer_sub, "<mode>:<window>")`. An engineer hitting `/ssh/time-payload` 60×/min doesn't deplete their `/ssh/cert` budget. This matches DESIGN intent. Flagging because the inverse is also true: a malicious-shaped client (or a buggy CLI) firing 3 modes × 60/min = 180 requests/minute against the broker per engineer is the per-engineer ceiling. Operators sizing the broker's downstream load should size for `(N engineers × 3 modes × limit)` not `(N engineers × limit)`.

**Recommendation**: Documentation only — consider noting this in the rate-limit operator guidance.

### BD-17: `OpenTunnel` emits `tunnel_authorized` carrying `ValidBefore` overloaded with the resolved-TTL-derived ExpiresAt; field-overloading harms CloudWatch Insights query authoring

**Location**: `internal/broker/tunnel.go:231-245`
**Severity**: Informational
**Invariant or threat**: audit-schema clarity

**Finding**: Line 242 sets `ValidBefore: engineerCtx.Now.Add(time.Duration(resolvedLifetime) * time.Minute).Unix()`. The `ValidBefore` field was named for SSH cert validity windows; tunnel issuance doesn't mint a cert and has no "valid before" semantic. The reuse means operator Insights queries selecting `tunnel_authorized` rows by `valid_before` need to know "this is actually the tunnel ExpiresAt" — operator-facing schema confusion that would be cheap to avoid.

The code comment at lines 226-229 acknowledges this ("overloaded so operators get one timestamp-bound field per audit row vocabulary").

**Recommendation**: Documentation only — add a dedicated `TunnelExpiresAt int64 omitempty` to `AuditEvent` and stop overloading `ValidBefore` for tunnel rows. Audit-schema growth is cheap; the cost is one field on a struct.

### BD-18: `EngineerClaims.Raw` is populated but never consumed by any production path

**Location**: `internal/idp/oidc.go:122-125,151`, `internal/broker/types.go:200-205`
**Severity**: Informational
**Invariant or threat**: dead-field hygiene

**Finding**: `OIDCVerifier.VerifyAccessToken` decodes the full claim set into `EngineerClaims.Raw` (a `map[string]any`). No production consumer reads it (`grep -rn "\.Raw\b"` in `internal/` returns zero hits). The field exists for future Policy impls to read non-standard claims, but the v1 AVPPolicy uses the access token's claims via AVP's own parse (not the broker's Raw map). The Raw map is allocated + decoded per request and discarded.

**Recommendation**: Doc-only. Either delete the field (simplest) or comment-note it as a public extension hook reserved for wrapper Policy impls. Today it's pure cost on the hot path with no consumer.

## Areas investigated and found clean

- **Audit emit order** (`*_authorized` before `*_issued`/`*_denied`): correctly implemented across all three pipelines via `recordAuthorized` fail-closed before any Sign/AWS call.
- **`recordAuthorized` fail-closed contract**: the three pipelines all return early on `recordAuthorized` error before signing, matching LD-65/LD-84.
- **Access tokens vs ID tokens**: the broker's verifier is wired as an OIDC access-token verifier (with `token_use == access` defense for Cognito) and `SkipClientIDCheck` disables go-oidc's ID-token-style `aud == client_id` gate. ID tokens are not accepted as broker bearer auth.
- **KMS Ed25519 algorithm pinning**: `signer.NewKMSSigner` rejects non-Ed25519 keys at construction; `SignTimePayload` and `SignCert` both pass `SigningAlgorithmSpecEd25519Sha512`.
- **JWS `alg=EdDSA` pinning on signing**: `jose.NewSigner` is called with `jose.EdDSA` and the OpaqueSigner's `Algs()` returns only `EdDSA`. (The OpaqueSigner-internal mismatch case is the prior-pass F-BRK2-M4.)
- **OIDC supported-signing-algs allowlist**: HS* and `none` excluded; mainstream asymmetric algs covered.
- **AVP audience-via-IsAuthorizedWithToken**: the broker validates audience/scope BEFORE forwarding to AVP (BD-6 above is a defensive recommendation, not a missing invariant).
- **Rate-limit before any non-IdP external call**: rate-limit runs before Registry, Policy, KMS — only TokenVerify (which needs the engineer identity for the rate-limit key) runs before it.
- **Source access token never logged**: `grep -rn "SourceAccessToken"` shows no slog references outside the response struct itself; the structured-log lines on tunnel-failure paths log thing_name + jti, not the token.
- **MaxBytesReader on every endpoint**: `withBodyLimit` wraps the mux globally; the unimplemented stubs share the cap.
- **`DisallowUnknownFields` JSON decoding on all three POST endpoints**.
- **Trusted-proxies CIDR validation** at config-load time; runtime IP derivation uses `realclientip-go`'s vetted strategy.
- **Serial regex validation on Registry response** + post-resolve fail-closed if empty serial.
- **Conditional UpdateItem rate-limit** is correctly atomic (no read-then-write race).
- **AWS IoT OpenTunnel error classification**: LimitExceededException correctly routes to 429; the BD-7 finding is about widening the classifier, not fixing a bug.
- **Cert TTL operator path**: validation rejects non-positive durations; the default 12h matches DESIGN.md.
- **Lambda + long-running broker share `internal/brokerwire`**: no drift between the two entrypoints' dep wiring.

## Methodology

- Read AGENTS.md, prior-pass `docs/audit-post-sweep/broker-security.md` and `docs/audit-post-timefix/broker-security.md` end to end.
- Read every broker-pipeline file: `pkg/brokerhandlers/{handlers.go,config.go}`, `internal/broker/{preamble.go,sshcert.go,issuetimepayload.go,tunnel.go,types.go,errors.go,id.go,runes.go}`, `internal/idp/oidc.go`, `internal/policy/avp.go`, `internal/signer/kms.go`, `internal/audit/cloudwatch.go`, `internal/registry/{dynamodb.go,http.go,serial.go}`, `internal/ratelimit/dynamodb.go`, `internal/tunneling/awsiot.go`, `internal/brokerwire/wire.go`, `cmd/broker/main.go`, `cmd/broker-lambda/main.go`.
- Specifically traced the audit-emission lifecycle across cancellation boundaries (BD-1) by following `request.Context()` from handler entry to `CloudWatchAudit.Record` → `PutLogEvents`.
- Traced bearer-token data flow from HTTP header through `OIDCVerifier.VerifyAccessToken` to `AVPPolicy.Allow` to verify no logging or persistence (clean) and to identify BD-6 (defensive recommendation).
- Traced tunnel `SourceAccessToken` through the response path to confirm no slog references (clean).
- Did NOT audit: CLI, on-device timefix binaries, Terraform module deeply, the `internal/securetunnel/` source-proxy (deferred to tunneling-phase audit), example configs.
- Effort: ~75 min. 18 findings total (2 HIGH, 5 MEDIUM, 7 LOW, 4 INFO). No code edits.
