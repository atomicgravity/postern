# Audit summary — 2026-05-15

## Overview

Five parallel audits ran against the post-tunneling-phase codebase, each from a distinct lens, instructed to read prior audits (`docs/audit-post-sweep/`, `docs/audit-post-timefix/`) and surface only NEW findings. Total: **91 findings** across the five reports.

| Report | Path | Findings | Critical/High |
|---|---|---|---|
| Broad security | [`security.md`](security.md) | 16 (1H/4M/7L/4I) | 1 |
| Deep broker security | [`security-broker-deep.md`](security-broker-deep.md) | 18 (2H/5M/7L/4I) | 2 |
| Code quality / DRY / organization | [`quality.md`](quality.md) | 24 (3H/11M/7L/3I) | 3 |
| Go standards / community / style | [`go-standards.md`](go-standards.md) | 25 (2H/8M/10L/5I) | 2 |
| Library use (hand-rolled vs library) | [`libraries.md`](libraries.md) | 12 (0H/4M/4L/4I-stdlib) | 0 |

No `Critical` findings landed. Eight findings reached `High`; three of those are different views of the same underlying issue (the phase-ID comment regression).

## Headline findings — consolidated

### 1. Audit-context lifetime is engineer-controllable → denial-of-audit DoS (BD-1)

Every audit-emit call inside the broker pipelines forwards `request.Context()` into `CloudWatchAudit.Record` → `PutLogEvents`. A client that TCP-RSTs after triggering any 4xx codepath cancels the context before the deferred audit emit runs; `PutLogEvents` returns `context.Canceled` immediately and the row is dropped. Best-effort denial paths silently lose audit coverage; fail-closed `recordAuthorized` paths yield 500 to the engineer with no audit trace of the pending decision. The LD-65 "exactly one audit row per request" invariant collapses under client-controlled cancellation.

**Fix shape**: detach audit emission from the request context via `context.WithoutCancel(ctx)` + a bounded timeout. ~one-call-site change in `CloudWatchAudit.Record` would handle every emit site at once.

### 2. Scheme-validation asymmetry: CLI `idp.issuer` and broker `registry.http_url` both accept `http://` (S-1, BD-2)

Two distinct paths, same shape:
- **CLI side** (`pkg/cliapp/profile.go`): `Profile.Validate` requires `IDP.Issuer` non-empty but performs no scheme check. The OIDC discovery / JWKs / token-exchange / authz-code flows run over plaintext if the engineer's config (or `postern configure --idp-issuer http://...`) sets http. The broker has `isHTTPSOrLoopback`; the CLI doesn't.
- **Broker side** (`pkg/brokerhandlers/config.go`): `Config.Validate` does not require `https` for `registry.http_url`. With `http_auth_mode: bearer`, the long-lived registry bearer token transmits in plaintext on operator misconfiguration. `idp.issuer` IS gated; the asymmetry is the gap.

**Fix shape**: extract `isHTTPSOrLoopback` to a shared helper; call it from `Profile.Validate` (S-1) and from `Config.Validate` on `registry.http_url` when `http_auth_mode != none` (BD-2).

### 3. Phase-identifier comment regression (CV-1 reopened) (Q-3, G-1, G-2)

Three agents flagged this independently. The post-sweep and post-timefix audits closed CV-1 at zero references in production comments; the tunneling phase landed 12 new `LD-N` references and 4 `spec D-N` references across `internal/brokerwire`, `internal/broker`, `pkg/brokerhandlers`, `pkg/cliapp`, and `internal/tunneling`. One reference (`pkg/cliapp/tunnel.go:33` "scp once TN-D lands") is also stale. Per the user's Go-style memory rule 3, phase / LD / RO / sub-phase identifiers must not appear in production comments — they belong to the paper trail in git log and `docs/`.

**Fix shape**: mechanical sweep. Rephrase each comment to describe the architectural choice plainly without naming the LD/TN identifier. The discipline reset is the load-bearing part.

### 4. Three-pipeline duplication compounded by tunneling phase (Q-1, Q-2, Q-4, BD-15)

The SRP issuer split in TN-A produced three pipelines (`SSHCertIssuer`, `TimePayloadIssuer`, `TunnelIssuer`), each of which now carries:
- A near-identical 70-LoC denial-emit helper quartet (Q-1 / BD-15) — ~120 LoC of parallel code
- A near-identical ~50-line broker-side HTTP handler (Q-4) — including a copy-paste bug (Q-5) where `handleTimePayload`'s 501 message says "ssh cert issuer is not configured"
- A near-identical ~50-line `brokerclient.Client` request method (Q-2)

The duplication compounds the "every request → one audit row" invariant: it now lives in three copies that must stay in sync, and a future fourth endpoint would force a fourth copy. The shape Q-1 needs already exists in-house (`internal/broker/preamble.go`'s `PipelineDeps`-on-method-receiver pattern, called out by Q-23 as exemplary).

**Fix shape**: lift a single denial-emit helper parameterized by `Event` + `PrincipalType` + slog-prefix (Q-1); extract `postJSON[Req, Resp any]` generic on `brokerclient.Client` (Q-2); extract a generic `handleIssueEndpoint` builder in `pkg/brokerhandlers` (Q-4); Q-5 closes structurally as a side-effect of Q-4.

### 5. CLI-side ssh / scp parallel implementation pairs (Q-8, Q-12, Q-14)

The CLI added `--user`, `--tunnel`, and the unified user-resolution chain across ssh and scp in the same session. Result:
- `runTunneledSSH` / `runTunneledSCP` near-identical (~20 lines each, only suffix substitution)
- `resolveSSHCommandUser` / `resolveSCPCommandUser` near-identical (only `skipDashL bool` varies)
- `defaultExecSSH` / `defaultExecSCP` byte-identical except for the error-prefix string
- `newSSHTestRuntime` / `newSCPTestRuntime` ~35-line near-clones
- Per-subcommand flag-name constants (`sshMaxLifetimeFlag` / `scpMaxLifetimeFlag` / `tunnelOpenMaxLifetimeFlag`) all carry identical strings

**Fix shape**: consolidate `resolveSSHCommandUser` + `resolveSCPCommandUser` (Q-8.a); extract shared cert/identity-options prefix; merge `defaultExecSSH`/`defaultExecSCP` to a parameterized helper; parameterize the test-runtime fixture; hoist canonical flag-name constants to package scope.

## Cross-cutting themes

Some findings appeared in multiple agents' reports from different angles — these are the highest-confidence items:

| Theme | Agents flagging | Files involved |
|---|---|---|
| **`slices.Contains` over hand-rolled `containsString`** | quality (Q-10), go-standards (G-4), libraries (L-2) | `internal/securetunnel/loops.go:314` |
| **Phase-identifier leaks in production comments** | quality (Q-3), go-standards (G-1, G-2) | 16+ sites across internal + pkg/cliapp |
| **Scheme validation gaps for OIDC issuer / registry URL** | security (S-1), broker-deep (BD-2) | `pkg/cliapp/profile.go`, `pkg/brokerhandlers/config.go` |
| **Three-pipeline duplication after SRP split** | quality (Q-1/Q-2/Q-4), broker-deep (BD-15) | `internal/broker/{sshcert,issuetimepayload,tunnel}.go`, `pkg/brokerhandlers/handlers.go`, `internal/brokerclient/client.go` |
| **`sort.Slice` / `sort.Strings` over `slices.Sort*`** (carry-over) | quality (Q-17), go-standards (G-12) | 4 sites |
| **`TruncateRunes` `max` shadows Go-1.21 builtin** (carry-over) | quality (Q-16), go-standards (G-11) | `internal/broker/runes.go:12` |
| **Include-presence warning text duplicated** | quality (Q-6, Q-13, Q-20) | `pkg/cliapp/{mint,tunnel_open,addhost}.go` |

## Recommended action order

A pragmatic sequence — mechanical sweeps first (low risk, high signal), then the highest-leverage refactors, then the security hardening that's deferrable:

### Tier 1 — mechanical, do now (~1–2 hours)
1. **CV-1 sweep** (Q-3 / G-1 / G-2): strip 16 phase-ID references from production comments. Mechanical search-and-replace; the discipline reset is the value.
2. **`slices.Contains` swap** (Q-10 / G-4 / L-2): delete `containsString` in `securetunnel/loops.go`, replace the one call site.
3. **Q-5 copy-paste bug**: fix `handleTimePayload`'s 501 message to say "time-payload issuer is not configured" — one word change.
4. **Q-16 / G-11 `max` rename**: `TruncateRunes(s string, max int)` → `limit int`. One symbol.

### Tier 2 — security hardening, do this week
5. **Scheme validation** (S-1 + BD-2): extract `isHTTPSOrLoopback`; gate `Profile.Validate` on `idp.issuer` and `Config.Validate` on `registry.http_url` for bearer mode. Closes both findings together.
6. **Audit-context detach** (BD-1): `context.WithoutCancel` + bounded timeout inside `CloudWatchAudit.Record`. Closes the denial-of-audit primitive.
7. **GitHub Actions SHA pinning** (S-4): mechanical pass on `.github/workflows/*.yml`, plus Dependabot config addition.
8. **Region shape-validation** (S-3): one-regex check on `tunnelResponse.Region` before WebSocket URL interpolation.

### Tier 3 — refactor, do when nearby work brings it into scope
9. **Three-pipeline denial-emit helper** (Q-1 / BD-15): the precedent (Q-23: `preamble.go`'s SRP pattern) is in-house.
10. **`postJSON[Req, Resp any]` on `brokerclient`** (Q-2).
11. **`handleIssueEndpoint` generic handler builder** (Q-4) — closes Q-5 structurally.
12. **CLI ssh/scp consolidation** (Q-8 / Q-12 / Q-14 / Q-9): unify the resolve-user functions; share argv prefix; merge exec funcs; parameterize test fixture; hoist flag-name constants.
13. **`atomicfile` defer-cleanup refactor** (G-7 / G-19): two exported functions sharing 16 LoC of body; private helper would halve maintenance.

### Tier 4 — defer / discuss
14. **Tunnel-mode host-key trust** (S-2): documented design choice. Decide whether the residual trust on AWS IoT thingName routing is acceptable, or invest in SSH host certs / per-tunnel `UserKnownHostsFile`. Surface in `docs/team-handoff.md` so the choice is visible.
15. **Empty-`sub` OIDC tokens / sub-truncation collision** (BD-3 / BD-5): reject (rather than truncate) over-length subs; reject empty sub at the verifier; bounded threat from cooperative-IdP assumption but worth tightening.
16. **JWKs-fetch DoS pre-rate-limit** (BD-4): either add coarse per-source-IP rate limit or formalize the LD-66 APIGW JWT-authorizer dependency in docs.
17. **DynamoDB `attributevalue.UnmarshalMap`** (L-1): partial swap for named fields; keep the explicit drop-non-scalar switch for the open-ended attributes map.

## What was checked and found clean

Both security agents and the go-standards agent included clean-area lists; consolidating:

**Crypto and auth invariants intact**:
- KMS Ed25519 algorithm pinning at construction + per-sign call
- OIDC alg allowlist excludes HS\* and `none`
- JWS alg=EdDSA pinning at both signing and verification
- Access tokens (never ID tokens) at broker; `SkipClientIDCheck` is intentional
- PKCE applied to both authorize URL and token exchange
- OAuth state 32 bytes from `crypto/rand`
- Audit emit order (`*_authorized` → `*_issued`/`*_denied`) correctly implemented across all three pipelines
- Fail-closed `recordAuthorized` contract before any Sign/AWS call
- Rate-limit before all external calls except IdP-side TokenVerify (engineer identity is the partition key)
- Source access token never logged (invariant T): zero slog references found

**Pipeline hardening intact**:
- `MaxBytesReader` body cap on every endpoint
- `DisallowUnknownFields` JSON decode on every POST
- Trusted-proxies CIDR validation at config load; vetted `realclientip-go` strategy
- Serial regex validates Registry response + fail-closed on empty serial
- Conditional UpdateItem rate-limit is correctly atomic
- AWS IoT `LimitExceededException` correctly routes to 429
- WebSocket subprotocol mismatch rejected; per-conn read limit set before any frames
- WebSocket frame size-prefix cap before allocation

**File / OS / supply chain**:
- No `InsecureSkipVerify` anywhere
- Atomic file writer: chmod-then-rename ordering correct; `os.Link` for create-or-fail
- Tokenstore: 0600 files, 0700 dir, atomic writes; keychain backend separates access/refresh tokens
- On-device privilege split (`timefix-set-clock`) has single-integer-arg surface; range-checks independently of verifier
- On-device verifier: go-jose alg pin, typ check post-parse, signature before claim inspection, JWS read cap
- Sigstore wiring in `.goreleaser.yaml` correct; verification recipe accurate

**Go fundamentals**:
- `go vet ./...` clean; no `panic` in non-test code; no `time.Sleep` anywhere
- `errors.Is`/`As`/`%w` used at 151+ sites with no string-matching anti-patterns
- `errors.Join` adopted at validator sites
- `any` (not `interface{}`); modern `log/slog` exclusively
- Concurrency primitives tightly scoped; `goleak` discipline in tests
- `pkg/` → `internal/` import direction clean (modulo the known intentional `brokerwire` reverse-import)

**Library choices**:
- JWS pipeline → `go-jose/v4` on both sides (LD-90/LD-91 closure verified)
- OIDC → single-dep `coreos/go-oidc/v3`
- WebSocket → actively-maintained `coder/websocket`
- V3 protobuf wire framing via `google.golang.org/protobuf` + stdlib `encoding/binary`
- SSH cert + key parse/marshal exclusively `golang.org/x/crypto/ssh`
- YAML-only config (single dep on `gopkg.in/yaml.v3`); no INI/TOML/JSON reintroductions
- No DI framework; constructor wiring in `main.go` / `brokerwire.BuildDeps`

## Reports index

- [`security.md`](security.md) — Broad-scope security (CLI, on-device, source proxy, supply chain, config)
- [`security-broker-deep.md`](security-broker-deep.md) — Broker pipeline + abstractions
- [`quality.md`](quality.md) — DRY, organization, naming, file shape
- [`go-standards.md`](go-standards.md) — Idiomatic Go, modern stdlib, comment hygiene
- [`libraries.md`](libraries.md) — Hand-rolled vs library; stdlib-over-third-party
