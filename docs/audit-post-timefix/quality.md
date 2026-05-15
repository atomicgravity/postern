# Code quality / Go convention audit — post-timefix

## Summary

Production code is in very good shape. `go vet ./...` passes clean. No `time.Sleep` anywhere (production or tests). No `TODO`/`FIXME`/`HACK` markers. No `interface{}` (uses `any`). `errors.Is`/`errors.As` used consistently; no string-matching on `err.Error()`. Go 1.22 method-prefix ServeMux pattern used. Domain errors (`broker.Error`) consistently mediate HTTP-mappable failures. The CV-1 sweep held: zero phase-identifier references in production code (the remaining `LD-XX`/`invariant X`/`TF-A` references all live in `_test.go` files, which is allowed). 17 findings total — most LOW/INFO; a few small MEDIUM cleanups; no HIGH-severity issues.

**Severity counts:** HIGH 0 · MEDIUM 5 · LOW 9 · INFO 3

## High

(none)

## Medium

### F-QUAL-M1: `ModeOperator` and `ModeTimefix` split across two const blocks
**Location**: `internal/broker/types.go:26-28` and `internal/broker/types.go:116-118`
**Finding**: `ModeOperator = "operator"` and `ModeTimefix = "timefix"` are declared in two separate `const ( … )` blocks, both annotated with similar "Mode is the broker-internal label…" prose. The split is a visible scar from incremental TF-A feature work. Other adjacent constant groups (PrincipalType, Event*, DenyReason*, PolicyAction*) are co-located in single blocks.
**Impact**: Cosmetic; reduces local-reasoning ability when a reader is scanning the Mode enumeration.
**Recommendation**: Merge into one `const ( ModeOperator = "operator"; ModeTimefix = "timefix" )` block with a single doc comment.

### F-QUAL-M2: `SSHSigner` is production-exposed but used only by tests
**Location**: `internal/broker/types.go:311-338`
**Finding**: The `SSHSigner` adapter (ssh.Signer → CertSigner with both SignCert and SignTimePayload) is exported from `internal/broker` and referenced exclusively by `_test.go` files across the project (sshcert_test, issuetimepayload_test, timefix_test, cmd/timefix-apply/integration_test). Production wiring uses `*signer.KMSSigner` directly via `brokerwire.BuildDeps`. The type's own doc comment admits "test impl" usage.
**Impact**: Production code carrying an exported type whose only consumers are tests is an anti-pattern: test-only adapters in production packages widen the surface area for unintended use and make the abstraction's real production shape harder to reason about. Per Rule 5, the test helper belongs in test code (e.g., a `testhelpers_test.go` or a `internal/brokertest` package).
**Recommendation**: Move `SSHSigner` to a test-only file (`signer_test_helpers.go` with build tag, or under an `internal/brokertest` helper package, or just inline the adapter into the test files that use it — it's a 10-line wrapper). Same call sites; less production surface.

### F-QUAL-M3: `truncateRunes` duplicated across packages
**Location**: `internal/idp/oidc.go:148-153` and `pkg/brokerhandlers/handlers.go:338-343`
**Finding**: Identical 6-line UTF-8-safe rune-truncate helper exists in two packages. Both have identical bodies and doc comments. The function is generic enough (no domain coupling) that a shared `internal/runestr` (or in `internal/broker`) helper would suffice.
**Impact**: Drift risk — a future bound-policy change must be applied in both places or the broker's input-cap behavior at the wire boundary will diverge from the verifier's IdP-claim caps.
**Recommendation**: Hoist to a shared helper (e.g., `internal/broker.TruncateRunes` since both call sites are broker-domain, or a tiny `internal/runestr` package). Both call sites collapse to one import.

### F-QUAL-M4: `defaultExecSSHTimefix` has 6× repeated cleanup blocks
**Location**: `pkg/cliapp/runtime.go:161-245`
**Finding**: The streaming-ssh exec function has six near-identical 2-line cleanup blocks of the form `_ = stdinPipe.Close(); _ = cmd.Wait()` before each early-return error path. Six repetitions is enough that a future contributor will skip one.
**Impact**: Maintenance liability — one missed cleanup leaks a goroutine waiting on a child process or leaves an open pipe. Real correctness footgun, not just style.
**Recommendation**: Extract a single `cleanup := func(err error) (int, error) { _ = stdinPipe.Close(); _ = cmd.Wait(); return 0, err }` closure declared right after `cmd.Start()`, and use `return cleanup(...)` at each error point. Reduces 12 lines of cleanup to one closure plus six call sites.

### F-QUAL-M5: `NewDynamoDBRateLimiter` is a test-only constructor in production code
**Location**: `internal/ratelimit/dynamodb.go:62-64`
**Finding**: This three-line constructor delegates to `NewDynamoDBRateLimiterWithOptions` with package-default Limit/Window. Its only caller is `dynamodb_test.go:45`. Production wiring goes through `NewDynamoDBRateLimiterFromConfig`. The exported surface advertises a constructor that production never uses.
**Impact**: Wrapping-contract clutter. Wrappers reading the exported API see three constructors and have to decide which is the "right" one. Per AGENTS.md "Don't make the wrapping surface bigger than what real users need."
**Recommendation**: Either remove `NewDynamoDBRateLimiter` (have the test call `NewDynamoDBRateLimiterWithOptions(client, "rate", DefaultLimit, DefaultWindow, SystemClock{})` directly), or rename it so its test-only role is explicit.

## Low

### F-QUAL-L1: `oauthlogin/login.go:184` uses inline `errors.New` instead of a package sentinel
**Location**: `internal/oauthlogin/login.go:184`
**Finding**: `return Result{}, errors.New("id token missing from token exchange response")` — inline error in a file that otherwise defines 11 named sentinels (`ErrOAuthLogin*`) for every other named failure mode. The neighboring branch (`ErrOAuthLoginIDTokenMissingSubject`) follows the sentinel pattern.
**Impact**: Callers that want to match this specific failure with `errors.Is` can't.
**Recommendation**: Promote to `ErrOAuthLoginIDTokenMissing` alongside the existing `ErrOAuthLoginIDTokenMissingSubject`.

### F-QUAL-L2: `oidc.go` uses inline `errors.New` for verify-time domain errors
**Location**: `internal/idp/oidc.go:100, 118, 121, 124, 130`
**Finding**: Five `errors.New("access token …")` / `errors.New("token_use must be access")` strings inside `VerifyAccessToken`. None are sentinels. The broker preamble swallows the error verbatim and remaps to a fixed `broker.Error{401, "invalid access token"}` (preamble.go:127), so callers can't currently distinguish failure classes anyway.
**Impact**: Today: pure log-text variability. Future: if any caller (a test, an observability hook, the audit row) wants to break out "iat in future" vs "audience missing", it can't via `errors.Is`. Cheap to fix proactively.
**Recommendation**: Optional — define `ErrAccessTokenAudience`, `ErrAccessTokenScope`, `ErrAccessTokenIATFuture`, `ErrAccessTokenIATTooOld`, `ErrAccessTokenUse` and wrap them with `fmt.Errorf("%w: …", ErrX, …)` so the log text stays informative and callers gain matchability.

### F-QUAL-L3: `sort.Slice` used where `slices.SortFunc` would be idiomatic
**Location**: `internal/certcache/cache.go:276-278`
**Finding**: `sort.Slice(entries, func(i, j int) bool { return entries[i].Device < entries[j].Device })` predates Go 1.21's `slices` package. The file already imports stdlib `sort` for `sort.Strings`, so this isn't unique; just a generation behind.
**Impact**: Cosmetic; `sort.Slice` still works correctly. Modern senior-Go bar (Rule 4) reaches for `slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Device, b.Device) })`.
**Recommendation**: Optional — `slices.SortFunc` is type-safe and avoids the index-comparator pattern.

### F-QUAL-L4: `truncateRunes` parameter shadows Go 1.21+ builtin `max()`
**Location**: `internal/idp/oidc.go:148`, `pkg/brokerhandlers/handlers.go:338`
**Finding**: Both `truncateRunes(s string, max int)` use `max` as a parameter name, shadowing the language builtin. No use of `max(…)` inside the body, so no actual collision today.
**Impact**: Future-only: any contributor who later wants `max(a, b)` inside the function for some reason gets a confusing "max is not a function" because of the parameter shadow.
**Recommendation**: Rename to `limit` (or `maxRunes`). Trivial.

### F-QUAL-L5: `IssueTimePayload` repeats three identical signer-denial blocks
**Location**: `internal/broker/issuetimepayload.go:216-220, 230-233, 237-241`
**Finding**: After `jose.NewSigner`, `joseSigner.Sign`, and `signed.CompactSerialize` each fails, an identical three-line `signerDenial := timePayloadDenialTemplate(...); signerDenial.DeviceSerial = ...; i.recordTimePayloadDenialFor(...)` block precedes the return. The three failure points are exhaustive (each is the next step in the JWS pipeline).
**Impact**: Mild repetition; a future fourth signer-related failure point would need a fourth copy.
**Recommendation**: Optional — extract a `recordSignerDenial(engineerCtx, deviceCtx, request)` helper. Three call sites collapse to one line each.

### F-QUAL-L6: `internal/brokerwire` depends on `pkg/brokerhandlers`
**Location**: `internal/brokerwire/wire.go:22`
**Finding**: `internal/brokerwire` imports `pkg/brokerhandlers` — inverts the conventional "pkg depends on internal" direction. No cycle because `pkg/brokerhandlers` does NOT import brokerwire (only `internal/broker`). The arrangement works but is unusual.
**Impact**: Architecturally surprising. Wrappers that want to reuse `brokerwire.BuildDeps` discover it's in `internal/` (so they can't import it) and have to re-implement the wiring. That's by design (wrappers compose their own deps) but the package's location in `internal/` could be in `cmd/internal/` or made a sibling of `cmd/broker` to avoid the unusual import direction.
**Recommendation**: Document the rationale in the brokerwire package comment (one sentence: "this lives in internal/ because it's not part of the wrapping contract — wrappers wire their own deps"), or relocate the package under `cmd/broker/internal/brokerwire` (used by both `cmd/broker` and `cmd/broker-lambda`, so a single shared `cmd/` location).

### F-QUAL-L7: `Config.Validate()` is a 86-line linear validation function
**Location**: `pkg/brokerhandlers/config.go:368-454`
**Finding**: Long but flat; each branch is a single `errs = append(errs, …)`. The Registry HTTPAuthMode switch (lines 397-426) is the densest cluster. No nesting; readability is fine.
**Impact**: None today. Adding the next 4-5 fields would push it past the comfortable-skim threshold.
**Recommendation**: Optional — extract `validateRegistry(c.Registry, &errs)`, `validateRateLimit(c.RateLimit, &errs)`, `validateTrustedProxies(c.TrustedProxies, &errs)`. Top-level `Validate()` becomes a 20-line dispatcher. Not urgent.

### F-QUAL-L8: Many constructors named `NewXxxFromConfig` AND `NewXxx` AND `NewXxxWithOptions`
**Location**: `internal/ratelimit/dynamodb.go`, `internal/registry/dynamodb.go`, `internal/audit/cloudwatch.go`, `internal/signer/kms.go`, `internal/policy/avp.go`, `internal/registry/http.go`
**Finding**: Most v1-default-impl packages expose 2-3 constructors: `NewX(client, …)` (test-friendly), `NewXFromConfig(aws.Config, …)` (production), and sometimes `NewXWithOptions(client, …, clock, …)` (full-control). The pattern is consistent and documented in each constructor's doc.
**Impact**: Stable, well-documented surface; the AGENTS.md wrapping contract explicitly supports the `FromConfig` vs raw-client split.
**Recommendation**: No change. Logged here so a future audit doesn't re-flag the multi-constructor pattern — it's intentional.

### F-QUAL-L9: `id.go` lacks a package doc comment but the package has one in `errors.go`
**Location**: `internal/broker/id.go:1-2`
**Finding**: The file opens with `package broker` directly. The broker package's doc comment lives in `errors.go`. Per Go convention this is fine (one package doc per package), but a per-file overview ("File-level comment: this file defines the ID type and UUIDv7 generator") would help readers landing here from godoc cross-references.
**Impact**: None functionally. The user's Rule 2 mentions "File-level (package) comment on every non-trivial Go file" — six broker-package files lack file-level overviews (preamble.go, id.go, errors.go has the package doc, sshcert.go, issuetimepayload.go, types.go).
**Recommendation**: Optional — add a short file-level top-of-file comment to each (e.g., `// id.go — UUIDv7 + 64-bit Serial generation for the cert-mint pipeline.`). Per Rule 4, only add it if it tells the reader something the filename and first function don't.

## Informational

### F-QUAL-I1: CV-1 holds in production code
**Location**: `internal/`, `pkg/`, `cmd/` non-test files
**Finding**: Zero hits for `LD-\d+`, `D-\d+`, `TF-[A-Z]`, `OQ-`, `RO-\d+`, `invariant [A-Z]`, `sub-phase`, `phase \d` across non-test production files. The remaining hits (15 lines, all `_test.go`) are in the kms_test, issuetimepayload_test, sshcert_test, and timefix-apply test files. Tests are out of CV-1 scope per AGENTS.md style guidance.
**Impact**: Positive — the CV-1 sweep at TF-E end held.

### F-QUAL-I2: Idioms cleanly modern
**Location**: project-wide
**Finding**: `errors.Join` for batched validation (NewSSHCertIssuer, Config.Validate, tokenstore.Delete), `errors.Is`/`errors.As` everywhere — no string-matching on `err.Error()`, Go 1.22 method-prefix ServeMux routes (`POST /ssh/cert` etc.), `slices.Contains` used instead of manual `for-range` (3 spots), `any` (not `interface{}`), `cmp` and `slices` packages adopted, `log/slog` (not pkg/log) throughout, `context` cancellation propagated through all I/O calls including the KMS Sign hot path. No `panic` in production code. No `time.Sleep` in production OR test code.
**Impact**: Positive — senior-Go bar (Rule 4) is met.

### F-QUAL-I3: One `_test.go`-equivalent build tag pattern in `cmd/timefix-apply/`
**Location**: `cmd/timefix-apply/capubpath_testbuild.go` + `capubpath_prod.go`
**Finding**: Build-tag-separated production vs test CA-pubkey path resolution. Production hardcodes the install path; test build (separate `_testbuild.go` file gated by a build tag) reads from env. The package doc explains why (env access in production would be a footgun against a hostile sshd misconfiguration). Tests reference `LD-69` in a test comment that names this rule — appropriate for test docs.
**Impact**: Positive pattern; well-documented; the privilege-split rationale lives where the privilege-split lives.

## Methodology

1. Read `AGENTS.md` (Workflow rules, Doc style rules, Things AI agents should NOT do), the user's Go-style memory (5 rules: whitespace; doc-comment coverage; comments-explain-not-defend; senior-Go bar; tests-test-something-real), and `CONTRIBUTING.md`.
2. Built file inventory: 9 283 lines of non-test production Go across `internal/` (16 subpackages), `pkg/` (2 subpackages), `cmd/` (5 binaries).
3. CV-1 check: ripgrep for phase identifiers (`LD-\d+`, `D-\d+`, `TF-[A-Z]`, `OQ-`, `RO-\d+`, `invariant [A-Z]`, `sub-phase`, `phase \d`) — zero hits in non-test files.
4. Idiom checks: `fmt.Errorf` without `%w`-class directives (2 hits, both `%T`-only — acceptable; not an `errors.New` candidate); `strings.Contains(err.Error()…)` patterns (zero); `errors.Is`/`errors.As` adoption (44 hits, well-distributed); `slices.Contains` and `slices.SortFunc` usage; `sort.Slice` legacy patterns; `time.Sleep`, `panic`, `TODO`/`FIXME`/`XXX`/`HACK` (none).
5. Function-length scan: awk-driven per-file pass for `func` blocks > 80 lines (6 real hits; only `IssueSSHCert` and `IssueTimePayload` are arguably long, both intentional pipelines with extensive comment scaffolding).
6. Package-boundary scan: `pkg/` → `internal/` deps (clean; expected direction), `internal/` → `pkg/` deps (one hit: `brokerwire` → `brokerhandlers`; flagged as F-QUAL-L6; no cycle).
7. Doc-comment scan: file-level + package-level doc presence, exported-symbol coverage, and contrast against Rule 4's senior-Go bar ("delete the comment if you can without losing information").
8. Concurrency scan: `sync.\b`, `chan `, `go func`, `go [a-z]` — three hits total, all well-bounded (login callback channel, broker listen goroutine, certcache key mutex). Context propagation checked through `context.Background` usage (all at appropriate boundaries).
9. Constructor surface review for the v1-default-impl packages (ratelimit, registry, audit, signer, policy, idp).
10. `go vet ./...` clean. `staticcheck` not installed locally, not run.
