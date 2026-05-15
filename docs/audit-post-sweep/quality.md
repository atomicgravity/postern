# Code quality / Go convention audit — post-sweep (pass #2)

## Summary

Second pass after the `8eb0efd` sweep. Production code remains in very good
shape: `go vet ./...` clean, full `go test ./...` green, no `time.Sleep` or
`panic` in production, idiomatic Go 1.24 throughout (`errors.Is/As`, `errors.Join`,
`slices.Contains`, Go 1.22 method-prefix `ServeMux`, `log/slog`, `any` not
`interface{}`). The five prior MEDIUMs (F-QUAL-M1..M5) are substantively
closed; one HIGH-impact regression introduced by the sweep needs attention —
a `F-SEC-M1` finding-ID reference leaked into a production comment, breaking
the CV-1 sweep that had been clean for the prior pass. The new files
(`runes.go`, `testsigner.go`, `id.go`, `runtime.go` cleanup closure,
`token.go` go-jose use) are otherwise idiomatic and well-commented. A handful
of carry-over LOWs from pass #1 remain unaddressed (the sweep was scoped to
MEDIUMs); they remain valid but low-priority.

**Severity counts:** HIGH 1 · MEDIUM 2 · LOW 7 · INFO 3 — total 13.

## Prior-pass closure status (F-QUAL-M1..M5)

| ID  | Status            | Notes                                                                                                                          |
|-----|-------------------|--------------------------------------------------------------------------------------------------------------------------------|
| M1  | Closed            | `ModeOperator`/`ModeTimefix` now share one `const` block in `internal/broker/types.go:25-28`.                                  |
| M2  | Closed (effective)| `SSHSigner` moved to `internal/broker/testsigner.go` with a comment flagging it as a cross-package test helper. Still exported because cross-package tests in `pkg/cliapp/` and `cmd/timefix-apply/` import it; the file's purpose is now grep-discoverable. The pure-test-package alternative wasn't taken, but the surface is now self-documenting. |
| M3  | Closed            | `TruncateRunes` now lives in `internal/broker/runes.go`; both prior call sites (`internal/idp/oidc.go`, `pkg/brokerhandlers/handlers.go`) import the shared helper. No drift risk left.                                                                                                                                                          |
| M4  | Mostly closed     | `defaultExecSSHTimefix` now has a `cleanup` closure used by five early-return paths. **Partial regression** at `pkg/cliapp/runtime.go:233-236`: the post-`io.WriteString` close-stdin path bypasses the closure and re-inlines `_ = cmd.Wait()`. See F-QUAL2-L1.                                                                                                                            |
| M5  | Closed            | `NewDynamoDBRateLimiter` unexported to `newDynamoDBRateLimiter`. Only caller is `dynamodb_test.go:45`. Wrapping surface no longer carries the test-only default-applying constructor.                                                                                                                                                                                                        |

## High

### F-QUAL2-H1: `F-SEC-M1` finding-ID leaked into production code comment (CV-1 regression)
**Location**: `internal/oauthlogin/token.go:174` — `// symmetric algs the broker would reject under F-SEC-M1's`
**Finding**: The CV-1 sweep at the end of the timefix pass left production code with zero references to phase identifiers / locked-decision IDs / observation IDs / finding-IDs. The `8eb0efd` sweep introduced one: the `accessTokenExpiry` doc comment names `F-SEC-M1` (the finding ID for the OIDC verifier's `SupportedSigningAlgs` pin). Per the user's Rule 3 ("comments NEVER reference phases / LD-X / RO-X / sub-phase numbers"), finding-IDs are exactly the kind of process metadata that belongs in `git log` and `docs/`, not in code.
**Impact**: HIGH for sweep-discipline regression — this is the first such reference in production code since CV-1 closed. Low for any reader (the comment is still informative if you ignore the abbreviation). The fix is trivial and the precedent matters more than the words.
**Recommendation**: Rephrase to drop the `F-SEC-M1` reference. The comment already describes the constraint ("the broker's asymmetric-only pin") so the finding-ID adds nothing. Example: `// the list is intentionally permissive (including symmetric algs the broker's asymmetric-only pin would reject)`.

## Medium

### F-QUAL2-M1: `defaultExecSSHTimefix` cleanup closure has one stray inline copy
**Location**: `pkg/cliapp/runtime.go:233-236`
**Finding**: M4's sweep introduced a `cleanup` closure for the post-`cmd.Start()` error paths, and five early-returns use it cleanly. The sixth path (`stdinPipe.Close()` failing after the JWS write succeeded) bypasses the closure and re-inlines `_ = cmd.Wait()` directly:
```go
if err := stdinPipe.Close(); err != nil {
    _ = cmd.Wait()
    return 0, fmt.Errorf("execSSHTimefix: close stdin: %w", err)
}
```
**Impact**: The closure exists to centralize the "close stdin, wait for child" idiom; one site bypassing it defeats the centralization. A future maintainer reading the closure may assume it covers every path. The path is reachable in practice (stdinPipe.Close returns an error if the OS pipe is in an unexpected state).
**Recommendation**: Use the existing closure: `if err := stdinPipe.Close(); err != nil { cleanup(); return 0, fmt.Errorf(...) }`. Calling `cleanup()` discards its return — but every other early-return path also discards it, so the pattern is consistent.

### F-QUAL2-M2: `accessTokenExpiry` accepts every JWT signature algorithm including `none`-adjacent symmetric algs
**Location**: `internal/oauthlogin/token.go:180-198`
**Finding**: `jwt.ParseSigned` is called with an explicit `[]jose.SignatureAlgorithm` listing 13 algorithms (HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512, EdDSA). The doc comment defends the permissiveness ("the broker is the authoritative verifier; this is just `exp` extraction"). The reasoning is correct in isolation, but: (a) the CLI also calls `accessTokenExpiry` against tokens it just received from refresh, before the broker sees them again, so the CLI does momentarily trust whatever it parses to decide "is this token even worth sending?", and (b) the broker's `SupportedSigningAlgs` (F-SEC-M1) intentionally excludes symmetric algs precisely to defend against malicious IdPs — letting the CLI's expiry-parser silently accept them creates a small asymmetry between the CLI's and broker's views of "acceptable token shape." (c) The CLI's `accessTokenFresh` returning `false` on parse failure means a symmetric-alg token gets treated as "stale, refresh me" — not "reject this," which is acceptable defense in depth but worth pinning.
**Impact**: Cryptographic-shape consistency rather than direct vulnerability — the broker remains the authoritative verifier and will reject symmetric-alg tokens regardless. The asymmetry just makes the CLI's expiry-parsing surface wider than the broker's verification surface, which is the kind of "two different lists in two places" maintenance liability the F-SEC-M1 pin specifically argues against.
**Recommendation**: Drop the HS256/384/512 entries from the list to mirror the broker's asymmetric-only stance. The CLI's expiry parse still works for every realistic IdP (which all issue asymmetric tokens for access tokens). If a future IdP truly does issue HS-signed access tokens, the broker will reject them anyway, so the CLI rejecting them at parse time is consistent.

## Low

### F-QUAL2-L1: Carry-over — `truncateRunes` parameter name shadows Go 1.21+ `max` builtin
**Location**: `internal/broker/runes.go:12`
**Finding**: Pass #1's F-QUAL-L4 flagged `max int` as a parameter name shadowing the language builtin. M3's sweep moved the function to `internal/broker/runes.go` but kept the parameter name. Production-impact-zero today (no `max(a, b)` call inside the function), but the shadow remains.
**Impact**: Future-only.
**Recommendation**: Rename to `limit` or `maxRunes`. One-line change.

### F-QUAL2-L2: Carry-over — `oauthlogin/login.go:184` uses inline `errors.New` instead of a sentinel
**Location**: `internal/oauthlogin/login.go:184`
**Finding**: Pass #1's F-QUAL-L1. `return Result{}, errors.New("id token missing from token exchange response")` is the only inline `errors.New` in a file that otherwise uses 11 named sentinels.
**Impact**: Callers can't match this specific failure with `errors.Is`.
**Recommendation**: Promote to `ErrOAuthLoginIDTokenMissing` alongside `ErrOAuthLoginIDTokenMissingSubject`.

### F-QUAL2-L3: Carry-over — `OIDCVerifier.VerifyAccessToken` uses six inline `errors.New` for distinct failure modes
**Location**: `internal/idp/oidc.go:108, 126, 129, 132, 138, 141`
**Finding**: Pass #1's F-QUAL-L2. Five distinct failure modes (audience, scope, token_use, iat-future, iat-too-old, empty-token) return `errors.New(...)` rather than sentinels callers can match.
**Impact**: Pure log-text variability today; future audit-tagging or observability hooks can't distinguish failure classes.
**Recommendation**: Optional — promote to sentinels (`ErrAccessTokenAudience`, etc.) and wrap with `fmt.Errorf("%w: ...", ...)`. Not urgent.

### F-QUAL2-L4: Carry-over — `IssueTimePayload` repeats three identical signer-denial blocks
**Location**: `internal/broker/issuetimepayload.go:217-220, 230-233, 237-241`
**Finding**: Pass #1's F-QUAL-L5. Three near-identical 3-line `signerDenial := timePayloadDenialTemplate(...); signerDenial.DeviceSerial = ...; i.recordTimePayloadDenialFor(...)` blocks at the three JWS-pipeline failure points.
**Impact**: A future fourth signer-failure point would need a fourth copy.
**Recommendation**: Extract a `recordSignerDenialFor(ctx, engineerCtx, deviceCtx, request)` helper.

### F-QUAL2-L5: Carry-over — `sort.Slice` / `sort.Strings` legacy patterns
**Location**: `internal/certcache/cache.go:276,311`, `internal/sshconf/writer.go:134`, `pkg/cliapp/profile.go:172`
**Finding**: Pass #1's F-QUAL-L3 flagged one site; the broader survey finds four production sites still using stdlib `sort.Slice` / `sort.Strings` where `slices.SortFunc` / `slices.Sort` would be idiomatic Go 1.21+. Tests still pass; correctness is unchanged.
**Impact**: Cosmetic. Senior-Go bar (Rule 4) would reach for the generic helpers.
**Recommendation**: Optional — `slices.Sort(devices)`, `slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Device, b.Device) })`.

### F-QUAL2-L6: `internal/broker` lacks per-file overview comments under the user's Rule 2 sniff test
**Location**: `internal/broker/preamble.go`, `internal/broker/sshcert.go`, `internal/broker/types.go`, `internal/broker/issuetimepayload.go`, `internal/broker/id.go`, `internal/broker/runes.go`
**Finding**: The package-level doc lives in `errors.go`. Six other files in the package open directly with `package broker` and no per-file context. Rule 2 calls for "file-level (package) comment on every non-trivial Go file"; Rule 4's senior-Go sniff test asks "would deleting the comment lose the reader information?" — for `runes.go` (one tiny exported helper) the file-level comment is redundant with the function's own doc, but `preamble.go` (which has a 30-line `//` block of design rationale **between** the `package broker` declaration and the first type — see lines 12-33) is actually carrying its file-level doc, just not on the package line. The convention is "either godoc-style or in-body explanation"; the current placement skips godoc.
**Impact**: Minor. Readers landing in `preamble.go` via grep do find the design block; readers landing via `godoc internal/broker` do not.
**Recommendation**: Optional — move `preamble.go`'s block-comment above the `package broker` line (it would attach to the package doc, which is allowed: multiple files can each carry a doc; godoc concatenates) or leave alone. `runes.go` and `id.go` need no file-level doc per Rule 4.

### F-QUAL2-L7: `// for the IDGenerator interface (the broker pipeline...)` — UUIDv7Generator method comment runs long
**Location**: `internal/broker/id.go:34-41`
**Finding**: The `NewID` method's body has a 7-line inline comment explaining why `time.Time` is preserved as a parameter even though `uuid.NewV7` ignores it. The comment is defensive about a non-decision (the interface preserves the param; the impl ignores it; both are fine) and the prose is wordier than the code it explains.
**Impact**: Comment-readability. Rule 4's sniff test ("delete the comment without losing information") applies — the IDGenerator interface signature is the contract; that this impl ignores `now` is a per-impl detail a reader can verify in three lines.
**Recommendation**: Optional — collapse to one line: `// uuid.NewV7 reads its own millisecond timestamp from time.Now; the now parameter satisfies the IDGenerator interface.` or delete entirely (the impl is short enough that the unused parameter is self-evident).

## Informational

### F-QUAL2-I1: CV-1 production sweep holds (except F-QUAL2-H1)
**Location**: project-wide
**Finding**: Sweep for `LD-\d+`, `D-\d+`, `TF-[A-Z]`, `OQ-`, `RO-\d+`, `invariant [A-Z]`, `sub-phase`, `phase \d` patterns across non-test production files turns up zero hits. Only `F-SEC-M1` (a finding-ID, which the original CV-1 spec didn't list but which falls under the same Rule-3 prohibition) regressed; see F-QUAL2-H1. The `_test.go` files still carry some `LD-XX` references, which is in-scope-allowed per AGENTS.md guidance.
**Impact**: Positive — the discipline that took multiple passes to establish is mostly intact.

### F-QUAL2-I2: Sweep-introduced files are idiomatic Go
**Location**: `internal/broker/runes.go`, `internal/broker/testsigner.go`, `internal/broker/id.go`, `internal/oauthlogin/token.go`, `internal/tokenstore/file.go`, `pkg/cliapp/runtime.go`
**Finding**: Modulo F-QUAL2-H1 and F-QUAL2-M1, the new code is well-shaped:
- `runes.go` is properly minimal (one exported function, one import, godoc on the function explaining the use-case domain).
- `testsigner.go`'s comment block is exemplary — it names the cross-package-tests-only role explicitly and steers production callers away. The "Keep new production paths from reaching for `SSHSigner`" sentence is the kind of comment Rule 3 actually wants.
- `id.go` correctly preserves the 64-bit-Serial independence rationale in a code comment (lines 47-51) — the *why* is non-obvious from the code shape, so the comment earns its keep.
- `file.go`'s `Save` now delegates to `atomicfile.WriteFile`; the doc comment explains the atomic-write semantics in one sentence each.
- `token.go`'s go-jose use is idiomatic (`jwt.ParseSigned` + `UnsafeClaimsWithoutVerification`). The `UnsafeClaimsWithoutVerification` doc comment is correct about the broker-is-authoritative-verifier rationale.
- `runtime.go`'s cleanup closure (modulo F-QUAL2-M1) is the right Go pattern.

### F-QUAL2-I3: `go vet ./...` clean; `go test ./...` green
**Location**: project-wide
**Finding**: No vet diagnostics. All 17 test packages pass. No `time.Sleep` in production OR test code. `TODO`/`FIXME`/`HACK`/`XXX` zero in production. `interface{}` zero in production. `panic` zero in production. Concurrency primitives bounded (one `sync.Mutex` in `internal/certcache/cache.go`, one `chan` + `go func` in `cmd/broker/main.go` for the listen goroutine, one in `internal/oauthlogin/login.go` for the OAuth callback channel).
**Impact**: Positive baseline.

## Methodology

1. Read `AGENTS.md` (Workflow rules, Doc style rules, Things AI agents should NOT do), the user's Go-style memory (Rules 1-5), and `docs/audit-post-timefix/quality.md` for prior-pass cross-check.
2. Read each of the named sweep-touched files end-to-end: `internal/broker/runes.go`, `internal/broker/testsigner.go`, `internal/broker/id.go`, `internal/tokenstore/file.go`, `internal/oauthlogin/token.go`, `internal/idp/oidc.go`, `pkg/cliapp/runtime.go`. Cross-referenced against the sweep commit message at `8eb0efd`.
3. CV-1 production-code sweep: `grep -rnE 'LD-[0-9]+|D-[0-9]+|TF-[A-Z]|OQ-|RO-[0-9]+|invariant [A-Z]|sub-phase|phase [0-9]'` plus a follow-up sweep for `F-SEC|F-HR|F-QUAL|F-OQ` finding-ID prefixes (caught the F-QUAL2-H1 regression).
4. Pass #1 closure verification: each of F-QUAL-M1..M5 located in the current tree.
5. Idiom checks: `fmt.Errorf` with no format verbs (none), `errors.New` in production (audited; carry-over LOWs noted), `err.Error()` string-matching (zero), `interface{}` usage (zero), `time.Sleep` (zero), `panic` (zero), `sort.Slice`/`sort.Strings` (four sites; F-QUAL2-L5), `sync.*`/`chan`/`go func` concurrency surface (three well-bounded sites).
6. Function-length scan: six functions > 80 lines, all justified as pipelines with extensive comment scaffolding (`IssueSSHCert`, `IssueTimePayload`, `oauthlogin.Login`, `Config.Validate`, `defaultExecSSHTimefix`, `runTimefix`).
7. Doc-comment scan: package-level doc presence (all 19 production packages have one), file-level overview comments (six broker-package files lack them; F-QUAL2-L6).
8. `go vet ./...` clean; `go test ./...` green; build not re-run (already verified by sweep commit).
9. `staticcheck` not installed locally, not run.
