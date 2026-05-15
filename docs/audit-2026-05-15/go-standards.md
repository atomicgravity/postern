# Go idiom / community-style audit — 2026-05-15

## Scope and methodology

Fresh Go-style audit of all production code under `cmd/`, `internal/`, and `pkg/` (72 non-test `.go` files; protobuf-generated `internal/securetunnel/proto/v3.pb.go` excluded). Focus: error handling (`errors.Is`/`errors.As`, `%w` wrapping, sentinels), context propagation, concurrency, package design, type design, modern standard library usage (`slices`, `maps`, `cmp`, `errors.Join`, Go 1.22+ features), naming, comments, `go vet`-class issues. The prior pass's closed findings (`docs/audit-post-timefix/quality.md` and `docs/audit-post-sweep/quality.md`) are not re-stated; what remains here is either new since the pass-2 audit or a still-open carry-over that the user-facing Go-style memory (Rule 3 on phase references) makes worth surfacing again. `go vet ./...` runs clean; `staticcheck` not installed locally.

## High

### G-1: `LD-NN` and other phase identifiers have leaked back into production comments — CV-1 regression
**Location**: 12 occurrences across `internal/broker/sshcert.go:68`, `internal/broker/issuetimepayload.go:19`, `internal/brokerwire/wire.go:63`, `pkg/brokerhandlers/handlers.go:55,82`, `pkg/cliapp/addhost.go:85,151`, `pkg/cliapp/mint.go:59,63,127`, `pkg/cliapp/scp.go:139,199`
**Priority**: High
**Finding**: The user's Go-style memory rule 3 ("comments NEVER reference phases / LD-X / RO-X / sub-phase numbers") is explicit, and the prior two audits (`audit-post-timefix` + `audit-post-sweep`) closed CV-1 at zero hits in production code. The current tree has 12 production-code references to locked-decision identifiers: `LD-93` (3 sites documenting the SRP issuer split), `LD-112` / `LD-116` / `LD-109` (cliapp comments). Examples: `internal/broker/sshcert.go:68` `// device, rate-limit, authorize, build cert, sign, audit. Per LD-93's SRP`; `pkg/cliapp/mint.go:59` `// State-aware branch (LD-116): consult the Postern-managed ssh.conf`. The references add nothing the surrounding code doesn't already explain — they're paper-trail metadata that belongs in git log and `docs/`, not in live source.
**Recommendation**: Strip the parenthetical `(LD-NNN)` / `per LD-NNN` references from every comment. Where the comment leans on the reference to mean something ("Per LD-93's SRP split, …"), rephrase to describe the architectural choice plainly ("The cert-mint, time-payload, and tunnel-open pipelines live on distinct issuer types so …").

### G-2: `spec D7` / `Spec D8` / `D3` references in production comments
**Location**: `internal/tunneling/awsiot.go:30`, `internal/broker/tunnel.go:40`, `pkg/cliapp/tunnel.go:157`, `pkg/cliapp/scp.go:191`
**Priority**: High
**Finding**: Same memory-rule-3 violation as G-1, different prefix. `internal/tunneling/awsiot.go:30` `// or DescribeTunnel — those have no v1 use case per spec D7.`; `internal/broker/tunnel.go:40` `// engineer doesn't pass --max-lifetime. Spec D8: 8 hours fits a full`; `pkg/cliapp/tunnel.go:157` `// tunnel-mode flags from D3: -p <local-port> …`. These are spec section numbers that, like LD-N, are not a stable in-code reference. Future spec edits or renumbering will leave the in-code reference stale.
**Recommendation**: Drop the `per spec DN` / `Spec DN:` prefixes; keep the rationale prose. In `tunneling/awsiot.go` the comment is informative without `spec D7`; in `broker/tunnel.go` the engineer-workday rationale stands without "Spec D8:".

## Medium

### G-3: `internal/oauthlogin/login.go` carries an unchecked `*net.TCPAddr` type assertion
**Location**: `internal/oauthlogin/login.go:347`
**Priority**: Medium
**Finding**: `addr := listener.Addr().(*net.TCPAddr)` — single-value type assertion that panics on a non-TCP listener. The listener is created via `net.Listen("tcp", …)` two lines above, so today the assertion always succeeds, but the convention is to use the two-value form for any type assertion not provably safe at type-system level. `internal/securetunnel/proxy.go:261-266` shows the right pattern (`addr, ok := s.listener.Addr().(*net.TCPAddr); if !ok { return 0 }`).
**Recommendation**: Use the two-value assertion and propagate a clean error rather than panicking if the assumption ever breaks: `addr, ok := listener.Addr().(*net.TCPAddr); if !ok { return nil, "", fmt.Errorf("loopback listener returned non-TCP addr %T", listener.Addr()) }`.

### G-4: `internal/securetunnel/loops.go` redefines `slices.Contains`
**Location**: `internal/securetunnel/loops.go:314-321` (`containsString`), with one caller at `loops.go:110`
**Priority**: Medium
**Finding**: A hand-rolled `containsString(list []string, target string) bool` lives at the bottom of the file. The package already targets Go 1.24 (so stdlib `slices` is available) and other packages in the tree use `slices.Contains` (e.g. `internal/idp/oidc.go:130,190`). Local helper is dead code waiting to happen.
**Recommendation**: Replace the body of the single call site with `slices.Contains(message.GetAvailableServiceIds(), s.serviceID)` and delete `containsString`. Net change is a positive line count.

### G-5: `internal/securetunnel/proxy.go` allocates stream IDs with a hand-rolled CAS loop
**Location**: `internal/securetunnel/proxy.go:304-312` (`allocateStreamID`)
**Priority**: Medium
**Finding**: The function uses an explicit `Load` + `CompareAndSwap` loop to allocate the next int32 from an `atomic.Int32`. The semantically equivalent and far simpler call is `s.nextStreamID.Add(1) - 1` (return the prior value, advance by one) or `s.nextStreamID.Add(1)` (with the counter pre-seeded at 0). Hand-rolled CAS only earns its keep when there's a branch inside the loop, and there isn't one here — the loop exists to wrap a single increment that `atomic.Int32` already does atomically.
**Recommendation**: Replace the loop body with `return s.nextStreamID.Add(1) - 1` (preserves the existing "starts at 1" semantics because `Store(1)` happens in `StartSourceProxy`, so the first `Add(1)-1` returns 1).

### G-6: `internal/idp/oidc.go` uses `map[string]bool` for set semantics
**Location**: `internal/idp/oidc.go:194` (`seen := map[string]bool{}`)
**Priority**: Medium
**Finding**: Idiomatic Go (per the Go FAQ and Go Wiki SliceTricks) uses `map[string]struct{}{}` for sets so the zero-byte value makes intent explicit and saves the bool tag. `map[string]bool` is fine when you actually need the bool's `false` slot to mean something; here only the key membership matters. Single occurrence; mentioning so the next set-pattern lands in the right shape.
**Recommendation**: `seen := map[string]struct{}{}` with `seen[group] = struct{}{}` and `if _, ok := seen[group]; ok { continue }`. Or use `slices.Contains` against the result slice in this small loop — N is bounded ≤ 64+64.

### G-7: `internal/atomicfile/atomicfile.go` discards `tempFile.Close()` errors via bare call instead of `_ =` and could use `defer cleanup`
**Location**: `internal/atomicfile/atomicfile.go:39,44,77,82` (both `WriteFile` and `WriteFileExclusive`)
**Priority**: Medium
**Finding**: On the error paths after `tempFile.Write` / `tempFile.Chmod` fail, the code calls `tempFile.Close()` without capturing the result and without the `_ =` blank-assignment that signals "intentionally ignored." `go vet` doesn't flag this for `Close` specifically (only `errcheck`/`staticcheck` SA5001 do), but the pattern is inconsistent with the same files' `_ = os.Remove(tempPath)` two lines below. More structurally, a `defer cleanup()` after `os.CreateTemp` would simplify the function: every error path duplicates the `tempFile.Close(); cleanup()` pair and a single deferred handler eliminates that duplication.
**Recommendation**: Either prefix the discarded `Close` with `_ =` for consistency, or refactor with `defer` so cleanup runs once: capture `closed := false`, defer `if !closed { tempFile.Close() }` and `defer cleanup()` (with `cleanup` no-oping after a successful rename).

### G-8: `pkg/cliapp/tunnel.go` / `pkg/cliapp/scp.go` use `fmt.Sprintf("%d", localPort)` instead of `strconv.Itoa`
**Location**: `pkg/cliapp/tunnel.go:179`, `pkg/cliapp/scp.go:209`
**Priority**: Medium
**Finding**: `fmt.Sprintf("%d", localPort)` is the textbook over-engineered integer-to-string conversion. `strconv.Itoa(localPort)` is faster (avoids the format-string parser), allocates less, and is the documented idiom in the Go standard library. `strconv.Itoa` already imported in other files in the same package (`pkg/cliapp/tunnel_open.go`).
**Recommendation**: `"-p", strconv.Itoa(localPort)` / `"-P", strconv.Itoa(localPort)`.

### G-9: `internal/registry/dynamodb.go` returns broker domain errors that wrap an `Error{StatusCode:…}` but bypass the err-wrap chain
**Location**: `internal/registry/dynamodb.go:67,80,84,87`; same pattern in `internal/registry/http.go:168,190,193,207`
**Priority**: Medium
**Finding**: These call sites return `broker.Error{StatusCode: …, Message: "…"}` as plain values rather than wrapping the underlying cause. The pattern is intentional (the broker domain treats `Error` as a status-bearing terminal error per `errors.go:28-40`), and the `errors.As` translation at the HTTP boundary works correctly. The Medium concern: when the DynamoDB SDK returns a meaningful error (e.g. throttling), `dynamodb.go:77` correctly wraps it via `fmt.Errorf("registry: %w", err)`, but the empty-serial branch at `:84` silently drops the SDK-level diagnostic and surfaces only the broker.Error's static message. A caller running with debug logs sees `"registry item missing serial"` with no clue which SDK call (if any) produced the malformed item.
**Recommendation**: Either accept the current shape (it's defensible — the empty-serial branch is provenance-free anyway, the broker just observed missing data) or thread the deviceID into the error message so operators can find the offending row: `Message: fmt.Sprintf("registry item %q missing serial", deviceID)`. Same for `http.go:193` "registry lookup failed" — including the upstream status code (`fmt.Sprintf("registry lookup failed (status %d)", response.StatusCode)`) would make 502 deflection diagnosable from logs alone.

### G-10: `internal/oauthlogin/login.go:184` and `internal/idp/oidc.go:110-141` carry-over inline `errors.New` for distinct failure modes
**Location**: `internal/oauthlogin/login.go:184`, `internal/idp/oidc.go:110,128,131,134,140`
**Priority**: Medium
**Finding**: Carry-over from prior pass's F-QUAL-L1 / F-QUAL-L2 (still flagged as F-QUAL2-L2 / F-QUAL2-L3 in pass 2). `login.go:184` still has the lone inline `errors.New("id token missing from token exchange response")` in a file that defines 11 named sentinels. `oidc.go` `VerifyAccessToken` still has 5 inline `errors.New` for distinct failure modes (token_use, audience, scope, iat-future, iat-too-old) that callers can't match with `errors.Is`. Pass 2 flagged these as Low; bumping to Medium here because the prior two audits closed all but these LOWs, and a third pass not addressing them suggests they may be in scope. Cheap to fix.
**Recommendation**: Promote each inline `errors.New` to a package-level sentinel and wrap with `fmt.Errorf("%w: …", ErrFoo, contextDetail)` at the use site, mirroring the file's existing sentinel pattern.

## Low

### G-11: `internal/broker/runes.go:12` — `max` parameter shadows the language builtin
**Location**: `internal/broker/runes.go:12` (`TruncateRunes(s string, max int)`)
**Priority**: Low
**Finding**: Carry-over from the prior two passes (F-QUAL-L4 / F-QUAL2-L1). `max` is now a Go 1.21+ builtin function; using it as a parameter name shadows the builtin inside the function body. Compiles fine today (no call to `max(…)` inside the body) but the shadow is a future-only foot-gun.
**Recommendation**: Rename the parameter — `limit` matches the field's role across call sites.

### G-12: `sort.Slice` / `sort.Strings` still used where `slices.SortFunc` / `slices.Sort` would be idiomatic
**Location**: `internal/certcache/cache.go:276,311`, `internal/sshconf/writer.go:134`, `pkg/cliapp/profile.go:172`
**Priority**: Low
**Finding**: Carry-over from F-QUAL-L3 / F-QUAL2-L5. Modern Go-1.21+ idiom is `slices.Sort(devices)` (for `[]string`) and `slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Device, b.Device) })`. Stdlib `sort.Strings` and `sort.Slice` still work; the project otherwise reaches for `slices.*` and `cmp.*` (per the prior audit's F-QUAL-I2). Three sites; one more than pass 2 (the certcache file had two sites already).
**Recommendation**: Replace each call with the generic equivalent. `pkg/cliapp/profile.go:172` can collapse the whole function body to `return slices.Sorted(maps.Keys(c.Profiles))` (Go 1.23+ helper that returns sorted keys directly).

### G-13: `internal/idp/oidc.go:194-205` (`mergedGroups`) builds and discards a slice via `append(groups, cognitoGroups...)` to iterate
**Location**: `internal/idp/oidc.go:193-205`
**Priority**: Low
**Finding**: `for _, group := range append(groups, cognitoGroups...)` creates a fresh slice purely to iterate over both inputs. The idiomatic Go 1.23+ approach is `slices.Concat` (zero hidden mutation surface) or a small helper, but the simplest replacement is two `for-range` loops over the original slices. The mutation cost is small but the `append(a, b...)` pattern is sometimes load-bearing (when `groups` has capacity headroom it mutates the underlying array); putting it in a fresh-slice expression inside the loop header is the textbook accidentally-mutate-shared-backing-array footgun.
**Recommendation**: `for _, group := range slices.Concat(groups, cognitoGroups)` (Go 1.22+) or two range loops, sharing the dedup logic. Same observable behavior, no implicit capacity-mutation hazard.

### G-14: `internal/securetunnel/proxy.go:30` — `DefaultServiceID` exported with no godoc-shape doc comment
**Location**: `internal/securetunnel/proxy.go:27-30`
**Priority**: Low
**Finding**: `DefaultServiceID = "SSH"` is exported but the comment block above it doesn't lead with the symbol name ("Default service identifier…" — Go convention is "DefaultServiceID is the default service…"). godoc won't surface this comment correctly. Same minor issue at `internal/oauthlogin/login.go:106` (`DisplayName` method has no doc), `internal/broker/types.go:349` (`SystemClock.Now`), `internal/broker/id.go:33` (`UUIDv7Generator.NewID`), and `internal/signer/kms.go:77` (`KMSSigner.PublicKey`).
**Recommendation**: Either rewrite the comment to lead with the symbol name (`// DefaultServiceID is the default service identifier the v1 source proxy advertises…`) or drop the comment if the symbol name plus the godoc on the type already says enough. For interface-implementing methods like `Now` / `PublicKey` / `NewID`, the interface doc covers it; deleting the missing-comment problem entirely is the right call.

### G-15: `internal/idp/oidc.go:68` (`NewOIDCVerifier`) is exported without a doc comment
**Location**: `internal/idp/oidc.go:68`
**Priority**: Low
**Finding**: `NewOIDCVerifier(ctx context.Context, config OIDCVerifierConfig) (*OIDCVerifier, error)` is a primary exported constructor with no leading `// NewOIDCVerifier …` comment. The 30-line comment block inside the function body (about `SkipClientIDCheck` and `SupportedSigningAlgs`) is informative, but a reader landing on the godoc index for the package sees an undocumented constructor.
**Recommendation**: Add a 2-3 line doc comment naming what the constructor returns and what the discovery roundtrip costs ("reaches the configured IdP's `/.well-known/openid-configuration` endpoint during construction").

### G-16: `cmd/timefix-apply/main.go:230` uses `strings.Split` on the full file body for line iteration
**Location**: `cmd/timefix-apply/main.go:230`
**Priority**: Low
**Finding**: `for _, line := range strings.Split(string(contents), "\n")` allocates the full split-slice up-front for what is otherwise a one-pass linear scan. The principals file is tiny (a handful of lines in practice), so the cost is invisible, but Go 1.24's `strings.SplitSeq` (or a `bufio.Scanner` over `bytes.NewReader(contents)`) is the modern idiom and avoids the full-slice allocation.
**Recommendation**: `for line := range strings.SplitSeq(string(contents), "\n")` (Go 1.24+ iterator) keeps the body unchanged. `bufio.Scanner` works too if the function ever grows to read the file streaming.

### G-17: `internal/tunneling/awsiot.go:126` — `Error()` uses `fmt.Sprintf("%v", e.err)` instead of `e.err.Error()`
**Location**: `internal/tunneling/awsiot.go:126-128`
**Priority**: Low
**Finding**: `return fmt.Sprintf("tunneling: %v", e.err)` runs the inner error through `fmt`'s reflection-driven formatter when a direct string concat or `%s` would do. For wrapped errors that aren't `fmt.Stringer` this is identical, but `%v` semantics on an `error` is "call `.Error()` via the fmt formatter pipeline" — strictly slower and idiomatically `%s` (or `e.err.Error()`) is what the standard library uses (e.g. `os.PathError.Error()` returns `op + " " + path + ": " + err.Error()`).
**Recommendation**: `return "tunneling: " + e.err.Error()`.

### G-18: `internal/securetunnel/proxy.go:108-112` stores `context.Context` in a struct (`rootCtx`)
**Location**: `internal/securetunnel/proxy.go:108-112`, with retrieval at `loops.go:56`, `loops.go:245`
**Priority**: Low
**Finding**: The Go context guidelines explicitly say "Do not store Contexts inside a struct type; instead, pass a Context explicitly to each function that needs it." The exception is documented and intentional here (the proxy owns long-running goroutines spawned at construction time; the rootCtx becomes the cancellation channel they all listen on), and the comment at `proxy.go:108-110` explains it. The same pattern in `internal/signer/kms.go:128-131` (`kmsSSHSigner.ctx`) explicitly names itself "the documented Go anti-pattern" and explains why — that's how this should land.
**Recommendation**: Add a one-sentence comment above the `rootCtx` field acknowledging the anti-pattern by name and naming the per-goroutine cancellation requirement that forces it, matching `kms.go:122-127`'s tone. The pattern itself is fine; the documentation makes it grep-discoverable.

### G-19: `internal/atomicfile/atomicfile.go` could expose a single function with an exclusive flag
**Location**: `internal/atomicfile/atomicfile.go:28-57` (`WriteFile`) and `:66-96` (`WriteFileExclusive`)
**Priority**: Low
**Finding**: The two exported functions differ only in `os.Rename` vs `os.Link`. Sixteen lines of body are duplicated verbatim. A single `WriteFile(path string, data []byte, mode os.FileMode, opts ...Option)` (or `WriteFileOpts`) with a `WithExclusive()` toggle would halve the maintenance surface; alternatively a private helper `writeAtomic(path string, data []byte, mode os.FileMode, publish func(temp, dest string) error) error` keeps the two public entry points but folds the body together. Not urgent — the two functions are tiny — but the next time both need a tweak (umask handling, fsync, sync directory), both will need the same tweak twice.
**Recommendation**: Extract the shared body into a private helper that takes a publish-closure. Net change is mild simplification.

### G-20: `pkg/cliapp/profile.go:167` — `ProfileNames` could collapse via `slices.Sorted(maps.Keys(c.Profiles))`
**Location**: `pkg/cliapp/profile.go:167-174`
**Priority**: Low
**Finding**: The function body manually iterates the map to build `names`, then sorts. Go 1.23 introduced `slices.Sorted(maps.Keys(m))` which does both in one line. The project's go.mod floor is 1.24, so the helper is available.
**Recommendation**: `func (c Config) ProfileNames() []string { return slices.Sorted(maps.Keys(c.Profiles)) }`. Drops the manual loop + `sort.Strings`.

## Informational

### G-21: `for range int` (Go 1.22+) is unused across the tree
**Location**: project-wide
**Finding**: Go 1.22 introduced `for i := range N` as a count-up form (no need for the C-style `for i := 0; i < N; i++`). The codebase has zero such loops today — defensible because the codebase tends to range over slices and maps, not count-up. Flagging only as informational: if a future contributor needs a counted loop they should reach for the modern form first.

### G-22: `errors.Join` adoption is excellent; `errors.Is`/`As` usage clean
**Location**: project-wide
**Finding**: 12 `errors.Join` call sites (validators in `oauthlogin`, `tokenstore`, `cliapp.Profile`, `brokerhandlers.Config`, and the broker-pipeline `PipelineDeps.validate`). No `strings.Contains(err.Error(), …)` patterns. No bare `err == sentinel` comparisons. 44+ `errors.Is` / `errors.As` uses are well-distributed. The error vocabulary is consistent — broker domain owns the status-bearing `Error` type, every package defines `Err*` sentinels with `errors.Is`-matchable identities, and `%w` wrapping is used at 151 sites with no `%w` misuse detected.

### G-23: `go vet ./...` runs clean
**Location**: project-wide
**Finding**: No `vet` diagnostics. No `interface{}` (uses `any`). No `panic(` in non-test code. No `time.Sleep` in any code (production or test). No `TODO`/`FIXME`/`XXX`/`HACK` markers. Go 1.22 method-prefix `ServeMux` patterns (`POST /ssh/cert`) used. `log/slog` used throughout — no `pkg/log`, no `fmt.Println` outside test/CLI-output paths. `cmp` package adoption confirmed in error-classifier paths.

### G-24: Concurrency primitives are tightly scoped and well-bounded
**Location**: `cmd/broker/main.go:86-94` (listen goroutine), `internal/oauthlogin/login.go:361-398` (OAuth callback), `internal/certcache/cache.go:80,140-170` (key creation mutex), `internal/securetunnel/proxy.go` (read+accept+stream pumps tracked via sync.WaitGroup with `goleak` discipline)
**Finding**: Each `go func` / `chan` / `sync.*` use has a documented owner and a documented closure path. `internal/securetunnel/doc.go` calls out the goroutine-join discipline as load-bearing and the test suite uses `go.uber.org/goleak` to assert clean teardown. The `terminateOnce sync.Once` / `closeOnce sync.Once` pattern in `proxy.go` correctly idempotent-izes the teardown paths. Solid concurrency hygiene.

### G-25: `pkg/` → `internal/` direction kept clean except the known brokerwire arrangement
**Location**: project-wide
**Finding**: `pkg/brokerhandlers` and `pkg/cliapp` import `internal/*` (expected); `internal/brokerwire` still imports `pkg/brokerhandlers` (carry-over flag from F-QUAL-L6 — the package is wiring-glue for the unwrapped binaries, sitting in `internal/` because wrappers wire their own). No new cycles introduced. The decision is intentional and previously flagged; informational here so a future audit doesn't re-discover it cold.

## Already-idiomatic areas

The codebase is in genuinely good shape on Go fundamentals: errors are wrapped with `%w` at 151 sites with consistent sentinel + `errors.Is`/`As` reach; `errors.Join` is the validator standard; context flows through every blocking I/O call including KMS Sign, OIDC discovery, DynamoDB UpdateItem, the AWS IoT OpenTunnel control-plane call, and the WebSocket source-proxy read/accept/stream loops; goroutines have named owners with `sync.WaitGroup` joins and `sync.Once` idempotent teardown; `log/slog` is the only logging path; `any` (not `interface{}`); no `time.Sleep` in production or test code; no `panic` in production; no `err.Error()` string-matching; protobuf-generated code is segregated; the broker domain owns its status-bearing `Error` type with a clean one-way HTTP-shim translation in `pkg/brokerhandlers`; the privilege-split between `cmd/timefix-apply` (unprivileged) and `cmd/timefix-set-clock` (cap_sys_time) keeps the setter's input surface to a single integer; `go vet ./...` runs clean and `cmd/timefix-apply`'s build-tag-gated test path is correctly partitioned from production. The two highest-impact findings (G-1 / G-2 CV-1 regressions) are comment cleanups, not structural issues — the production code body itself remains modern Go.
