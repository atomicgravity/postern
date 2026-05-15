# Code quality / DRY / organization audit — 2026-05-15

## Scope and methodology

Fresh code-quality lens on the Postern repo, focused on what landed in the
tunneling phase (TN-A–TN-F, closed 2026-05-14, LD-92..LD-118) plus the
unified user-resolution refactor that closed in the same session. Read
`AGENTS.md`, `docs/team-handoff.md`, both prior quality audits
(`docs/audit-post-sweep/quality{,-overall}.md`,
`docs/audit-post-timefix/quality{,-overall}.md`), then walked the new and
new-shaped surfaces: `internal/broker/tunnel.go`, `internal/broker/preamble.go`
(post-SRP-split), `internal/securetunnel/*` (the new package), `internal/tunneling/*`
(the AWS IoT impl), `internal/brokerclient/client.go` (now three near-identical
request methods), `pkg/cliapp/tunnel.go`, `pkg/cliapp/tunnel_open.go`,
`pkg/cliapp/ssh.go`/`scp.go`/`sshuser.go`, and the broker `handlers.go` post-SRP.
Cross-referenced against the prior audits to surface only NEW issues. Did NOT
re-flag prior-pass items the post-sweep audit already addressed or carried as
backlog; explicit reuse calls below where a finding is the carry-over backlog
the user explicitly asked me to skip.

Capped at 25 findings. Tester / security / Go-style / library-swap concerns
deferred to the parallel agents.

**Severity counts:** High 3 · Medium 11 · Low 7 · Informational 3

## High

### Q-1: Three near-identical issuer-denial APIs across the SSH-cert / time-payload / tunnel pipelines
**Location**: `internal/broker/sshcert.go:287-371`, `internal/broker/issuetimepayload.go:299-368`, `internal/broker/tunnel.go:303-370`
**Priority**: High
**Finding**: The LD-93 SRP split shipped three concrete issuer types
(`SSHCertIssuer`, `TimePayloadIssuer`, `TunnelIssuer`) that each define a parallel
quartet of audit-emit helpers: `*DenialTemplate(engineerCtx) AuditEvent`,
`record*DenialFor(ctx, event, deniedReason, request)`, `Record*HandlerDenial(ctx, HandlerDenial)`,
and `record*Denial(ctx, event)` (the slog-and-record helper). The three quartets
are byte-near-identical — they vary only in the `Event` literal (`EventCertDenied` /
`EventTimePayloadDenied` / `EventTunnelDenied`), the `PrincipalType` literal, the
slog message prefix, and the request's `DeviceID` field name. ~120 lines of
near-duplicate code across the three files, all written in the same phase. The
"every request → one audit row" invariant currently lives in three copies that
must stay in sync; a future fourth endpoint would force a fourth copy.
**Recommendation**: Hoist a single `denialEmitter` (or methods on `PipelineDeps`)
parameterized by `Event` literal, `PrincipalType` literal, and slog log line. The
per-endpoint `record*DenialFor` becomes a 3-line wrapper that sets DeviceIDUsed
from the request type, then delegates. Since the three request types differ in
shape (`SSHCertIssueRequest` carries PrincipalType wire-side, the others don't),
a small generic or interface satisfies the DeviceID-extraction needs without
pulling request shape into the shared helper.

### Q-2: Three near-identical request methods on `brokerclient.Client` (MintSSHCert / RequestTimePayload / OpenTunnel)
**Location**: `internal/brokerclient/client.go:49-242`
**Priority**: High
**Finding**: The CLI's broker HTTP client has three methods, each ~50 lines, each
following the same exact shape: trim+empty-check the inputs, resolve endpoint,
JSON-marshal the body, build the request with timeout context, set bearer/Content-Type/Accept
headers, do the HTTP call with a generic error wrap, status-code-check with
4096-byte body read on non-200, JSON-decode the response, sanity-check non-empty
response fields. The only per-method variation is (a) input validation rules,
(b) endpoint path, (c) request/response struct shapes, (d) the error prefix
string. The OpenTunnel method was added in TN-B; its arrival triples the
copy-paste exposure.
**Recommendation**: Extract a generic `postJSON[Req, Resp any](ctx, accessToken,
endpointPath, req)` (or a non-generic helper that takes `interface{}` plus a
"validate response is non-empty" closure). Each public method shrinks to its
distinctive input validation + endpoint path + response sanity-check.

### Q-3: CV-1 regression — multiple `LD-XX` / `TN-X` phase-IDs leaked into production code
**Location**: `internal/brokerwire/wire.go:63`, `internal/broker/sshcert.go:68`, `internal/broker/issuetimepayload.go:19`, `pkg/brokerhandlers/handlers.go:55,82`, `pkg/cliapp/tunnel.go:33`, `pkg/cliapp/scp.go:139,199`, `pkg/cliapp/mint.go:59,63,127`, `pkg/cliapp/addhost.go:85,151`
**Priority**: High
**Finding**: The post-timefix audit's F-QUAL-I1 verified zero phase-ID references
in production code; the post-sweep audit's F-QUAL2-I1 confirmed the discipline
held (modulo one `F-SEC-M1` reference that got cleaned up). The tunneling phase
broke that. There are now thirteen new production-code comments referencing
`LD-93`, `LD-109`, `LD-112`, `LD-116`, and `TN-D` across `internal/brokerwire`,
`internal/broker`, `pkg/brokerhandlers`, and four files in `pkg/cliapp`. The
`pkg/cliapp/tunnel.go:33` reference (`// (ssh today, scp once TN-D lands) consumes`)
is doubly broken: it's a process-vocab leak AND it's stale (TN-D is closed; scp
tunneling shipped). Per the user's Rule 3 in `feedback_go_code_style.md`:
"comments NEVER reference phases / LD-X / RO-X / sub-phase numbers."
**Recommendation**: Sweep all 13 sites; rephrase each to describe the
behavior/decision without naming the LD/TN identifier. The doc-string in
`internal/broker/sshcert.go:68` ("Per LD-93's SRP split, it carries ONLY the
cert-mint methods...") becomes "It carries ONLY the cert-mint methods —
time-payload and tunnel-open pipelines live on sibling concrete types..." with
no LD reference. Trivial mechanical fix; the precedent is what matters.

## Medium

### Q-4: Three near-identical HTTP handlers in `pkg/brokerhandlers` (handleSSHCert / handleTimePayload / handleTunnel)
**Location**: `pkg/brokerhandlers/handlers.go:165-373`
**Priority**: Medium
**Finding**: Each handler closes over its issuer + clientIP strategy, then runs
the same nine-step shape: (1) nil-issuer 501, (2) cap UserAgent, (3) resolve
sourceIP, (4) parse bearer with handler-denial-emit-on-missing, (5) JSON-decode
with DisallowUnknownFields and handler-denial-on-malformed, (6) trim + cap
DeviceID (and Nonce for time-payload), (7) stamp transport metadata on the
request, (8) dispatch to the issuer's Issue/OpenTunnel method, (9) sanity-check
the response and writeJSON. Only step 6 (which fields exist), step 8 (which
method to call), and the "issuer is not configured" / "returned empty" message
strings vary. ~200 lines of near-duplicate code, three near-identical 501
messages, three near-identical handler-denial-emit pairs.
**Recommendation**: Extract a generic handler builder
(`handleIssueEndpoint[Req, Resp any](issuer SomeIssuer, decodeAndNormalize func(*http.Request, Req) (Req, broker.HandlerDenial, error), dispatch func(ctx, Req) (Resp, error), label, emptyCheck func(Resp) bool)`).
The three handlers shrink to ~25 lines each, the message strings stay distinct,
and the deny-emit-on-pre-pipeline-failure invariant lives in one place.

### Q-5: Copy-paste bug — `handleTimePayload`'s 501 message says "ssh cert issuer is not configured"
**Location**: `pkg/brokerhandlers/handlers.go:246`
**Priority**: Medium
**Finding**: Direct symptom of Q-4. The time-payload handler's nil-issuer branch
emits `writeError(response, http.StatusNotImplemented, "ssh cert issuer is not configured")`.
The comment on the same line correctly says "matching handleSSHCert's parallel
branch" — but the parallel branch was copy-pasted with its hardcoded message.
An operator misconfiguring `TimePayloadIssuer` to nil hits /ssh/time-payload and
gets a misleading 501 pointing them at the cert issuer.
**Recommendation**: Change to `"time-payload issuer is not configured"`. Q-4's
helper would prevent this class of bug structurally (the label parameter is the
right place for the per-route string).

### Q-6: `verbosef` and tunnel-open Include warning still hardcode the `"postern:"` prefix; mint added another copy
**Location**: `pkg/cliapp/ssh.go:31`, `pkg/cliapp/tunnel_open.go:174`, `pkg/cliapp/mint.go:81`
**Priority**: Medium
**Finding**: The post-sweep audit's F-OQ2-M2 carried the `verbosef` hardcoded
"postern: " prefix forward; the tunneling phase compounded it with two new
hardcoded literals (`tunnel_open.go:174` and `mint.go:81`, both printing
`"postern: warning — Include line for %s is NOT in ~/.ssh/config..."`). The
mint.go copy is on a hot output path (every successful mint when a registered
device's Include is missing). `rt.binaryName` is available in both call sites;
neither uses it. A wrapper binary `acme-access` sees both literals leak through.
**Recommendation**: Thread `rt.binaryName` (or `verbosef`'s prefix) through. The
mint and tunnel_open warning lines are near-identical and should share a helper
(`warnMissingInclude(stderr, binaryName, sshConfPath, host)`); that helper also
becomes the natural place to do the binary-name substitution exactly once.

### Q-7: `ErrTunnelingThingNameFormatInvalid` defined twice in two packages with different message strings
**Location**: `internal/broker/tunnel.go:60` and `pkg/brokerhandlers/config.go:54`
**Priority**: Medium
**Finding**: The same conceptual error sentinel exists in two packages with
slightly different wording: broker says `"tunneling thing-name format must
contain exactly one {serial} placeholder"`; brokerhandlers says `"tunneling.thing_name_format
must contain exactly one {serial} placeholder"`. Each has its own
`strings.Count(format, "{serial}") != 1` check (one in `Config.Validate`, one in
`NewTunnelIssuer`). The doc-comments call this "defense-in-depth" but the two
errors don't share a sentinel identity — a caller doing `errors.Is(err,
broker.ErrTunnelingThingNameFormatInvalid)` won't match the brokerhandlers
version. Likewise `TunnelingThingNameSerialPlaceholder` constant in brokerhandlers
duplicates the unexported `tunnelSerialPlaceholder` in broker.
**Recommendation**: Pick one canonical home. Either (a) move the
constant + sentinel + the format-validation helper into `internal/broker` and
have `pkg/brokerhandlers/config.go` import it, or (b) accept that the broker
package validates at constructor time and remove the brokerhandlers-side check
(it's already enforced at construction). The "two errors, one concept" shape is
worse than either single-impl alternative.

### Q-8: `runTunneledSSH` and `runTunneledSCP` are near-identical functions; same for `resolveSSHCommandUser` / `resolveSCPCommandUser`
**Location**: `pkg/cliapp/ssh.go:163-182` ↔ `pkg/cliapp/scp.go:143-162`; `pkg/cliapp/ssh.go:141-155` ↔ `pkg/cliapp/scp.go:118-132`
**Priority**: Medium
**Finding**: A line-by-line diff of `runTunneledSSH` vs `runTunneledSCP` shows
they're effectively `s/SSH/SCP/g; s/sshUser/scpUser/g; s/buildTunneledSSHArgv/buildTunneledSCPArgv/g`.
Same for `resolveSSHCommandUser` vs `resolveSCPCommandUser` (only difference:
`skipDashL` flag passed to `passthroughHasUserInfo`). Both pairs were authored
in the tunneling phase; the duplication is fresh, not legacy. The argv-build
functions (`buildSSHArgv` / `buildSCPArgv` / `buildTunneledSSHArgv` /
`buildTunneledSCPArgv`) also share the same 7-line cert/identity option prefix.
**Recommendation**: Three small refactors: (a) unify `resolveSSHCommandUser` +
`resolveSCPCommandUser` into a single helper taking `skipDashL bool` (already
the only varying parameter passed through); (b) extract the common identity-options
prefix slice into a shared helper; (c) optionally fold `runTunneledSSH` /
`runTunneledSCP` into one parameterized helper that takes the argv-builder and
exec func, though the cobra-wiring shape may keep them readable as siblings.
The (a) win is mechanical and immediate.

### Q-9: Per-subcommand flag-name constants are duplicated three times (ssh/scp/tunnel)
**Location**: `pkg/cliapp/ssh.go:16-22`, `pkg/cliapp/scp.go:12-18`, `pkg/cliapp/tunnel_open.go:15-30`
**Priority**: Medium
**Finding**: `sshMaxLifetimeFlag = "max-lifetime"`, `scpMaxLifetimeFlag = "max-lifetime"`,
`tunnelOpenMaxLifetimeFlag = "max-lifetime"` — three constants with identical
string values. Likewise `sshRefreshFlag` / `scpRefreshFlag`, `sshTunnelFlag` /
`scpTunnelFlag`, `sshUserFlag` / `scpUserFlag` / `tunnelOpenUserFlag`,
`sshVerboseFlag` / `scpVerboseFlag` / `tunnelOpenVerboseFlag`. Each carries the
same description string in its `Flags().DurationVar/StringVar/BoolVar` call.
Eight string literals duplicated five times across the three subcommands.
**Recommendation**: One package-level block of canonical flag-name constants
(`FlagMaxLifetime`, `FlagRefresh`, `FlagTunnel`, `FlagUser`, `FlagVerbose`),
shared by all three subcommands. Descriptions stay per-subcommand if their
wording differs; the names are the load-bearing duplication.

### Q-10: `containsString` in securetunnel reinvents `slices.Contains`
**Location**: `internal/securetunnel/loops.go:314-321`
**Finding**: A six-line `containsString(list []string, target string) bool` at
the bottom of `loops.go`. Go floor is 1.24; `slices.Contains` covers this with
the same semantics. The new package shouldn't ship its own copy. (The
`pkg/cliapp/ssh_test.go:1010 contains` helper has the same problem with a
defensive comment "without the import dance for the older Go floor" that's no
longer true at Go 1.24.)
**Priority**: Medium
**Recommendation**: Delete `containsString`; replace `containsString(message.GetAvailableServiceIds(), s.serviceID)` at `loops.go:110` with `slices.Contains(message.GetAvailableServiceIds(), s.serviceID)`. Same for the test helper.

### Q-11: `SourceProxy.terminate` and `SourceProxy.Close` both walk-and-snapshot the streams map
**Location**: `internal/securetunnel/proxy.go:285-301` and `:308-334`
**Priority**: Medium
**Finding**: Close acquires `streamsMu`, copies the map into a slice, releases,
then iterates `closeStream(st, true)`. terminate (called from Close itself and
from error paths in `loops.go`) acquires `streamsMu` again, snapshots again,
then iterates a per-stream close via `closeOnce`. Two near-identical
snapshot-and-iterate blocks in adjacent methods, plus a third in `evictExistingStreams`
at `loops.go:253`. The patterns differ slightly (emit STREAM_RESET vs skip the
emit; use the public `closeStream` vs an inlined idempotent close) but the
snapshot logic is the same. The first iteration in Close (with `emitReset=true`)
also overlaps with terminate's iteration on the same path when Close calls
`terminate(nil)` — every stream's `closeOnce` has already fired once.
**Recommendation**: Extract a `snapshotStreams() []*stream` private helper. Then
each call site is one line, and the lifecycle is easier to reason about
("Close emits STREAM_RESET on the snapshot; terminate runs the idempotent
TCP-close on the snapshot").

### Q-12: `defaultExecSSH` and `defaultExecSCP` are byte-identical except for the argv label
**Location**: `pkg/cliapp/runtime.go:178-188` and `:333-343`
**Priority**: Medium
**Finding**: The two functions are line-for-line identical: validate argv non-empty
with a different error prefix, build `exec.CommandContext`, wire stdio, return
`cmd.Run()`. The only meaningful difference is the error-prefix string
(`"execSSH"` vs `"execSCP"`) and the type seam (`execSSHFunc` vs `execSCPFunc`).
The doc-comment on `defaultExecSCP` even says "Mirrors defaultExecSSH; kept
separate so the seam can be substituted independently" — the seam-distinction
is real (tests substitute them separately), but the implementations don't need
to be physically separate. The type-distinct seam can wrap a single
`defaultExecCommand(argv, label, stdin, stdout, stderr)`.
**Recommendation**: Extract one private helper; have both `defaultExecSSH` and
`defaultExecSCP` be one-line delegates that pass the label and conform to their
seam signature.

### Q-13: Include-presence warning lines in mint and tunnel-open share their structure but not a helper
**Location**: `pkg/cliapp/mint.go:79-84`, `pkg/cliapp/tunnel_open.go:172-177`, `pkg/cliapp/addhost.go:194-200`
**Priority**: Medium
**Finding**: Three sites print the same shape of stderr warning when
`checkIncludePresence(writer.Path())` returns false: a `postern: warning —
Include line for %s is NOT in ~/.ssh/config; \`ssh %s\` will fail\n  Add it with:
echo 'Include %s' >> ~/.ssh/config\n` template, with `displayIncludePath(writer.Path())`
substituted in. The wording is consistent — that's the point — but it's
hand-replicated three times. The fourth callsite (`runAddHostCheck`) emits a
slightly different shape (no "warning" prefix) for the explicit `--check` flag.
**Recommendation**: A small `warnMissingInclude(w io.Writer, binaryName, sshConfPath,
host string)` helper covers the three warn-shape callers; the engineer-facing
warning text lives in one place, the binary name (Q-6) gets threaded through
once, and a future copy-edit doesn't have to be applied three times.

### Q-14: Duplicated test fixture builders `newSSHTestRuntime` / `newSCPTestRuntime` (~35 lines each, near-identical)
**Location**: `pkg/cliapp/ssh_test.go:815-850` and `pkg/cliapp/scp_test.go:836-871`
**Priority**: Medium
**Finding**: Both build a runtime with: tmpdir cache, tmpdir ssh.conf, fresh
`mintTestCA`, `brokerRecorder`, fresh capture struct, profile resolver returning
the same fixed profile, access-token func returning `"access-token"`,
sshCertRequester wired through the recorder, openSSHConfWriter rooted at the
tmpdir ssh.conf. The only difference is `capture := &sshExecCapture{}` vs
`&scpExecCapture{}`, plus `rt.execSSH = capture.hook()` vs `rt.execSCP =
capture.hook()`. Substantial repeated test-fixture wiring that will continue to
duplicate as a third subcommand (tunnel, timefix) wants the same shape.
**Recommendation**: Extract a parameterized `newSubcommandTestRuntime(t, wireExec)`
that takes a function-of-runtime to bind the exec hook. The per-test-file
wrappers shrink to ~3 lines each (build the capture, call the shared helper,
return the trio).

## Low

### Q-15: `internal/broker/tunnel.go` (446 LoC) is the largest single file in `internal/broker` and bundles unrelated concerns
**Location**: `internal/broker/tunnel.go`
**Priority**: Low
**Finding**: One file holds: the const block (12h ceiling, 8h default, thing-name
placeholder), the `TunnelIssuerDeps`/`TunnelIssuer` types, `NewTunnelIssuer`,
the `OpenTunnel` pipeline (~140 LoC), four denial helpers (`tunnelDenialTemplate`,
`recordTunnelDenialFor`, `RecordTunnelHandlerDenial`, `recordTunnelDenial`),
`thingName`, the `TunnelingErrorClassifier` interface + `TunnelingErrorKind` enum,
plus `tunnelingDenyReason` and `mapTunnelingError`. `sshcert.go` has a similar
sprawl (435 LoC) but it's a more cohesive set; tunnel.go's classifier+kind
machinery for error routing feels separable from the pipeline. Reading the file
end-to-end is fine; jumping to a specific concern from a stack trace is harder
than `internal/broker/preamble.go`-sized files.
**Recommendation**: Optional split — move the `TunnelingErrorClassifier`
interface + `TunnelingErrorKind` + `tunnelingDenyReason` + `mapTunnelingError`
into `internal/broker/tunnel_errors.go` (~60 LoC). The pipeline file shrinks
to ~370 LoC; the error-classification surface is co-located with the
defense-in-depth seam the AWS impl uses. Not urgent.

### Q-16: `TruncateRunes` parameter `max` still shadows the Go 1.21+ builtin (carry-over)
**Location**: `internal/broker/runes.go:12`
**Priority**: Low
**Finding**: F-QUAL2-L1 from the post-sweep audit. Still open verbatim. Production-impact-zero
today but the shadow remains and the function has been moved to this file since
the original flag without the rename.
**Recommendation**: Same as the prior audit — rename to `limit` or `maxRunes`.
One-line change.

### Q-17: `sort.Slice`/`sort.Strings` legacy patterns still in production (carry-over F-QUAL2-L5)
**Location**: `internal/certcache/cache.go:276,311`, `internal/sshconf/writer.go:134`, `pkg/cliapp/profile.go:172`
**Priority**: Low
**Finding**: Four production sites still call `sort.Slice` / `sort.Strings`
where Go 1.21+ `slices.Sort` / `slices.SortFunc` would be idiomatic. Already
flagged in the post-sweep audit; carrying as backlog. Re-stated here only
because Q-10's `containsString` is the same class of legacy-stdlib pattern and
the two could be swept together.
**Recommendation**: Defer to the next sweep of legacy stdlib idioms; Q-10's
`slices.Contains` substitution is the natural anchor for that sweep.

### Q-18: Cache safety margin (`cacheHitSafetyMargin = 5 * time.Minute`) lives only in ssh.go but is conceptually shared
**Location**: `pkg/cliapp/ssh.go:14`
**Priority**: Low
**Finding**: The 5-minute safety margin is consumed by `ensureFreshCert` in
`certflow.go` and is implicitly the cache-reuse decision policy for both ssh and
scp. It's declared in `ssh.go` because that's where the cert-mint flow started,
but conceptually it belongs adjacent to `ensureFreshCert` (or in a new
`pkg/cliapp/cert.go`). Cosmetic; correctness-zero.
**Recommendation**: Move to `pkg/cliapp/certflow.go` alongside `ensureFreshCert`.
Doc-comment stays accurate; the const's home reflects its consumer.

### Q-19: `awsTunnelCeiling` (cliapp) and `MaxTunnelLifetimeMinutes` (broker) encode the same magic number in different units
**Location**: `pkg/cliapp/tunnel.go:30` (`12 * time.Hour`) and `internal/broker/tunnel.go:37` (`12 * 60`)
**Priority**: Low
**Finding**: Same hard ceiling expressed as `time.Duration` in cliapp and `int32`
minutes in broker. The CLI's ceiling check is a UX courtesy ("save a round-trip
to the broker"); the broker's is authoritative. The duplication is fine in
isolation, but the comment on `MaxTunnelLifetimeMinutes` says "broker re-enforces
it as the authoritative cap; client-side rejection is a UX courtesy" — the CLI's
constant has no symmetric reference back to the broker, so a future AWS quota
bump means two unsynced edits.
**Recommendation**: Either (a) have cliapp import the broker constant and derive
the duration (`time.Duration(broker.MaxTunnelLifetimeMinutes) * time.Minute`), or
(b) leave as-is but cross-reference each from the other's doc comment so a
future bump finds both. (a) is the cleaner option since both packages already
share the `internal/broker` import direction.

### Q-20: `tunnel_open.go`'s warning text duplicates `mint.go`'s phrasing but with subtly different output
**Location**: `pkg/cliapp/mint.go:79-84` vs `pkg/cliapp/tunnel_open.go:172-177`
**Priority**: Low
**Finding**: Sub-finding of Q-13. mint.go says "Include line for %s is NOT in
~/.ssh/config; \`ssh %s\` will fail"; tunnel_open.go says the same but with the
suffixed `<device>.tunnel` host. The texts are 95% identical with one
substitution; if Q-13's helper isn't extracted, future drift between the two
warnings is the predictable failure mode.
**Recommendation**: Subsumed by Q-13.

### Q-21: `cmd/postern/main.go` may be unaware of `--print-config` for broker; CLI-side equivalent absent (informational on observability) — verify scope
**Location**: scoping check only — `cmd/postern/main.go` vs `cmd/broker/main.go`
**Priority**: Low
**Finding**: Broker has `--print-config` for resolved-config debug; CLI doesn't.
Engineers debugging "which profile is postern using? what's the resolved broker
URL?" have no equivalent. The `postern configure` subcommand only edits, not
prints. Not a duplication finding per se; mentioning here because the asymmetry
in operator-side tooling between the two binaries is a quality observation
worth tracking. Not in scope for this lens — defer to product-overall audit
or specifically request from team.
**Recommendation**: No action this audit; flag for awareness.

## Informational

### Q-22: Test fixture `mintTestCA` + `marshalCertForTest` + `seedCachedCert` are well-factored despite heavy reuse
**Location**: `pkg/cliapp/mint_test.go:509`, `pkg/cliapp/ssh_test.go:856`, used across mint/ssh/scp/addhost/cache tests
**Priority**: Informational
**Finding**: The cross-test-file fixture sharing is good practice; the
`seedCachedCert(t, cacheDir, ca, device, validFor)` interface is small and the
helpers stay close to their primary consumers. The test-runtime construction is
where the duplication lives (Q-14), not in the cert/cache fixtures. Worth
noting that this part of the suite is already well-organized.

### Q-23: `internal/broker/preamble.go`'s SRP refactor is exemplary
**Location**: `internal/broker/preamble.go`
**Priority**: Informational
**Finding**: The `PipelineDeps`-on-method-receiver pattern with `verifyEngineer`
and `resolveDevice` is well-shaped. Each preamble returns a typed context + a
typed denial; per-endpoint vocabulary stays in the endpoint. The "audit
vocabulary collapses at preambles" comment is precisely the kind of explanatory
prose Rule 4 wants. Note this here because it's the opposite of Q-1's finding:
the preamble pattern is exactly the helper the issuer-denial quartet should be
following, and the model for resolving Q-1 already exists in the same file.

### Q-24: `pkg/cliapp/sshuser.go` is a model "one chokepoint" file
**Location**: `pkg/cliapp/sshuser.go`
**Priority**: Informational
**Finding**: The unified-user-resolution refactor produces a single 99-line file
with one exported helper (`resolveUser`) and one supporting parser
(`passthroughHasUserInfo`). The doc-comment explains the four-tier precedence,
the `explicit bool` contract, the `Profile.WithDefaults` non-injection rule, and
the load-bearing reason `"engineer"` isn't a sentinel. This is the shape Q-1
would adopt. Same package, same engineer-influenced design, so the refactor in
Q-1 is precedented in-house.

## Prior-pass items considered already-tracked vs ones I would elevate

**Already-tracked (not re-raised)**:
- F-OQ-M1 (operator cert missing `permit-port-forwarding`) — DESIGN-vs-code
  divergence, carried twice, not new this audit.
- F-OQ2-M2 (`verbosef` hardcoded prefix) — touched here only because
  Q-6 reports the tunneling-phase compounded the issue with two NEW hardcoded
  copies in mint and tunnel_open; the original carry-over remains.
- F-OQ2-M5 (`internal/logging` env unconditional `POSTERN_LOG_LEVEL`) — not new.
- F-OQ2-M6 / M7 (DESIGN.md timefix signature, DESIGN.md Options shape) — doc
  drift, not in this audit's lens.
- F-QUAL2-L1 (TruncateRunes `max` parameter shadow) — re-raised at Q-16 because
  it's truly trivial and a one-line cleanup is appropriate when nearby work
  touches the file.
- F-QUAL2-L5 (`sort.Slice` legacy patterns) — re-raised at Q-17 as the natural
  anchor for the Q-10 `containsString` sweep.

**Would elevate now if seen fresh**:
- Q-3 (CV-1 regression with 13 phase-ID leaks) reads to me as HIGH for sweep
  discipline — the post-sweep audit established and the post-timefix audit
  verified that production code had zero such references; the tunneling phase
  broke that invariant en masse, and the precedent the previous discipline set
  matters more than the words. Mechanical fix, but the message that
  process-vocab does not survive into production should be reasserted.
- Q-1 + Q-2 + Q-4 are the highest-value refactors. They're all "the tunneling
  phase tripled the parallel-implementation surface that the SRP split started"
  — three issuers, three brokerclient methods, three handlers. Each on its own
  is medium; the combined picture is "the third copy is the one where it
  becomes obvious a helper is needed."
- Q-5 (the 501 message copy-paste bug) is the proof point for Q-4: when there
  are three near-identical handlers, copy-paste bugs in messages stop being
  hypothetical.
