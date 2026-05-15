# Quality / overall-product audit — post-timefix

## Scope

Catch-all "is this product solid?" lens. Covers wrapping-contract integrity, doc accuracy, test-coverage gaps, configuration surface, error/observability, build/release pipeline, backwards-compat hygiene, cross-platform readiness, dependency surface, and phase-close hygiene. Findings the parallel security / broker / Go-style / hand-rolled-vs-library audits naturally cover are deferred to them.

## Summary

The timefix phase shipped clean code; the integration was reviewed and ratified, tests are green (`go test -race ./...` passes top-to-bottom), and the CV-1 (phase-identifier) sweep is at zero in production. The big quality holes are **doc / paper-trail drift around a closed phase that hasn't propagated to the framework-level docs**, and **the unwrapped product's end-to-end story for `postern timefix` is not actually green out-of-the-box on the reference Terraform deployment** — two upstream gaps stop it before the first successful run.

Two HIGH findings stop an unwrapped operator dead on `postern timefix`:

- The bundled reference Cedar schema has no `MintTimefixCert` action (or starter policy permitting it), so even a perfectly-deployed timefix path returns `authorization_denied`.
- The reference `examples/on-device/sshd/postern.conf` drop-in points `ForceCommand` at `/usr/local/sbin/timefix-apply` while every other doc, the broker's force-command cert critical option, and the install README all say `/usr/sbin/timefix-apply`.

A third HIGH: `AGENTS.md` and `docs/team-handoff.md` are stale enough to mislead any returning agent — they still describe timefix as "not yet built" / "TF-A ready to dispatch" while the phase has been closed end-to-end (TF-A through TF-E, LD-67 through LD-91 all ratified in `docs/architect-log.md`).

A real but lower-severity functional gap: the operator cert is minted with only `permit-pty` in `Permissions.Extensions`, but `DESIGN.md` § "Operator cert (real shell)" specifies `permit-pty, permit-port-forwarding` and the bundled sshd drop-in allows `AllowTcpForwarding local` precisely so engineers can `-L` debug tunnels. Without `permit-port-forwarding` on the cert, OpenSSH refuses `-L` regardless of sshd config — so the README's "VSCode-Remote-SSH / `-L` debug tunnel" workflow won't work end-to-end for fresh operators.

The rest of the findings are MEDIUM doc / wrapping-contract leaks, plus an assortment of LOW / INFO observations the parallel auditors aren't likely to surface.

**Severity counts:** HIGH 4 · MEDIUM 9 · LOW 8 · INFO 4

## High

### F-OQ-H1 — Default AVP schema and starter Cedar policy don't authorize `MintTimefixCert`
**Location**: `terraform/postern-broker/cedar/schema.json` (no `MintTimefixCert` action declared), `terraform/postern-broker/cedar/starter.cedar` (only `MintOperatorCert` permit).
**Finding**: `internal/policy/avp.go` dispatches `ModeTimefix → Postern::Action::"MintTimefixCert"`, but the bundled Terraform Cedar schema declares only `MintOperatorCert` under `Postern.actions`. AVP's STRICT validation rejects any operator-side policy that references an action not in the schema, and the starter policy only permits `MintOperatorCert`. An unwrapped operator running the reference `examples/terraform/deployment/` and immediately trying `postern timefix <device>` will hit `authorization_denied` on every invocation — and won't be able to fix it without editing the bundled schema first.
**Impact**: The framework's headline "broken-clock recovery" feature is non-functional on a default deployment of the framework's own reference Terraform. Operators have no signal that the schema needs to be extended; the broker emits `time_payload_denied authorization_denied` with no hint pointing at the Cedar schema gap.
**Recommendation**: Add `MintTimefixCert` to `terraform/postern-broker/cedar/schema.json` (same `appliesTo` shape as `MintOperatorCert`); extend `terraform/postern-broker/cedar/starter.cedar` with a parallel permit on the timefix action (or document explicitly that the starter is operator-only and operators must add the timefix permit themselves). Update `terraform/postern-broker/variables.tf` description for `avp_schema_json` / `avp_install_starter_policy` to mention timefix.

### F-OQ-H2 — `examples/on-device/sshd/postern.conf` `ForceCommand` path disagrees with verifier install path
**Location**: `examples/on-device/sshd/postern.conf:23` and `:80` (both reference `/usr/local/sbin/timefix-apply`); every other site uses `/usr/sbin/timefix-apply` (verifier source `cmd/timefix-apply/main.go:47`, broker cert force-command `internal/broker/sshcert.go:32`, install README `examples/on-device/timefix/README.md:41`, DESIGN.md `§/usr/sbin/timefix-apply` (multiple), the timefix-apply package docstring).
**Finding**: An operator dropping in the bundled `postern.conf` as-is gets `ForceCommand /usr/local/sbin/timefix-apply` while the install recipe installs the binary at `/usr/sbin/timefix-apply`. sshd will try to exec the wrong path and the timefix session immediately fails. The cert's `force-command=/usr/sbin/timefix-apply` critical option provides defense-in-depth if the sshd `ForceCommand` is missing, but here the cert and sshd ForceCommand fight each other (cert says one path; sshd says another).
**Impact**: Reference sshd drop-in is wired to a path the install recipe doesn't write to. Operator hits a broken timefix path on first use; the symptom is "sshd: No such file" not "Postern timefix recovery failed in some discoverable way".
**Recommendation**: Change both `postern.conf` references from `/usr/local/sbin/` to `/usr/sbin/` so they match every other site.

### F-OQ-H3 — `AGENTS.md` is stale: still describes timefix as not-yet-built
**Location**: `AGENTS.md:7`, `:135-139`, `:143`.
**Finding**: Multiple critical claims are out of date:
- L7 still says "The on-device timefix path, secure-tunneling source proxy, and the `timefix` + `upgrade` CLI subcommands remain to land." The timefix path is fully landed (CLI, broker endpoint, verifier, setter, integration test).
- L7 lists CLI subcommands as `login, mint, ssh, scp, add-host, remove-host, cache, logout, configure, version` — missing `timefix`.
- L135 says `/ssh/time-payload` is a 501 stub. It is a fully-implemented endpoint (`internal/broker/issuetimepayload.go`).
- L137 says `timefix` is a placeholder. The handler at `pkg/cliapp/timefix.go` is the full real implementation.
- L138-139 say `cmd/timefix-apply/` and `cmd/timefix-set-clock/` are "Not yet built". They are built, tested, and goreleaser-cross-compiled.
- L143 lists `examples/on-device/sshd/` as the only on-device sample; `examples/on-device/timefix/` (TF-C deliverable) is missing.
**Impact**: A returning agent reads `AGENTS.md` as authoritative orientation. Stale claims of "not yet built" steer agents toward duplicating finished work.
**Recommendation**: Refresh the status parens to current reality. The timefix-phase punch list is also entirely closed; remove it from open-work claims.

### F-OQ-H4 — `docs/team-handoff.md` says "TF-A ready to dispatch" while spec is `CLOSED`
**Location**: `docs/team-handoff.md:3,5,7`; cross-ref `docs/phases/timefix/spec.md:3` (status: CLOSED 2026-05-13).
**Finding**: The handoff doc's top banner says "Current phase: timefix — TF-A ready to dispatch" and §4 still lists `cmd/timefix-apply/`, `cmd/timefix-set-clock/`, `/ssh/time-payload`, and `postern timefix` as open v1 product gaps. Per the spec file, all five sub-phases TF-A through TF-E shipped, with LD-67 through LD-91 ratified in `docs/architect-log.md`. The "Last updated" line still reads "2026-05-13, timefix spec locked, open questions resolved, TF-A ready" — pre-phase-close.
**Impact**: Same as F-OQ-H3 (returning agent confusion). Coupled because `team-handoff.md` is the file the spec instructs agents to consult for current state.
**Recommendation**: Promote the timefix phase to the §3 closed-phases table; clear the timefix entries from §4 open-work list; refresh §4 to focus on the remaining v1 gaps (tunneling source proxy, `/ssh/tunnel`, `postern upgrade`); re-anchor the test-baseline numbers to the post-TF-E count (already captured in `tester-baselines.md`).

## Medium

### F-OQ-M1 — Operator cert missing `permit-port-forwarding` extension; bundled sshd drop-in and README assume it works
**Location**: `internal/broker/sshcert.go:394-398` (`Extensions: map[string]string{"permit-pty": ""}`); `internal/broker/sshcert_test.go:67-68` (test enforces extensions == `permit-pty` only); `DESIGN.md:148`; `examples/on-device/sshd/postern.conf:66-70` and `examples/on-device/sshd/README.md:13` (claim `-L` works); `README.md:67-68` (`ssh device-1234` + VSCode Remote-SSH workflow).
**Finding**: `DESIGN.md` § "Operator cert (real shell)" specifies `Cert extensions: permit-pty, permit-port-forwarding — sshd constrains forwarding to local forwarding; no agent-forwarding, no X11`. The minted cert only carries `permit-pty`. OpenSSH refuses local port forwarding via a cert that doesn't carry `permit-port-forwarding` regardless of sshd's `AllowTcpForwarding local`. The sshd drop-in README explicitly tells engineers "Local port forwards allowed (so engineers can `-L` a debug HTTP/UI on the device back to their laptop)" — that workflow currently won't work end-to-end on a freshly deployed system.
**Impact**: A documented engineer workflow (local port forwarding via `-L`) is broken at the cert level. VSCode Remote-SSH itself does not use port forwarding for the editor channel, so the README's VSCode claim is probably fine — but any `-L`-using engineer workflow is gated by this. Test at `sshcert_test.go:67` actively enforces the truncated shape, so this is a deliberate divergence from DESIGN rather than an oversight.
**Recommendation**: Either (a) align code+test with DESIGN.md by adding `permit-port-forwarding` to the operator cert extensions (and possibly explicitly omitting `permit-agent-forwarding` and `permit-X11-forwarding`); or (b) update DESIGN.md and the sshd README to acknowledge that v1 ships cert-only without `permit-port-forwarding` and that `-L` workflows aren't supported. Pick one; the current half-and-half state breaks both invariants.

### F-OQ-M2 — `verbosef` hardcodes `"postern:"` prefix in CLI stderr lines
**Location**: `pkg/cliapp/ssh.go:23-31`.
**Finding**: The `verbosef` helper writes `"postern: "+fmt.Sprintf(...)` regardless of the wrapper's `BinaryName`. Used by `pkg/cliapp/ssh.go`, `pkg/cliapp/certflow.go`, `pkg/cliapp/timefix.go` for verbose/progress output. A wrapper binary named `acme-access` will print lines like `postern: minting cert for ...` from the wrapper's own progress output.
**Impact**: Wrapping-contract leak. The verbose-by-default timefix subcommand emits this on every recovery invocation, so the leak is no longer hidden behind a `-v` flag — it's the default user experience for the recovery flow.
**Recommendation**: Thread `rt.binaryName` into `verbosef` (e.g. `verbosef(cmd *cobra.Command, binaryName string, verbose bool, format string, ...)`) or attach the prefix at the `runtime` constructor. The function is small and centralized, so the fix is mechanical.

### F-OQ-M3 — `postern add-host` summary hardcodes `postern ssh` / `postern mint` in user-facing next-steps
**Location**: `pkg/cliapp/addhost.go:143-158`.
**Finding**: After a successful `add-host`, the summary prints:
```
Then mint a cert and connect:
  postern ssh %s              # mints on first use, then execs ssh
  # or: postern mint %s       # mints only; subsequent `ssh %s` works until cert expiry
```
The two `postern` literals don't honor the wrapper's `BinaryName`. The `runtime.binaryName` is available; it just isn't plumbed into `writeAddHostSummary`.
**Impact**: Wrapper-renamed binary surfaces wrong next-step commands. An engineer running `acme-access add-host` is told to run `postern ssh` which doesn't exist.
**Recommendation**: Pass `rt.binaryName` into `writeAddHostSummary` and substitute it for the two literals.

### F-OQ-M4 — `internal/logging` env var is unconditionally `POSTERN_LOG_LEVEL`
**Location**: `internal/logging/logging.go:16`.
**Finding**: All three binaries (`cmd/broker`, `cmd/broker-lambda`, `cmd/postern`) call `logging.Configure()` which reads `os.Getenv("POSTERN_LOG_LEVEL")`. Every other env override in the CLI uses `EnvPrefixForBinaryName` (`POSTERN_PROFILE`, `POSTERN_BROKER`, etc., each per-wrapper). `POSTERN_LOG_LEVEL` is the lone holdout.
**Impact**: Wrappers extending the CLI inherit the framework-branded env var for log-level control. Wrapper docs would have to say "set `POSTERN_LOG_LEVEL`" inside an `acme-access` distribution, which contradicts the rest of the env-prefix story.
**Recommendation**: Accept a `binaryName` (or prefix) param on `logging.Configure()`; default to `POSTERN` so the upstream unwrapped binaries don't change. Wrapper main.go threads its binary name. The broker side is harder because `cmd/broker` doesn't have a binary-name concept the way the CLI does — but the same shape works: `logging.Configure("postern")` upstream, wrappers pass their own value.

### F-OQ-M5 — DESIGN.md `postern timefix` signature drifts from implementation
**Location**: `DESIGN.md:702` lists `postern timefix <device-id> [<host>] [--tunnel]`; actual flag set is `<device-id> [--ip <addr>] [--quiet]` per `pkg/cliapp/timefix.go:56-67` and `README.md:85`.
**Finding**: The DESIGN signature predates D13 (`--ip`) and D15 (`--quiet`); it lists `[<host>]` (never implemented) and `[--tunnel]` (not in the timefix surface — tunneling is reserved on `ssh`/`scp` only).
**Impact**: Doc-vs-code drift on the engineer-facing entry point. README is correct; DESIGN isn't.
**Recommendation**: Update DESIGN.md L702 to match the shipped flag set. Per AGENTS.md doc-style rules, the doc shouldn't reference file/line specifics, so just state the flag semantics: `postern timefix <device-id> [--ip <addr>] [--quiet]`.

### F-OQ-M6 — DESIGN.md references `cliapp.Run()` and constructor params that don't exist
**Location**: `DESIGN.md:1086` references `cliapp.Run()` accepting an "upgrade-source URL and the expected certificate-identity pattern (regex matching their CI workflow URL) as constructor params"; `DESIGN.md:1104` references passing an embedded `cliapp.Config` to `cliapp.Run()`; the codebase only exposes `cliapp.New(Options)` and `Options` has no upgrade-URL or certificate-identity fields.
**Finding**: The DESIGN section "Branding and wrapping pattern" describes a wrapping API the code hasn't built yet — `cliapp.Run()`, an embedded `Config`, upgrade-source params. The CLI has `cliapp.New(Options{...})` returning a `*cobra.Command` for the caller to dispatch, and the upgrade subcommand is a placeholder.
**Impact**: A wrapper author reading DESIGN.md to plan their integration will write code against an API that doesn't exist. Compiles will fail; they'll re-read the package and discover the actual surface.
**Recommendation**: Either rewrite the DESIGN paragraph to describe `cliapp.New(Options{...})` (the real API) and remove the `cliapp.Run()` and upgrade-param speculation, or add a marginal "(planned for v1.x; v1 ships `cliapp.New(Options{...})` returning *cobra.Command for caller-side execute)" disclaimer.

### F-OQ-M7 — `examples/on-device/timefix/README.md` doesn't mention the new two-line stdout protocol
**Location**: `examples/on-device/timefix/README.md:78` describes the verifier as "emits the nonce to stdout (you'll see one base64url-encoded line in sshd's debug log if `LogLevel VERBOSE` is set...)".
**Finding**: D14/LD-88 changed the verifier's stdout to emit **two** lines (nonce, then `device-clock: <RFC3339>`). The install README still describes a single line. Operators tracing a timefix invocation in sshd's verbose logs will see two lines and may assume the second is a protocol violation.
**Impact**: Minor doc inaccuracy on a recently-changed protocol detail. Doesn't break anything but confuses sshd-log-walkers.
**Recommendation**: Update the §"Verifying end-to-end" paragraph to mention the two-line emit and the `device-clock:` prefix as part of the verifier protocol.

### F-OQ-M8 — `internal/broker/types.go` Mode-const split + stale "Timefix is reserved... not yet implemented" comment
**Location**: `internal/broker/types.go:16-21` ("Timefix is reserved for the on-device clock-fix path (not yet implemented)"), `:26-28` (`ModeOperator` block), `:116-118` (separate `ModeTimefix` block added in TF-A).
**Finding**: The `PrincipalTypeTimefix` doc says "not yet implemented" but the full cert-mint timefix branch exists at `internal/broker/sshcert.go:411-425`. `ModeOperator` and `ModeTimefix` live in separate const blocks at lines 26-28 and 116-118 — a visible scar from TF-A growing the broker. Other adjacent constant groups (PrincipalType, Event*, DenyReason*, PolicyAction*) live in single blocks.
**Impact**: Stale comment misleads readers; split const blocks confuse `grep`-walking the Mode enum.
**Recommendation**: Drop the "not yet implemented" parenthetical; merge the two Mode blocks into one with a single doc comment. The Go-style audit may also raise this — defer if so.

### F-OQ-M9 — `internal/version/version.go` doc comment references a DESIGN.md "release process" section that doesn't exist
**Location**: `internal/version/version.go:2-3` ("see the release process in DESIGN.md for how these are populated").
**Finding**: `DESIGN.md` has §"Updates and release pipeline" (around line 1074) but no "release process" section by that name. The ldflags injection details are split between DESIGN's release-pipeline paragraphs and `.goreleaser.yaml` itself; the version.go pointer is approximate.
**Impact**: Cross-reference is fuzzy; reader following the breadcrumb has to grep.
**Recommendation**: Either remove the cross-reference or rename it: "see `.goreleaser.yaml` and `DESIGN.md` §Updates and release pipeline".

## Low

### F-OQ-L1 — `cmd/broker/main.go` `slog.Error("broker exited", "error", err)` uses bare K=V; rest of codebase uses `slog.String(...)`
**Location**: `cmd/broker/main.go:38`, `cmd/broker-lambda/main.go:33`, `internal/broker/preamble.go:123`.
**Finding**: Three slog call sites use bare key-value variadic form (`"error", err`) while the rest of `internal/broker/*.go` uses typed `slog.String`/`slog.Int`/etc. forms. Both work; consistency would be a minor readability win.
**Recommendation**: Convert the three sites to `slog.String("err", err.Error())` for consistency. Non-blocking; the Go-style auditor may surface this independently.

### F-OQ-L2 — `cmd/broker-lambda/main.go` and `cmd/broker/main.go` don't expose `--version`
**Location**: Both binary entry points.
**Finding**: The CLI threads `internal/version.{Version, Commit, Date}` through cliapp into a `--version` flag and `postern version` subcommand. The broker binaries don't surface their version. `goreleaser` builds inject ldflags for the broker too, so the data is present but unused.
**Impact**: Operators investigating a deployed broker have no `broker --version`; they have to rely on artifact filenames or container metadata. Mild operational friction.
**Recommendation**: Add a `--version` flag mode to `cmd/broker/main.go` and the equivalent log line at startup for `cmd/broker-lambda/main.go` (Lambda doesn't have a `--version` invocation path, but a single `slog.Info("broker-lambda starting", "version", version.Version, ...)` line at init makes the version visible in CloudWatch). Reuse `internal/version.{Version,Commit,Date}`. Trivial.

### F-OQ-L3 — `pkg/cliapp/timefix.go` `validateTimefixNonce` duplicates the broker's 32-byte-base64url check
**Location**: `pkg/cliapp/timefix.go:233-249`; broker side at `internal/broker/issuetimepayload.go:53`.
**Finding**: Both the CLI and the broker enforce "nonce decodes to exactly 32 bytes via base64url". The CLI side catches a malformed device-emitted nonce locally (saving a broker round-trip on a clearly-broken device); the broker check is the canonical one. Already flagged in reviewer-observations obs 22 as future cleanup.
**Impact**: Future protocol change to 64-byte nonces would require both sides to be updated. Today the constant is duplicated (32 in each file).
**Recommendation**: Reviewer obs 22 already tracks this; consider hoisting the constant into `internal/brokerwire` or a shared package. Non-urgent.

### F-OQ-L4 — `examples/on-device/timefix/README.md` "Verifying end-to-end" uses a hardcoded 2025-vintage timestamp
**Location**: `examples/on-device/timefix/README.md:71` (`sudo -u timefix /usr/sbin/timefix-set-clock 1747000000` — i.e. 2025-05-11).
**Finding**: Reviewer obs 18 already flagged this. Using `$(date +%s)` instead of a hardcoded value avoids advancing a correct clock backward to 2025. Doc-polish; reviewer-tracked.
**Recommendation**: Adopt the reviewer's `$(date +%s)` suggestion in the next docs touch.

### F-OQ-L5 — `cmd/timefix-apply/verify.go` retains two `invariant [A-Z]` letter-refs
**Location**: `cmd/timefix-apply/verify.go` (specifically the comments reviewer obs 28 lists: ~line 66 "invariant-P purposes" and ~line 178-179 "per invariant R forward-compat rule").
**Finding**: The CV-1 sweep is complete for LD-X / D-X / TF-X / OQ-TF references in production code. Two `invariant [A-Z]` letter-refs survived (reviewer-flagged at obs 28). Spec §8 success criterion #16 reads as "production-code reference count = 0"; depending on strict-vs-loose interpretation, these two count.
**Recommendation**: One-commit cleanup (already noted in reviewer obs 28); inline the underlying property rather than indirecting through the letter ref. Non-blocking.

### F-OQ-L6 — `internal/version/version.go` plain-`var` defaults can be overwritten by callers
**Location**: `internal/version/version.go:8-12`.
**Finding**: `Version`, `Commit`, `Date` are package-level `var` declarations specifically so ldflags can write them at link time. Any importer of `internal/version` could also overwrite them at runtime. The package is `internal/` so the blast radius is just the postern monorepo, and ldflags injection is the documented mechanism, so this isn't a defect — just worth a one-line note that the package-level mutability is intentional.
**Recommendation**: Add a one-line "// Mutability is intentional: ldflags writes these at link time; runtime callers should not." Non-blocking.

### F-OQ-L7 — Broker handler 501 paths for `nil SSHCertIssuer` are auditless by design but emit no operator log line either
**Location**: `pkg/brokerhandlers/handlers.go:147-155` (handleSSHCert), `:221-230` (handleTimePayload).
**Finding**: When `deps.SSHCertIssuer == nil`, the handler writes a 501 response and returns. The comment says "auditless on purpose" (engineer identity not yet established). No `slog.Warn` or `slog.Error` either — an operator running a misconfigured broker sees only the 501 status in access logs with no in-process signal that the wrapping is broken. Health check side fails closed (returns 503 via `handleHealthz`), which surfaces the wiring gap; but a wrapper that mounts only `handleSSHCert` without `handleHealthz` would have no log signal at all.
**Recommendation**: One-line `slog.Error("ssh cert issuer not configured", ...)` in each branch before the 501. The deps-nil branch should never fire in production; logging it makes the misconfiguration loud. Non-blocking.

### F-OQ-L8 — `pkg/brokerhandlers/handlers.go` `unimplementedHandler` for `/ssh/tunnel` has no audit / log emit either
**Location**: `pkg/brokerhandlers/handlers.go:284-286`.
**Finding**: `/ssh/tunnel` is mounted via `mux.HandleFunc("/ssh/tunnel", unimplementedHandler)` and returns 501 without any audit emit, any rate-limit consumption, or any operator-side log. An attacker can send unauthenticated probe traffic at `/ssh/tunnel` and the broker silently 501s. The cert and time-payload endpoints both run their pre-invocation `RecordHandlerDenial` audit emit on missing bearer; `/ssh/tunnel` doesn't.
**Impact**: When the tunneling endpoint lands, the audit-coverage invariant will need to extend to cover its pre-invocation path. Today the gap is benign (auth still rejects unauthenticated tunnel traffic the moment the real endpoint lands), but pre-landing parity would be cheap to set up.
**Recommendation**: Defer to when the `/ssh/tunnel` endpoint actually lands; document the expectation in the same place as the audit invariant for the other endpoints. INFO-class rather than fix-now.

## Info

### F-OQ-I1 — `examples/on-device/sshd/postern.conf` is the only on-device sample wired to `sshd_config.d/*.conf` includes; `principals-init` script not yet authored
**Location**: AGENTS.md L143 acknowledges the principals-init script is missing; DESIGN.md §"Principals-init systemd unit" specifies the shape. `examples/on-device/timefix/` lists `principals-init` writes as a prerequisite.
**Finding**: An operator following the on-device install end-to-end needs to author the principals-init script themselves from DESIGN.md. The bash steps are simple but not packaged. Tracked as a known gap in the AGENTS.md status list; not new.
**Recommendation**: Author the `examples/on-device/principals-init/` sample (~30 LoC bash + systemd unit + README) when the timefix on-device path gets its next docs polish. Closes a small but real onboarding rough edge.

### F-OQ-I2 — `internal/broker/types.go` `TunnelingConfig` parsed and validated but never consumed
**Location**: `pkg/brokerhandlers/config.go:147-156` (struct definition), `internal/brokerwire/wire.go` (no consumer).
**Finding**: Config schema includes `tunneling.iot_region` and env override `POSTERN_TUNNELING_IOT_REGION` even though the tunneling source proxy isn't built. Plumbed-but-unused; the comment on the struct calls this out explicitly ("Parsed and normalized today but not yet wired into the broker pipeline... published ahead so operator config files don't have to change when the impl lands"). Deliberate design choice; flag for awareness.
**Recommendation**: No action. Documented intent.

### F-OQ-I3 — Test baseline file format diverges across phase appends
**Location**: `docs/tester-baselines.md` last 5 sections (TF-A, TF-B, TF-C, TF-D close entries plus engineer-CLI baseline).
**Finding**: Each phase appends a dense single-paragraph close entry with embedded telemetry. The shape works but the doc is no longer scannable as "current baseline at a glance". Tester audit would have to scroll to L11 to find "this is the TF-D close" and L7 to find "the at-rest 281/279 baseline is from 2026-05-12". A pre-section "Current baseline at HEAD" summary line on top of the close-by-close history would help.
**Recommendation**: When the next phase opens, prepend a "Current baseline" section that's just the most recent close numbers; keep the per-phase telemetry below. INFO-class style nit.

### F-OQ-I4 — `realclientip-go` dep at v1.0.0 with no recent upstream activity
**Location**: `go.mod:18` (`github.com/realclientip/realclientip-go v1.0.0`).
**Finding**: The package is at v1.0.0 (Jan 2023 release). It's a small focused library doing trusted-proxy XFF parsing; the API is stable and the code is straightforward. No defect, but it's the kind of dep where the security audit might flag the maintenance state.
**Recommendation**: No action; defer to whichever audit lens picks dependency surface (likely the hand-rolled-vs-library or security audit). Flag if a CVE surfaces.

## Cross-references

- Reviewer observations forward-looking obs 28 (CV-1 invariant-letter residue) and obs 22 (nonce-shape constant duplication) cover items in F-OQ-L3 and F-OQ-L5 — no need to double-track.
- The Go-style audit's findings on slog-style consistency and the const-block split likely overlap F-OQ-L1 and F-OQ-M8 — defer to that audit's findings for the canonical write-up; this audit flags them for completeness.
- The hand-rolled-vs-library audit may cover `realclientip-go` (F-OQ-I4) and the verifier's library-on-both-sides JWS path (LD-90/-91 implementation, not flagged here as that lens owns it).
- The security audits cover the cert-extension threat-model side of F-OQ-M1 if applicable; this audit raised it under the doc-drift / unwrapped-end-to-end-product lens.
