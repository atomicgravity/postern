# Quality / overall-product audit — post-sweep

## Scope

Second-pass catch-all audit after the `8eb0efd` sweep that landed against the prior `docs/audit-post-timefix/quality-overall.md` findings. This pass verifies closure of F-OQ-H1..H4 plus the F-OQ-M cluster, then re-walks the lenses the parallel auditors don't cover (wrapping-contract integrity, doc accuracy, test-coverage gaps, configuration surface, error/observability, build/release pipeline, backwards-compat hygiene, cross-platform readiness, dependency surface, phase-close + tunneling-phase-open hygiene). Findings the security / broker / Go-style / hand-rolled-vs-library audits naturally cover are deferred to them.

## Summary

The sweep closed the four prior HIGHs cleanly: Cedar starter ships `MintTimefixCert`, sshd drop-in uses `/usr/sbin/timefix-apply`, `AGENTS.md` reflects post-timefix reality, and `docs/team-handoff.md` promotes timefix to the closed-phases table and now leads with the tunneling phase. Tester baselines, architect log, and reviewer observations are all current. The "default deployment is broken at first `postern timefix`" cliff identified in the prior pass is no longer present.

The Medium tier moves less cleanly. Three of nine prior Mediums are still open verbatim (`verbosef`'s hardcoded `postern: ` prefix, `add-host` next-step text hardcoding `postern ssh` / `postern mint`, `internal/logging` reading `POSTERN_LOG_LEVEL` unconditionally) and visible to wrappers; one (operator cert missing `permit-port-forwarding`) is still open with the same diverged-from-DESIGN.md half-and-half status; two of nine have been addressed (timefix README two-line wire, Mode-const block merge); and three are doc-drift items (`DESIGN.md postern timefix` signature, `DESIGN.md cliapp.New(Options)` shape vs `Options` actual field set, `internal/broker/types.go` "not yet implemented" comment on `PrincipalTypeTimefix`) that remain because the sweep didn't touch DESIGN.md.

Fresh findings in this pass are concentrated in three areas:

- **Tunneling-phase-open hygiene**: `docs/team-handoff.md`'s "Last updated" header is dated 2026-05-13 but the body describes the 2026-05-14 lock; `docs/architect-log.md`'s top banner still says "TN-A ready to dispatch — awaiting user review", while the spec is locked. Neither is wrong materially but the dating is sloppy enough to confuse a returning agent. Spec §2 #11 cross-references a file-line (`pkg/brokerhandlers/config.go:153`), which AGENTS.md doc-style rules explicitly forbid.
- **Build/release**: `cmd/timefix-set-clock`'s linux-only nature is documented but the Makefile happily builds it on macOS (and ships a no-op fallback), which works but the resulting bin is non-functional and there's no warning. The release notes / CHANGELOG for `v0.10.0` and below have no mention of the timefix landing.
- **`cliapp.Options` surface drift vs DESIGN.md**: DESIGN.md continues to describe an `Options` carrying upgrade-source URL and certificate-identity pattern — neither field exists on the actual struct. The `upgrade` subcommand is also still a placeholder. Wrappers planning their integration against the doc will write code that doesn't compile.

**Severity counts:** HIGH 0 · MEDIUM 8 · LOW 11 · INFO 5

## Prior-pass closure status

| id | finding | status | evidence |
|---|---|---|---|
| F-OQ-H1 | Cedar starter missing `MintTimefixCert` | **CLOSED** | `terraform/postern-broker/cedar/schema.json` declares both actions; `terraform/postern-broker/cedar/starter.cedar` permits both with explanatory comment naming the recovery-flow dependency. |
| F-OQ-H2 | `examples/on-device/sshd/postern.conf` `ForceCommand` path wrong | **CLOSED** | The drop-in's `Match User timefix` block now points at `/usr/sbin/timefix-apply` and the preamble comment block lists the install paths matching the recipe. |
| F-OQ-H3 | `AGENTS.md` timefix stale | **CLOSED** | Lead paragraph names the timefix path as landed; current-status section names the broker time-payload endpoint as implemented; `cmd/timefix-apply/` + `cmd/timefix-set-clock/` rows say "Done; closed in the timefix phase 2026-05-13". `examples/on-device/timefix/` is listed alongside `examples/on-device/sshd/`. Current-phase line names tunneling. |
| F-OQ-H4 | `docs/team-handoff.md` stale | **CLOSED** | §3 lists the timefix phase as completed with the LD-67..LD-91 / invariants O–S range; §4 leads with the tunneling phase; §6 reference index includes both the closed timefix spec and the open tunneling spec. (The "Last updated" header still reads 2026-05-13 while the body describes 2026-05-14 events — see F-OQ2-M3.) |
| F-OQ-M1 | Operator cert missing `permit-port-forwarding` | **OPEN** | `internal/broker/sshcert.go` `buildOperatorCert` extensions = `{"permit-pty": ""}`; sshd README still claims `-L` debug tunnels work; DESIGN.md still specifies `permit-pty, permit-port-forwarding`. No movement. Re-raised here as F-OQ2-M1 (same severity). |
| F-OQ-M2 | `verbosef` hardcodes `postern:` prefix | **OPEN** | `pkg/cliapp/ssh.go` `verbosef` line: `fmt.Fprintln(cmd.ErrOrStderr(), "postern: "+...)`. 10 call sites including 5 in the verbose-by-default `pkg/cliapp/timefix.go` flow. Re-raised as F-OQ2-M2. |
| F-OQ-M3 | `add-host` summary hardcodes `postern ssh` / `postern mint` | **OPEN** | `pkg/cliapp/addhost.go` `writeAddHostSummary` — both `printf` templates still embed `postern ssh %s` / `postern mint %s` literals. Re-raised as F-OQ2-M4. |
| F-OQ-M4 | `internal/logging` env var unconditional | **OPEN** | `internal/logging/logging.go` const `EnvLogLevel = "POSTERN_LOG_LEVEL"`, `Configure()` takes no binary-name arg. Re-raised as F-OQ2-M5. |
| F-OQ-M5 | DESIGN.md `postern timefix` signature drift | **OPEN** | `DESIGN.md` §"`postern timefix <device-id> [<host>] [--tunnel]`" — `[<host>]` was never implemented; `--tunnel` is reserved on `ssh`/`scp`, never on `timefix`. README is correct; DESIGN.md isn't. Re-raised as F-OQ2-M6. |
| F-OQ-M6 | DESIGN.md `cliapp.Run()` + upgrade-source params on `Options` | **OPEN** | `pkg/cliapp/app.go` `Options` has BinaryName/ConfigPath/LookupEnv/Stdout/Stderr/Version — no upgrade-URL field, no certificate-identity field; `cliapp.Run()` doesn't exist; `cliapp.New` returns `*cobra.Command`. DESIGN.md §"Distribution" and §"Wrapping" still describe both. Re-raised as F-OQ2-M7. |
| F-OQ-M7 | timefix README single-line stdout claim | **CLOSED** | The "Verifying end-to-end" tail now explicitly describes the two-line emit (nonce + `device-clock: <RFC3339>`) and names the engineer-facing diagnostic purpose. |
| F-OQ-M8 | Mode-const split + stale "not yet implemented" comment | **PARTIAL** | The two Mode const blocks have been merged into one in `internal/broker/types.go`. The "Timefix is reserved for the on-device clock-fix path (not yet implemented)" parenthetical on `PrincipalTypeTimefix`'s doc comment still survives — `internal/broker/types.go` lines 14-20. Re-raised at lower severity as F-OQ2-L1. |
| F-OQ-M9 | `internal/version/version.go` cross-ref to DESIGN.md "release process" | **OPEN** | Doc comment unchanged: "see the release process in DESIGN.md". DESIGN.md has §"Updates and release pipeline" but no section named "release process". Re-raised at LOW as F-OQ2-L2. |
| F-OQ-L1 | `slog.Error(..., "error", err)` bare K=V at three sites | **OPEN** | `cmd/broker/main.go:38` `slog.Error("broker exited", "error", err)`; `cmd/broker-lambda/main.go:33` `slog.Error("broker-lambda init failed", "error", err)`. Both still use the bare-K=V shape. Re-raised at LOW as F-OQ2-L3. |
| F-OQ-L2 | `--version` for broker binaries | **OPEN** | Neither `cmd/broker/main.go` nor `cmd/broker-lambda/main.go` reads `internal/version` or surfaces a `--version` flag / startup log line. Re-raised as F-OQ2-L4. |
| F-OQ-L3 | nonce-shape constant duplicated | **OPEN** | `pkg/cliapp/timefix.go` `timefixNonceDecodedBytes = 32` ↔ `internal/broker/issuetimepayload.go`. Already reviewer-tracked (obs 22). Deferred. |
| F-OQ-L4 | timefix README hardcoded 2025 timestamp | **OPEN** | Still `sudo -u timefix /usr/sbin/timefix-set-clock 1747000000` in the verifying-end-to-end section. Already reviewer-tracked (obs 18). Deferred. |
| F-OQ-L5 | `verify.go` two `invariant [A-Z]` letter-refs | **CLOSED** | Architect log LD-85 names the orchestrator-applied inline patch that swept both refs; CV-1 footprint = 0 in production code per the reviewer-observations updated footprint accounting. |
| F-OQ-L6 | `internal/version` mutable vars | **OPEN** | No comment added. Trivial, defer. Not re-raised. |
| F-OQ-L7 | 501 paths log-silent on misconfiguration | **OPEN** | `pkg/brokerhandlers/handlers.go` `handleSSHCert` + `handleTimePayload` both write 501 without an operator-side `slog.Error` when `issuer == nil`. Not re-raised (informational; the `/healthz` 503 still gates traffic). |
| F-OQ-L8 | `/ssh/tunnel` unimplemented audit-silent | **OPEN** | `pkg/brokerhandlers/handlers.go` `unimplementedHandler` returns 501 with no `slog` line. Scheduled to land in TN-A per spec. Deferred to phase. |
| F-OQ-I1 | principals-init script not yet authored | **OPEN** | AGENTS.md confirms it's a known gap; nothing changed. Deferred. |
| F-OQ-I2 | `TunnelingConfig` plumbed-but-unused | **OPEN** | Same posture; tunneling-phase spec consumes the field at TN-A. Deferred. |
| F-OQ-I3 | tester-baselines format diverges per phase | **OPEN** | TF-A through TF-D close entries still appended in dense-paragraph shape; no "current baseline at HEAD" section yet. Deferred. |
| F-OQ-I4 | `realclientip-go` v1.0.0 maintenance state | **OPEN** | Dep still at v1.0.0; no CVE surfaced. Deferred. |

## High

(none — the four prior HIGHs are closed; nothing this pass surfaced rises to HIGH.)

## Medium

### F-OQ2-M1 — Operator cert missing `permit-port-forwarding` (carried)
**Location**: `internal/broker/sshcert.go` `buildOperatorCert` Extensions = `{"permit-pty": ""}`; `internal/broker/sshcert_test.go` `TestIssueSSHCertHappyPath` asserts `len(cert.Extensions) == 1`; DESIGN.md §"Operator cert (real shell)"; `examples/on-device/sshd/README.md` claims `-L` debug tunnels work.
**Finding**: DESIGN.md still specifies `permit-pty, permit-port-forwarding` and the sshd drop-in still tells engineers "Local port forwards allowed (so engineers can `-L` a debug HTTP/UI on the device back to their laptop)." Cert still ships `permit-pty` only. OpenSSH refuses local port forwarding via a cert that doesn't carry `permit-port-forwarding` regardless of `AllowTcpForwarding local`. The sshd drop-in's `Match User engineer` block was edited in the sweep to enable `AllowAgentForwarding yes` (which on its own won't fail without the cert extension) but the cert-side missing extension still gates `-L` workflows.
**Impact**: A documented engineer workflow (local port forwarding via `-L`) is broken at the cert level on the unwrapped path. VSCode-Remote-SSH's editor channel is not blocked. Same shape as the prior F-OQ-M1; left open through the sweep.
**Recommendation**: Pick one: (a) align code+test with DESIGN.md by adding `permit-port-forwarding` (and possibly explicitly omitting `permit-agent-forwarding` and `permit-X11-forwarding`); (b) update DESIGN.md and the sshd README to say v1 ships cert-only without `permit-port-forwarding`. Current state is half-and-half on both sides of the contract.

### F-OQ2-M2 — `verbosef` still hardcodes `"postern:"` prefix (carried)
**Location**: `pkg/cliapp/ssh.go` `verbosef` — `fmt.Fprintln(cmd.ErrOrStderr(), "postern: "+fmt.Sprintf(format, a...))`. Ten call sites across `ssh.go` / `scp.go` / `certflow.go` / `timefix.go`; the timefix subcommand is verbose-by-default so a wrapper engineer sees `postern: ...` lines on every recovery invocation.
**Finding**: Unchanged from the prior pass. The runtime carries `binaryName`; the helper doesn't take it.
**Impact**: Wrapper-rename leaks the framework brand into the default stderr stream on the recovery flow. Mechanical fix.
**Recommendation**: Thread `rt.binaryName` into `verbosef` (e.g. take `rt` instead of `cmd`, or accept a separate prefix param). Same fix shape the prior pass recommended.

### F-OQ2-M3 — `docs/team-handoff.md` "Last updated" still dated 2026-05-13 while body describes the 2026-05-14 tunneling lock
**Location**: `docs/team-handoff.md` header `**Last updated:** 2026-05-13, tunneling spec landed (draft), OQ-TN-1..5 awaiting user disposition.`
**Finding**: §1 banner says "Current phase: tunneling — locked 2026-05-14, TN-A ready to dispatch." with the 2026-05-14 OQ closures inline. The "Last updated" line under it still reads 2026-05-13 and "awaiting user disposition." Inconsistent within the same doc; agents that read the "Last updated" line as the source of truth for staleness will incorrectly conclude the OQs are open.
**Impact**: Returning-agent orientation friction. Doesn't change any code, but the file is the entry point for phased-delivery agents.
**Recommendation**: Bump the "Last updated" line to 2026-05-14 and replace "awaiting user disposition" with "OQ-TN-1..5 resolved 2026-05-14". One-line edit.

### F-OQ2-M4 — `postern add-host` next-steps still embed `postern` literal (carried)
**Location**: `pkg/cliapp/addhost.go` `writeAddHostSummary` — both `Fprintf` templates render `postern ssh %s` and `postern mint %s`.
**Finding**: Same as F-OQ-M3 from the prior pass; not addressed by the sweep. `rt.binaryName` is available; it isn't plumbed through.
**Impact**: Wrapper-renamed binary surfaces wrong next-step commands. Mechanical fix.
**Recommendation**: Pass `rt.binaryName` into `writeAddHostSummary` and substitute it for the two `postern` literals.

### F-OQ2-M5 — `internal/logging` env var unconditionally `POSTERN_LOG_LEVEL` (carried)
**Location**: `internal/logging/logging.go` `const EnvLogLevel = "POSTERN_LOG_LEVEL"`; consumed unchanged by `cmd/broker/main.go`, `cmd/broker-lambda/main.go`, `cmd/postern/main.go`.
**Finding**: Unchanged. Every other env override in the CLI uses `EnvPrefixForBinaryName`; log-level is the lone holdout.
**Impact**: Wrappers extending the CLI inherit the framework-branded env var for log-level control.
**Recommendation**: Same as prior pass — accept a `binaryName` (or prefix) arg on `logging.Configure()`; default to `POSTERN` so the upstream unwrapped binaries don't change. Broker side can stay `POSTERN` (no binary-name story on the broker today).

### F-OQ2-M6 — DESIGN.md `postern timefix` signature still drifts from implementation (carried)
**Location**: `DESIGN.md` §"`postern timefix <device-id> [<host>] [--tunnel]`" heading lists `[<host>]` (never implemented) and `[--tunnel]` (not in the timefix surface).
**Finding**: Unchanged. The README under §"Day-to-day commands" has the correct `postern timefix <device> [--ip <addr>] [--quiet]` row; DESIGN.md keeps the original signature.
**Impact**: Doc drift on the engineer-facing entry point. README is authoritative for the engineer; DESIGN.md is authoritative for design rationale, so the divergence isn't catastrophic — but it means the design doc is no longer trustworthy as the authoritative architecture per AGENTS.md §"Workflow rules" ("If code disagrees with the doc, decide which is right and update the loser").
**Recommendation**: Update DESIGN.md to `postern timefix <device-id> [--ip <addr>] [--quiet]`. Per AGENTS.md doc-style rules, drop the bracketed-positional notation and describe flag semantics in prose.

### F-OQ2-M7 — DESIGN.md describes `Options` carrying upgrade-source URL + certificate-identity regex; struct has neither (carried)
**Location**: `DESIGN.md` §"Distribution" — "`cliapp.New(Options{...})` accepts the upgrade-source URL and the expected certificate-identity pattern (regex matching their CI workflow URL) as fields on the `Options` struct"; `DESIGN.md` §"Wrapping" — "Wrappers extending the config with their own fields wrap or embed `cliapp.Config` in a wrapper-side struct and pass the embedded value through to `cliapp.New(Options{...})`."  
Actual struct in `pkg/cliapp/app.go`: `Options { BinaryName; ConfigPath; LookupEnv; Stdout; Stderr; Version }`. No upgrade-URL, no certificate-identity field; `cliapp.Config` is a Profiles map and is not embedded in `Options`.
**Finding**: The sweep noted in `docs/audit-post-timefix/quality-overall.md` flagged this; the sweep correctly resolved the `cliapp.Run()` mention (DESIGN.md now says `cliapp.New(Options{...})`) but the upgrade-URL + certificate-identity field claim survives. The wrapping section's "embed `cliapp.Config` in a wrapper-side struct and pass the embedded value through to `cliapp.New(Options{...})`" describes an embedding pattern the API doesn't support — `Options` doesn't take a `Config` value.
**Impact**: Wrapper authors planning their integration from DESIGN.md write code against an API that doesn't exist. Compiles fail; they reverse-engineer the package and discover the real surface.
**Recommendation**: Rewrite both DESIGN.md paragraphs to describe the actual `Options` shape (BinaryName / ConfigPath / LookupEnv / Stdout / Stderr / Version) and the actual config wiring path (wrappers populate `Config` literally and resolve it themselves — there is no `Config`-on-`Options` plumbing). For the upgrade-URL story, either acknowledge "deferred to the `postern upgrade` phase" or add the fields to `Options` as part of that phase.

### F-OQ2-M8 — Tunneling spec violates AGENTS.md doc-style rule against file:line cross-refs
**Location**: `docs/phases/tunneling/spec.md` §2 #1 ("at `pkg/brokerhandlers/handlers.go:108`"), #4 ("at `pkg/cliapp/ssh.go:74` and `pkg/cliapp/scp.go:57`"), §2 #10 ("`terraform/postern-broker/iam.tf`"), §2 #11 ("at `pkg/brokerhandlers/config.go:153`"); §4 D1 ("internal/broker"), D6 ("`internal/broker/sshcert.go`", "`internal/broker/issuetimepayload.go`"), D9 (`buildOperatorCert`/`buildTimefixCert` named directly), D13 ("`internal/oauthlogin`"), D14 ("`internal/brokerclient.RequestTimePayload`"), D15 ("`coder/websocket.Accept`").
**Finding**: AGENTS.md §"Doc style rules" says "Don't reference specific filenames or line numbers in the design doc. Describe components, behaviors, and boundaries by name. The code can change locations; the design shouldn't depend on file paths." The rule is scoped to DESIGN.md by the section heading, but the same principle clearly applies to spec docs — they're meant to outlive the file layout. The tunneling spec is the most filename/line-number-dense doc in the repo, with `pkg/brokerhandlers/handlers.go:108`, `pkg/brokerhandlers/config.go:153`, `pkg/cliapp/ssh.go:74`, `pkg/cliapp/scp.go:57` all listed as load-bearing anchors. The timefix spec (closed) has the same pattern but at least it's now a historical artifact; the tunneling spec is the live working document for the next 5 sub-phases.
**Impact**: Five sub-phases of refactoring TN-A → TN-E will continually fight the spec's stale line numbers as the codebase shifts. Reviewers chasing "where did the deny-on-disabled-tunneling 501 go?" hit `:108` and find different code. The spec is authoritative for the phase; treating it as such requires that it stay accurate.
**Recommendation**: Either scope the AGENTS.md doc-style rule explicitly to DESIGN.md (and tolerate file:line in phase specs) or strip the line numbers from the tunneling spec before TN-A dispatches. Stripping is cheaper than keeping them current across 5 sub-phases of refactoring. Names alone (`pkg/brokerhandlers.New`'s 501 stub mount, `pkg/cliapp/ssh.go`'s `ErrTunnelNotImplemented` return) are enough to find the code.

## Low

### F-OQ2-L1 — Stale "not yet implemented" parenthetical on `PrincipalTypeTimefix` doc comment
**Location**: `internal/broker/types.go` — the PrincipalType doc-comment block before the const declaration reads "Operator is the engineer-SSH path; Timefix is reserved for the on-device clock-fix path (not yet implemented)."
**Finding**: The Mode-const block merge from F-OQ-M8 happened in the sweep; the "not yet implemented" comment for `PrincipalTypeTimefix` didn't. The TF-E phase closure made the timefix path live; the comment now lies.
**Recommendation**: Drop the "(not yet implemented)" parenthetical; replace with a one-line description of the path (e.g. "Timefix is the on-device clock-fix path; the broker mints a 1979→3000-valid cert with a force-command critical option pinning the device-side verifier"). One-line edit.

### F-OQ2-L2 — `internal/version` doc-comment cross-references a non-existent DESIGN.md section
**Location**: `internal/version/version.go` doc comment: "see the release process in DESIGN.md for how these are populated."
**Finding**: Same as prior F-OQ-M9. DESIGN.md has §"Updates and release pipeline" and §"Distribution" but no section named "release process."
**Recommendation**: Either remove the cross-reference, or rename it: "see `.goreleaser.yaml` and `DESIGN.md` §Updates and release pipeline".

### F-OQ2-L3 — Broker `main.go` slog uses bare K=V form at two sites (carried)
**Location**: `cmd/broker/main.go:38` `slog.Error("broker exited", "error", err)`; `cmd/broker-lambda/main.go:33` `slog.Error("broker-lambda init failed", "error", err)`.
**Finding**: Unchanged from prior pass. The rest of the codebase uses `slog.String("err", err.Error())`. Two outliers.
**Recommendation**: Convert to `slog.String("err", err.Error())`. Non-blocking; one-commit cleanup.

### F-OQ2-L4 — Broker binaries don't surface their version (carried)
**Location**: `cmd/broker/main.go`, `cmd/broker-lambda/main.go` — neither reads `internal/version`.
**Finding**: Unchanged from prior pass. ldflags-injected version data exists in the binary but is unused.
**Recommendation**: Add `--version` flag to `cmd/broker`; add `slog.Info("broker-lambda starting", "version", version.Version, ...)` at init in `cmd/broker-lambda`.

### F-OQ2-L5 — `docs/architect-log.md` top banner says "TN-A ready to dispatch... awaiting user review" while the spec is locked
**Location**: `docs/architect-log.md` line 3 — "Current phase: tunneling — TN-A ready to dispatch. Spec at `docs/phases/tunneling/spec.md` (draft, awaiting user review 2026-05-13)."
**Finding**: Per the spec file header ("locked 2026-05-14, TN-A ready to dispatch") and LD-92..LD-99 entries in the same architect-log.md (each dated 2026-05-14 with the OQ resolutions inlined), the spec is no longer in "awaiting user review" status. The banner pre-dates the OQ-TN-1 resolution that flipped D6 from "rename" to "split."
**Recommendation**: Update the architect-log banner to "Current phase: tunneling — locked 2026-05-14, TN-A ready to dispatch. Spec at `docs/phases/tunneling/spec.md`. OQ-TN-1..5 resolved."

### F-OQ2-L6 — `cmd/timefix-set-clock` builds on macOS but produces a non-functional binary; no warning at build or run
**Location**: `Makefile` `build` target unconditionally builds all four `cmd/*` binaries on whatever platform; `cmd/timefix-set-clock/syscalls_other.go` returns `errUnsupportedPlatform` from both seams.
**Finding**: A developer on macOS running `make build` gets `bin/timefix-set-clock` that exits non-zero at runtime with `unsupported platform`. Useful for compile-check (the goal per reviewer-obs C.1 + LD-85). But the binary's mere existence in `bin/` could mislead someone tarballing the directory for distribution. Compare with `.goreleaser.yaml`: it correctly only declares linux/amd64+arm64 for the on-device pair — the asymmetry between Makefile (builds everywhere) and goreleaser (linux-only) is the right asymmetry but the Makefile could note it.
**Recommendation**: Add a one-line comment block above the `build:` target naming that the on-device pair is dev-time-only on non-Linux ("Linux-only on-device binaries — non-Linux builds produce a stub that exits with unsupported-platform error on first call"). Or split the on-device pair into a separate `make build-on-device` target that gates on `GOOS=linux`. Non-blocking; today's behavior is documented in reviewer-observations + the source files but not at the build entry point.

### F-OQ2-L7 — Release CHANGELOG entries for the timefix phase don't exist
**Location**: `CHANGELOG.md` — most recent release `v0.10.0` is the terraform `module_version` output; no entries describe the timefix landing (TF-A through TF-E, LD-67..LD-91).
**Finding**: The timefix phase landed end-to-end (TF-A 2026-05-13 onward) but the conventional-commits-driven CHANGELOG has no `feat: postern timefix subcommand` / `feat: on-device verifier and setter` entries. Either the commits during the phase didn't use `feat:` / `fix:` prefixes that release-please picks up, or they were squashed into commits that didn't make the cut. Operators reading the GitHub Releases page on `v0.10.0` find a single terraform-only line and no signal that the broker now mints time-payloads.
**Impact**: Engineers downloading the latest tag don't see "timefix" mentioned at all in the release notes. The framework just gained its third major capability and the public-facing changelog is silent.
**Recommendation**: When the next release-please PR opens, manually add a `## v0.10.x` (or v0.11.0) entry summarizing the timefix landing — broker `/ssh/time-payload`, `postern timefix` subcommand, on-device pair, `examples/on-device/timefix/`. Forward-looking: ensure tunneling-phase commits use `feat:` / `fix:` prefixes that release-please picks up correctly.

### F-OQ2-L8 — `docs/team-handoff.md` v1 product gaps list is incomplete after the tunneling-phase open
**Location**: `docs/team-handoff.md` §4 "v1 product gaps remaining after tunneling" — lists only `postern upgrade`.
**Finding**: After tunneling closes, two more items remain that DESIGN.md describes but the team-handoff doesn't enumerate: (a) the `principals-init` sample script at `examples/on-device/principals-init/` (called out in AGENTS.md status block — "principals-init script + other on-device packaging samples not yet authored"), (b) `SECURITY.md` (README.md §"Contributing" says "A `SECURITY.md` disclosure process will land before v1; until then, please use GitHub's private vulnerability reporting"). Neither is large but both are v1 ship-list items.
**Recommendation**: Extend §4's "v1 product gaps remaining after tunneling" subsection with the two items so a returning agent has the full picture.

### F-OQ2-L9 — Tunneling spec scope item #11 cross-references file:line that may shift before TN-A
**Location**: `docs/phases/tunneling/spec.md` §2 #11 — "The `TunnelingConfig.IOTRegion` field already exists in `pkg/brokerhandlers/config.go:153`".
**Finding**: Subset of F-OQ2-M8 worth calling out separately because it pins a numeric line that's particularly brittle (config.go is right in the middle of the file; a single field addition above line 153 shifts the cross-reference). The pinned line currently matches (`config.go:153` is the `TunnelingConfig` struct opening brace) but the spec will date itself fast.
**Recommendation**: Same as F-OQ2-M8; replace with "in `pkg/brokerhandlers/config.go`'s `TunnelingConfig` struct" without the line number.

### F-OQ2-L10 — Test suite has no test for `cliapp.Options.Stdout/Stderr` redirect plumbing across subcommands
**Location**: `pkg/cliapp/app_test.go` covers basic invocation; per-subcommand tests use their own bound `*bytes.Buffer` rather than going through `Options.Stdout/Stderr`.
**Finding**: The `Options.Stdout/Stderr` plumbing per `pkg/cliapp/app.go:42-49` is wrapper-facing but never exercised end-to-end in tests. A wrapper passing `bytes.Buffer` in their main.go relies on the contract; nothing protects it against accidental breakage during a future refactor of the cobra root setup.
**Recommendation**: A single `TestOptionsStreamRedirect` that calls `cliapp.New(cliapp.Options{Stdout: &buf, Stderr: &buf})`, runs a known-output subcommand (e.g. `version`), and asserts the buffer captured the output. Non-blocking; the contract is small.

### F-OQ2-L11 — `cmd/timefix-apply` binary won't run on Windows engineer hosts even for testing
**Location**: `cmd/timefix-apply/main.go` + `syscalls_other.go` shape — verifier is Linux-only because `cmd/timefix-set-clock` exec is Linux-only (and `exec`/syscall-based on the verifier's end). Goreleaser correctly produces linux-only artifacts.
**Finding**: A Windows-host engineer wanting to dry-run-validate a captured JWS for diagnostics has no path — they can compile `cmd/timefix-apply` but the dependency on linux-specific paths (`/etc/ssh/postern_ca.pub`) and the setter-exec target means even the verify-only path effectively requires linux. The goreleaser config knows it; the README doesn't say so explicitly.
**Recommendation**: One-line note on the `examples/on-device/timefix/README.md` or top-level `README.md` saying the timefix verifier/setter pair is linux-only by design (matches the existing reviewer-obs disposition). Non-urgent; nobody is asking for Windows on-device.

## Info

### F-OQ2-I1 — Tunneling spec's `Tunneling` interface name collides with the existing `TunnelingConfig` shape
**Location**: `docs/phases/tunneling/spec.md` §2 #2 declares the new abstraction as `internal/broker.Tunneling`; `pkg/brokerhandlers.TunnelingConfig` already exists. Distinct types, related-but-not-identical names.
**Finding**: When TN-A lands, code reviewers will encounter two `Tunneling*` things — `TunnelingConfig` (broker config struct) and `Tunneling` (abstraction interface). Likely fine in practice (different packages, different responsibilities) but worth knowing about.
**Recommendation**: No action; flag for awareness. If TN-A engineer wants to disambiguate, the abstraction could be named `Tunneler` (verb-form, matches `Signer`, `Auditor`-shaped names) — but the spec locks `Tunneling`, and matching the verb-naming pattern of `Signer`/`Audit`/`Registry`/`Policy` is fine.

### F-OQ2-I2 — `internal/broker/types.go` `Mode` constants are bare `string` rather than a named `Mode` type
**Location**: `internal/broker/types.go` `const (ModeOperator = "operator"; ModeTimefix = "timefix")`. No `type Mode string` declaration; the consts are untyped string literals.
**Finding**: Inconsistent with `PrincipalType` (which has a named type) and with the tunneling spec's intent to add `ModeTunnel` (third arm). Adding a typed `Mode` now would tighten the signature of the future `mode` parameter on the AVPPolicy switch (`func (p *AVPPolicy) actionForMode(mode broker.Mode) string`).
**Recommendation**: Defer to the tunneling-phase TN-A engineer; cheap to fold into the mode-extension work. Not worth a pre-phase commit on its own.

### F-OQ2-I3 — `docs/team-handoff.md` §4 carries a "2026-05-13 audit backlog" subsection naming `docs/audit-2026-05-13/`
**Location**: `docs/team-handoff.md` §4 "**2026-05-13 audit backlog:**" — names the 5-lens audit, 163 findings, 8 High closed same-day.
**Finding**: Accurate. But the post-timefix audit (this audit's first pass) at `docs/audit-post-timefix/` is now also a backlog entry — 4 HIGH + 9 MEDIUM + 8 LOW + 4 INFO with closure status — and isn't referenced in §4. The handoff doc's tunneling-phase-spec cross-reference is the carryover from the architect-log; the audit cross-references aren't.
**Recommendation**: Add a "**2026-05-13 audit-post-timefix backlog:**" subsection citing `docs/audit-post-timefix/SUMMARY.md` (or the per-lens files) so a returning agent finds the full audit history. Trivial.

### F-OQ2-I4 — Test baselines doc still has flake registry table with one empty row
**Location**: `docs/tester-baselines.md` "Flake registry" table at the tail — has a header row and one blank data row.
**Finding**: Aesthetic. Markdown table rendering shows the blank row as an empty cell; not a defect.
**Recommendation**: Drop the empty row and add "(none recorded)" below the header instead. Or leave it as a placeholder for the first flake to be added. Either is fine.

### F-OQ2-I5 — `cliapp.Options.Version` field shape is `VersionInfo` struct, but `cliapp.New` always falls back to `currentVersionInfo()` when zero-valued
**Location**: `pkg/cliapp/app.go` `Options.Version` of type `VersionInfo`; `New` does `if versionInfo == (VersionInfo{}) { versionInfo = currentVersionInfo() }`. A wrapper passing a partial `VersionInfo` (e.g., only `Version: "1.2.3"` but leaving Commit / Date empty) gets the partial value through `normalizeVersionInfo`, which substitutes "unknown" for the empty fields — but a wrapper passing `VersionInfo{}` (all fields empty) gets the upstream `internal/version` values rather than three "unknown" strings.
**Finding**: Edge case in the zero-value semantics; almost certainly intentional ("wrappers that pass nothing get the upstream defaults; wrappers that pass anything get exactly what they passed, with `normalizeVersionInfo` filling in `unknown` for empties") but the contract isn't documented.
**Recommendation**: One-sentence comment on `Options.Version` naming the behavior. Non-blocking.

## Methodology

- Re-read AGENTS.md, DESIGN.md, README.md, team-handoff.md against the post-sweep commit.
- Re-walked all 25 prior findings in `docs/audit-post-timefix/quality-overall.md`; classified each as CLOSED / PARTIAL / OPEN / DEFERRED with file-level evidence.
- Read both the closed-timefix and open-tunneling phase specs end-to-end; cross-checked architect-log LD entries (LD-67 through LD-99) against spec status claims.
- Audited the wrapping contract: `pkg/cliapp` Options + Config exports, `pkg/brokerhandlers` Deps + handler types, `internal/broker` abstractions all walked for surface drift since the sweep.
- Audited the build/release pipeline (`.goreleaser.yaml`, `Makefile`, `.github/workflows/{test,release}.yml`, `CHANGELOG.md`) for cross-platform readiness, version surfacing, release-note continuity.
- Did NOT re-audit dimensions the other lenses own: security-broker pipeline (broker-deep audit), Go-style conventions (style audit), hand-rolled vs library choices (hand-rolled-vs-library audit), AVP/Cedar semantics (security audit), runtime correctness (correctness audit).
- Read-only pass; no files outside the named report path were modified.
