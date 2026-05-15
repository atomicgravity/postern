# Team Handoff — Postern

> **Tunneling phase closed 2026-05-14 with TN-E.** All six sub-phases TN-A through TN-F landed; LD-92 through LD-118 locked; invariants T..W in force. The framework's firewalled-device path is complete end-to-end: broker `/ssh/tunnel` endpoint, pure-Go AWS V3 source proxy, three engineer-facing entry points (`postern ssh --tunnel`, `postern scp --tunnel`, `postern tunnel`), AVP `OpenTunnel` Cedar action, three new audit event types, Terraform IAM + env-var wiring gated by `tunneling_enabled`, on-device packaging guidance at `examples/on-device/secure-tunnel/`. Spec at `docs/phases/tunneling/spec.md` (left in place per the timefix-phase precedent; no archive directory). **Next**: `postern upgrade` (signed-release fetch subcommand) — likely the next phase.
>
> Prior state: Timefix phase closed 2026-05-13. Engineer-CLI phase closed 2026-05-12.

**Last updated:** 2026-05-14, TN-E closed (tunneling phase closed).

## §1. How to use this doc

Project follows the `phased-delivery` skill at `/Users/ttarhan/.claude/skills/phased-delivery/`. When work resumes inside a formal phase (multi-agent gated delivery), archive these state files to `docs/archive/<phase>/` and re-initialize empty ones at `docs/` root. Lightweight 1:1 work (single-agent, no gate) appends here and to `architect-log.md` directly; no archive step.

## §2. Project context

Postern is an Apache-2.0 Go OSS framework for SSH access to embedded Linux device fleets.

- **Architecture:** `DESIGN.md` (authoritative)
- **Agent operating constraints:** `CLAUDE.md`
- **Code:** `cmd/`, `internal/`, `pkg/`
- **Terraform module:** `terraform/postern-broker/` (consumed by `examples/terraform/deployment/` for a directly-deployable apply)
- **Examples:** `examples/terraform/cognito/`

## §3. Completed phases / increments

| Phase / increment | Archive | Outcome |
|---|---|---|
| Cleanup phase | `docs/archive/cleanup-phase/` | 6 sub-phases, LD-1 through LD-18, 23 reviewer observations |
| Style sweep | (no archive — commit `8f33c7d`) | 5 user Go-style rules applied |
| Impl-pass | `docs/archive/impl-pass/` | 5 sub-phases A–E, LD-19 through LD-22, 12 reviewer observations |
| P3 phase | `docs/archive/p3/` | 2 sub-phases, LD-23/24, invariants K/L, 7 reviewer observations |
| OAuth2 phase | `docs/archive/oauth2/` | Single sub-phase, invariant M (PKCE), 3 reviewer observations |
| Pass-4 closeout | `docs/archive/p4/` | LD-25, F1/F6/F8 |
| AWS deployment | `docs/archive/aws-deployment/` | 1:1 work, LD-26/27/28, invariant N |
| Engineer-CLI phase | `docs/archive/engineer-cli/` | 6 sub-phases A–F, LD-29 through LD-53, 20 reviewer observations |
| **Timefix phase** | `docs/phases/timefix/spec.md` (closed in place; no archive) | **5 sub-phases TF-A–TF-E, LD-67 through LD-91, invariants O–S, full broken-clock recovery path end-to-end** |
| **Tunneling phase** | `docs/phases/tunneling/spec.md` (closed in place; no archive) | **6 sub-phases TN-A–TN-F, LD-92 through LD-118, invariants T–W, full firewalled-device recovery path end-to-end (broker `/ssh/tunnel` + pure-Go AWS V3 source proxy + 3 engineer entry points + Terraform IAM)** |

**Test baseline at rest:** 587 RUN / 0 FAIL / 2 SKIP under `make check` (551 untagged + 36 tagged at tunneling-phase close, 2026-05-14 TN-E). Two pre-existing env-gated SKIPs (`TestConfiguredIDPAccessTokenProviderIntegration`, `TestKeychainIntegration`).

**Locked decisions in force:** LD-1 through LD-53 + invariants A through N. All archived; not re-litigated.

## §4. What's open / suggested next

**Active item: `postern upgrade` subcommand.** Tunneling phase closed 2026-05-14 with TN-E. The remaining v1 product gap is the engineer CLI's `postern upgrade` placeholder — signed release fetch per DESIGN.md: `postern upgrade` fetches signed release artifacts from Postern's GitHub Releases (hardcoded URL), verifies via Sigstore — cosign-keyless signature on `checksums.txt` checked against the Postern repo's GitHub Actions OIDC identity, with Rekor inclusion proof. Decoupled from broker per AGENTS.md §"Updates are decoupled from the broker". Likely the next phase to open.

**v1 product gaps remaining:**

- **`postern upgrade`** — see active item above. Placeholder remains in `pkg/cliapp/`; signed-release fetch + Sigstore verify still to land.

**Closed in the engineer-CLI phase:**

- Local cert/key cache (`internal/certcache`) — atomic per-profile-shared-key + per-device-cert model.
- `postern mint` primitive (LD-32, LD-36 verb-of-action semantics).
- `postern ssh` real implementation replacing the debug stub (LD-29, LD-33, LD-34, LD-36).
- `postern scp` real implementation, same shape as ssh.
- `postern add-host` + Postern-managed `~/.postern/ssh.conf` writer (`internal/sshconf`) (LD-31, EC-2 manual-Include-only).
- `postern remove-host`.
- `postern cache ls` + `postern cache prune`.
- Three duplication-extraction sweeps: `internal/atomicfile`, `pkg/cliapp/paths.go` (binary-name path derivation), `pkg/cliapp/sshuser.go` (default-user resolution).

**Deferred (with seed artifacts):**

- **SSH agent mode** — pre-phase spike at `docs/spikes/ssh-agent-mode.md` with §12 deferral decision. Exec mode + cache + ssh_config Include covers the daily workflow including VSCode-remote at much smaller v1 surface; agent-mode wins are incremental (in-memory keys + auto-refresh) and additive. OQ-AGENT-1 through OQ-AGENT-4 carry to a future v1.x agent-mode phase.

**Tunneling enhancements (post-v1, opportunistic):**

- **Broker-side `CloseTunnel` on engineer ^C, with tag-based ownership.** Today tunnels age out at the configured TTL (default 8h) when the engineer ^Cs `postern tunnel`; the AWS tunnel record lingers but no live data path exists. A clean close is achievable without broker-side state by tagging the tunnel at OpenTunnel time with `postern:engineer_sub=<sub>` and verifying the tag on Close via `iot:DescribeTunnel`. Stateless on the broker; AWS holds the ownership metadata. Cost: new endpoint (~50 LoC), Cedar action `CloseTunnel`, IAM grants for `iot:DescribeTunnel`/`iot:CloseTunnel`/`iot:TagResource`, CLI signal handler tracking `tunnel_id`, new audit event pair. Bonus: tags make "which engineer opened tunnel X" answerable from AWS console alone.
- **Tunnel-mode SSH host-key TOFU.** `postern ssh --tunnel` and `postern tunnel` currently inject `NoHostAuthenticationForLocalhost=yes` so the device's SSH host key is not verified — trust collapses onto AWS IoT thingName routing + the broker's `iot:OpenTunnel` call. A compromised IoT credential or a thingName-to-serial misrouting silently MITMs the engineer. Implement per-device `UserKnownHostsFile=~/.postern/known_hosts/<device-id>` + `StrictHostKeyChecking=accept-new`: first connect TOFUs the device's host key into a per-device file, subsequent connects verify. Survives loopback-port changes (the keyed name is the device-id, not the loopback). Audit finding S-2 (2026-05-15). ~50 LoC.

**2026-05-15 audit backlog (post-tunneling 5-lens pass):**
Full audit ran 2026-05-15 across five lenses (broad security, deep broker security, code quality / DRY, Go standards / style, library use). Reports at `docs/audit-2026-05-15/`; SUMMARY.md for the triage agenda. 91 findings total; 8 High. Phase 1 (mechanical sweep), Phase 2 (security hardening), and Phase 3 (quality refactors) landed in this session. Remaining items deferred to backlog:

- **BD-4 coarse per-source-IP rate-limit** before TokenVerify. Closes the JWKs-fetch DoS amplification surface (an unauthenticated attacker spraying tokens with novel `kid` values forces broker-side cache-miss JWKs re-fetches at the IdP, with no rate-limit budget consumed since rate-limit currently runs *after* TokenVerify). Either coarse per-source-IP gate pre-TokenVerify, or formalize the LD-66 APIGW JWT-authorizer pre-filter dependency in docs as the documented out-of-band defense.
- **S-4 GitHub Actions SHA pinning.** All third-party actions currently pinned by floating tag (`@v6`, etc.). The release pipeline has `id-token: write` + `contents: write`; a `tj-actions`-style retag attack against any of these would silently inject into Postern's signed releases. Mechanical pass + Dependabot config so SHA bumps come as PRs.
- **S-3 broker `region` shape validation** before WebSocket URL interpolation. Marginal defense-in-depth — the trust model already assumes a non-compromised broker — but ~3 LoC regex on `^[a-z]{2}-[a-z]+-\d+$` closes a compromised-broker → source-access-token-exfil vector.
- **S-5 timefix tempfile in `$TMPDIR`.** `writeTimefixCertTempfile` uses `os.CreateTemp("", ...)` which honors the engineer-controlled `$TMPDIR`; a hostile shell env can redirect the write. Pairs with a broader timefix-file-handling refactor — migrate to per-profile cache dir at `~/.postern/cache/<profile>/`.
- **BD-7 tunneling error classifier extension.** `mapTunnelingError` collapses every non-LimitExceeded AWS error to a generic 503 `tunneling_unavailable`. AccessDeniedException (permanent, IAM-misconfig) and ThrottlingException (transient, retriable) deserve distinct error classes so operators can alert on permanent vs transient and so the CLI can make retry-vs-fail-fast decisions.

**Closed 2026-05-14 (commit 16ef48f):**

- **Unified user resolution across `postern add-host`, `postern tunnel`, `postern ssh`, `postern scp`.** Single `resolveUser` chokepoint with four-tier precedence (`--user` flag > persistent stanza User > profile `default_ssh_user` > built-in `DefaultSSHUser` fallback). `postern ssh` and `postern scp` gained `--user` flags. Returns `(string, explicit bool)` so ssh / scp can skip emitting `-l` / `-o User=` when only the implicit fallback applies, preserving any `Host *` wildcard User directive in `~/.ssh/config`. Critically, `"engineer"` is a legitimate fleet username — the explicit bool, not a value-match sentinel, drives the choice, so engineers who explicitly choose `engineer` (via flag, stanza, or profile config) get it honored.

**Closed 2026-05-15 (post-audit; commits 4d285d5 → d9380d4):**

- **Phase 1 mechanical sweep (4d285d5):** CV-1 phase-ID purge (17 `LD-NN` / `spec D-N` / `TN-D` / `invariant T` references stripped from production comments — the prior two audits had closed CV-1 at zero; the tunneling phase regressed it); `slices.Contains` swap (deleted hand-rolled `containsString` in `internal/securetunnel/loops.go`); `TruncateRunes(max int)` → `limit` (Go 1.21+ builtin shadow); `sort.Slice`/`sort.Strings` → `slices.Sort*` / `slices.SortFunc` / `slices.Sorted+maps.Keys` at 4 sites; `handleTimePayload` 501 message copy-paste bug fix; `oauthlogin/login.go` TCPAddr two-value type assertion.
- **Phase 2 security hardening (e6b7284):** **BD-1** audit-context detach in `CloudWatchAudit.Record` via `context.WithoutCancel` + 5s timeout — closes the client-disconnect denial-of-audit DoS primitive (a TCP-RST after triggering any 4xx codepath was canceling the audit-emit context); **S-1 + BD-2** scheme validation, with `isHTTPSOrLoopback` promoted from `pkg/brokerhandlers` to `internal/broker.IsHTTPSOrLoopback`, used now to gate CLI `idp.issuer` + CLI `broker` (Profile.Validate) and broker `registry.http_url` for bearer mode (Config.Validate); **BD-3** reject empty `sub` claim at OIDC verifier; **BD-5** reject (not truncate) over-length `sub`/`email` — the truncation could be weaponized for identity-collision impersonation.
- **Phase 3 quality refactors (d9380d4):** Net delta +461 / -678 across 15 files. **Q-1** three-pipeline denial helper consolidation (hoisted shared bits to `PipelineDeps` in new `internal/broker/denial.go`); **Q-2** `brokerclient` generic `postJSON[Resp any]`; **Q-4** generic `handleIssueEndpoint[Req, Resp any]` (closes Q-5 structurally — the 501-message label is now per-handler); **Q-8 + Q-12 + Q-9** CLI ssh/scp consolidation (single `resolveCommandUser` with `skipDashL bool`, shared `sshIdentityArgs` prefix, `defaultExecCommand(label)` closure with two seam-distinct call sites, package-level canonical flag-name constants); **Q-14** `newSubcommandTestRuntime` parameterization; **Q-6 + Q-13** `warnMissingInclude` helper that threads `rt.binaryName` (closes the `verbosef` hardcoded-prefix carry-over for this surface).

**Forward-looking observations (informational only):**
20 from the engineer-CLI phase archived at `docs/archive/engineer-cli/reviewer-observations.md`; 14 of those were addressed in-phase (obs 1, 2, 3, 6, 10, 11, 14 plus the obs-5/7/13/17 cluster in sub-phase F). Carry forward as backlog: obs 4 (ed25519 dead fallback), obs 8 (mint double-disk-read — likely closes in TN-F via LD-116 state-aware mint output reading ssh.conf), obs 12 (mintAndCache return-cert asymmetry), obs 15 (sshconf dir-chmod layering), obs 16 (narrow Include matcher), obs 18 (DESIGN.md "phase" leak), obs 19 (cache subcommand clock injection seam), obs 20 (remove-host double-parse). Obs 9 (`ErrTunnelNotImplemented` process-vocab leak) closed in TN-D per LD-110. Plus 61 from earlier phases + 5 from AWS-deployment increment. Address opportunistically as nearby work brings them into scope.

**2026-05-13 audit backlog:**
Full audit ran across 5 lenses (security-broad, security-broker-deep, correctness, quality, docs). Reports at `docs/audit-2026-05-13/` (`SUMMARY.md` for the triage agenda). 163 findings total; 8 High. All 8 High findings closed same-day (LD-62 go-jose CVE bump, LD-63 cert-shape panic guard, LD-64 pipeline reorder + audit-event split, README/AGENTS/registry-http-api doc refresh). Remaining 29 Medium + 49 Low + 77 Informational findings carry forward as backlog. The `SUMMARY.md` triage section ranks the highest-value Medium clusters (input bounding, design-vs-code drift, Cognito-namespacing doc gap, CI SHA-pinning, constructor-invariant tightening) for opportunistic pickup.

## §5. Operating rules (when resumed)

- Per `phased-delivery` skill for multi-agent work; 1:1 work appends to this file and `architect-log.md` directly.
- **Hard constraints from CLAUDE.md** (carry-over): no features beyond DESIGN.md, no second concrete impls of any abstraction, no DI framework, YAML-only config, JWS algorithm pin, no ID-token validation at broker, wrapping contract per LD-18, PKCE per invariant M, KMS Ed25519 key spec per invariant N.
- **User Go-style rules** at `/Users/ttarhan/.claude/projects/-Users-ttarhan-Code-postern/memory/feedback_go_code_style.md`. Apply to all new code.
- **Test command:** `make check` (with `go test -race`).
- **Go version:** language floor `go 1.24.0`, build with latest stable. No `toolchain` directive.

## §6. Reference index

- `DESIGN.md` — authoritative architecture
- `CLAUDE.md` — agent operating constraints
- `deploy/README.md` — Terraform reference deployment usage
- `terraform/postern-broker/README.md` — Terraform module reference
- `examples/terraform/deployment/README.md` — directly-deployable module consumer
- `examples/terraform/cognito/README.md` — sample Cognito IdP
- `examples/on-device/sshd/README.md` — partial sshd_config drop-in (engineer + timefix users)
- `.goreleaser.yaml` + `.github/workflows/{test,release,release-please}.yml` + `release-please-config.json` — release pipeline (LD-58)
- `CONTRIBUTING.md` — Conventional Commits + release workflow
- `docs/archive/{cleanup-phase,impl-pass,p3,oauth2,p4,aws-deployment,engineer-cli}/` — prior phase / increment artifacts
- `docs/spikes/ssh-agent-mode.md` — agent-mode spike (deferred to v1.x)
- `docs/phases/engineer-cli/spec.md` — engineer-CLI phase spec (closed 2026-05-12)
- `docs/phases/timefix/spec.md` — timefix phase spec (closed 2026-05-13)
- `docs/phases/tunneling/spec.md` — tunneling phase spec (closed 2026-05-14; 6 sub-phases TN-A through TN-F)
- `terraform/postern-broker/README.md` — module reference (Tunneling section gates the firewalled-device path via `tunneling_enabled`)
- `examples/on-device/secure-tunnel/README.md` — device-side packaging reference (AWS IoT Greengrass `SecureTunneling` component)
- `/Users/ttarhan/.claude/projects/-Users-ttarhan-Code-postern/memory/` — durable preferences
