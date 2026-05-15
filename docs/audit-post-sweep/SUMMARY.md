# Post-sweep audit — consolidated summary

Audit pass #2 run 2026-05-14, immediately after the post-timefix
audit sweep (commit `8eb0efd`) cleared 13 prior-pass findings. Five
independent subagents on disjoint lenses; read-only; no code changes
during the audit pass itself.

| Lens | High | Medium | Low | Info | Report |
|---|---|---|---|---|---|
| Overall security | 1 | 3 | 6 | 3 | [`security.md`](./security.md) |
| Broker security deep-dive | 0 | 3 | 6 | 10 | [`broker-security.md`](./broker-security.md) |
| Go conventions / quality / style | 1 | 2 | 7 | 3 | [`quality.md`](./quality.md) |
| Hand-rolled vs library | 0 | 2 | 1 | 2 | [`hand-rolled.md`](./hand-rolled.md) |
| Overall quality | 0 | 8 | 11 | 5 | [`quality-overall.md`](./quality-overall.md) |
| **Total** | **2** | **18** | **31** | **23** | **74 findings** |

## Headline verdict

**The sweep landed cleanly with two self-inflicted misses both caught
on the re-audit.** Net delta vs pass #1: 5 HIGH → 2 HIGH (3 closed,
0 new from outside the sweep), 23 MEDIUM → 18 MEDIUM (5 closed, 0
substantively new — fresh-MEDIUM count is mostly pre-existing items
re-flagged). No critical security holes; the threat-model
commitments still hold; `go-jose/v4`, `go-oidc/v3`, `x/crypto`,
`x/oauth2` deps are all on post-CVE pins; `govulncheck` recommended
for CI (carried-forward observation).

**Both HIGHs are sweep regressions I introduced**, fixed in the
trailing commit alongside this summary:

### F-SEC2-H1 — CLI ID-token verifier missing `SupportedSigningAlgs`
**Location**: `internal/oauthlogin/login.go:190`
**Effect**: F-SEC-M1 named two locations needing the asymmetric-alg
pin; the sweep fixed only the broker side (`internal/idp/oidc.go`).
The CLI's ID-token verifier — called after OAuth login to verify
the IdP's `id_token` before reading `sub`/`email` into the CLI's
keychain metadata — was silently missed. A malicious IdP advertising
HS256 in its discovery doc could substitute attacker-controlled
claims into the engineer's local "logged in as ..." display.
**Fix**: same `SupportedSigningAlgs` list as the broker side,
mirroring the pin. ✅ **Closed in `<next-commit-hash>`.**

### F-QUAL2-H1 — CV-1 regression: finding-ID in production comment
**Location**: `internal/oauthlogin/token.go:174`
**Effect**: my rationale comment for the new `accessTokenExpiry`
hand-roll → go-jose swap referenced `F-SEC-M1` as the source of the
broker's asymmetric pin. Per the user's Go-style rule, finding-IDs
(like phase identifiers) don't belong in production comments — they
rot as the audit reports decay. CV-1 had been at zero production
references since the timefix TF-E sweep; this regressed it to 1.
**Fix**: comment rewritten to describe the broker's asymmetric pin
plainly without the finding-ID. ✅ **Closed in `<next-commit-hash>`.**

## Prior-pass closure status

### Pass-#1 HIGHs (5 → all addressed; 4 closed, 1 partial)
| ID | Status | Notes |
|---|---|---|
| F-OQ-H1 (Cedar starter policy permit `MintTimefixCert`) | **CLOSED** | `terraform/postern-broker/cedar/{schema.json,starter.cedar}` extended. |
| F-OQ-H2 (sshd sample `ForceCommand` path) | **CLOSED** | `examples/on-device/sshd/postern.conf` corrected to `/usr/sbin/timefix-apply`. |
| F-OQ-H3 (AGENTS.md timefix state) | **CLOSED** | "What this repo is" + v1-status section refreshed. |
| F-OQ-H4 (handoff stale) | **CLOSED** | Tunneling architect dispatch pre-fixed; pass-#2 confirms. |
| F-HR-H1 (`accessTokenExpiry` hand-rolled JWT) | **CLOSED** | go-jose `jwt.ParseSigned + UnsafeClaimsWithoutVerification`. |

### Pass-#1 MEDIUMs by lens
- **Overall security (4)**: F-SEC-M1 **PARTIAL** (broker side closed; CLI side missed → F-SEC2-H1 → now closed); F-SEC-M2 (LD-65 wording) **CLOSED**; F-SEC-M3 (`--ip` flag whitespace) **OPEN**; F-SEC-M4 (sshconf `HostName`/`User`/`Patterns` newline-validate) **OPEN**.
- **Broker (3)**: F-BRK-M1 (panic-recovery) **OPEN**; F-BRK-M2 (`NewID` failure audit-bypass) **OPEN**; F-BRK-M3 (`/ssh/tunnel` 501 stub) **OPEN** (closes in TN-A).
- **Go quality (5)**: F-QUAL-M1..M5 all **CLOSED** (M4 partially — see F-QUAL2-M1 for one bypass path).
- **Hand-rolled (2)**: F-HR-M1 + F-HR-M2 both **CLOSED**.
- **Overall quality (9)**: 1 closed (M7 timefix README), 1 partial (M8 Mode consts merged + stale comment survives), 7 still open (operator cert `permit-port-forwarding`, "postern" hardcoded in user-facing output, `POSTERN_LOG_LEVEL` not per-binaryName, DESIGN.md `postern timefix` signature stale, etc).

## Fresh-pass findings worth flagging

### MEDIUMs

- **F-HR2-M1** — `pkg/cliapp/config.go:SaveConfigFile` uses `O_TRUNC` + encode (not atomic-write); kill-during-encode corrupts `config.yaml`. Same anti-pattern F-HR-M2 cleared from `tokenstore`. Recommend swap to `internal/atomicfile.WriteFile`.
- **F-HR2-M2** — `internal/certcache/cache.go:writeProfileKeyExclusive` hand-rolls temp+link for the per-profile key. `internal/atomicfile`'s package doc names "or os.Link, for the exclusive variant" but only exports the rename-based `WriteFile`. Recommend exporting `WriteFileExclusive` and switching certcache to it.
- **F-QUAL2-M1** — `defaultExecSSHTimefix` cleanup closure factor (from the sweep's F-QUAL-M4 fix) is bypassed in one path at `pkg/cliapp/runtime.go:230-233` (stdin-close-error branch). One-line consistency fix.
- **F-QUAL2-M2** — `accessTokenExpiry`'s accepted-algs list includes symmetric algs (HS256/384/512); the broker's verifier now pins asymmetric-only. The CLI's parse-don't-verify is correct (broker is authoritative), but asymmetry between the two for "what's an acceptable token shape" is a future-confusion vector. Defensible as-is per the comment, but worth a thought.
- **F-OQ2-M3** — `docs/team-handoff.md` "Last updated" line stale (still says 2026-05-13; spec status flipped 2026-05-14).
- **F-OQ2-M8** — Tunneling spec has file:line cross-references AGENTS.md doc-style rules forbid ("Don't reference specific filenames or line numbers in the design doc"). Worth re-reading the locked spec with that lens.
- **F-SEC2-M1** + **F-SEC2-M2** — restatements of F-SEC-M3 + F-SEC-M4 (`--ip` flag whitespace; sshconf newline-validate); both genuinely still open, neither touched by the sweep.
- **F-SEC2-M3** — refresh-no-verify on the ID token. Same threat shape as F-SEC2-H1; with H1 closed, this drops back to a LOW (refresh path uses the same verifier).
- **F-BRK2-M1..M3** — restatements of F-BRK-M1..M3 (panic-recovery, NewID failure audit-bypass, `/ssh/tunnel` 501 stub). The last closes in TN-A.

### LOWs / INFOs

Most pass-#2 LOWs and INFOs are carry-overs from pass-#1 that the sweep deliberately scoped at HIGH+MEDIUM only. Specifically: bearer-parser multi-space tolerance, broker `--version` flag missing, no CHANGELOG entries for timefix landing, Makefile on-device build on macOS produces a non-functional binary (the cmd/timefix-set-clock binary uses `syscalls_other.go`'s "unsupported platform" stub — correct behavior, but the Makefile builds it anyway). One new INFO worth noting: `timePayloadOpaqueSigner.Algs()` advertises EdDSA but go-jose does NOT cross-check `SigningKey.Algorithm` against the OpaqueSigner's `Algs()`; latent bug only (single call site uses EdDSA), two-line assert in `SignPayload` closes it.

## Triage recommendation

**Immediate** (already done in `<this-commit>`): F-SEC2-H1 + F-QUAL2-H1.

**Fold into TN-A scope** (the dispatch is about to start; cheap to bundle):
- F-BRK-M3 (`/ssh/tunnel` 501 stub) closes naturally by TN-A.
- F-HR2-M1 + F-HR2-M2 (atomic-write hygiene) — both small swaps, aligns with the library-first reminder already in the TN-A engineer brief notes (`docs/phases/tunneling/spec.md` §9).
- F-QUAL2-M1 (`defaultExecSSHTimefix` cleanup-closure bypass) — same file the engineer will touch for tunneling-CLI integration.
- F-OQ2-M3 (handoff "Last updated" date) — orchestrator should refresh on next handoff edit.

**Carry as backlog** (low risk, no natural TN-A coupling):
- F-SEC-M3 / F-SEC2-M1 (`--ip` flag whitespace), F-SEC-M4 / F-SEC2-M2 (sshconf newline-validate): pure UX-input hygiene; orchestrator can sweep opportunistically.
- F-BRK-M1 / F-BRK2-M1 (panic-recovery middleware): substantive design choice; defer until post-tunneling, address as 1:1 work.
- F-BRK-M2 / F-BRK2-M2 (NewID failure audit-bypass): same — defer for design.
- Remaining F-OQ-M items (operator cert `permit-port-forwarding`, hardcoded "postern" in user-facing output, `POSTERN_LOG_LEVEL` per-binaryName, DESIGN.md `postern timefix` signature): doc-and-polish backlog.

## Methodology

Five subagents in parallel against the post-sweep codebase (commit
`8eb0efd`):

- **overall security**: TLS/JWT/JWS validation (including the new
  go-jose use in `internal/oauthlogin/token.go`), auth boundaries
  (incl. the new `SupportedSigningAlgs` pin from the sweep),
  authorization gaps (Cedar starter now permits both
  `MintOperatorCert` and `MintTimefixCert`), input validation
  (`broker.TruncateRunes` is now the shared helper), privilege
  boundaries, secrets, rate-limit + audit invariants (LD-65 with
  LD-84 restatement), dependency security. Plus closure check on
  prior-pass MEDIUMs.
- **broker security deep-dive**: pipeline ordering + audit coverage,
  preamble shape, cert-mint shape (now including the new timefix
  branch), time-payload + JWS construction, HTTP surface, rate
  limiting, Registry, AVP (extended to `MintTimefixCert`), audit
  sink. Plus closure check.
- **Go conventions / quality / style**: CV-1 compliance, user's
  three Go-style rules, idioms, naming, function size, package
  boundaries, concurrency, error handling, test quality, doc
  comments. Plus closure check on F-QUAL-M1..M5.
- **hand-rolled vs library**: crypto-adjacent hand-rolls, parser
  hand-rolls, network hand-rolls, concurrency primitives, random,
  time / clock. Plus closure check on F-HR-H1 + F-HR-M1 + F-HR-M2.
- **overall quality (catch-all)**: wrapping contract integrity,
  documentation accuracy, test coverage gaps, config surface, error
  messages + observability, build/release pipeline, backwards-compat
  hygiene, cross-platform readiness, dependency surface, phase-close
  hygiene + tunneling-phase-open hygiene. Plus closure check on
  F-OQ-H1..H4.

Each report includes its own methodology + scope. No code changes
during the audit pass itself; the two HIGHs were fixed in the same
commit as this summary as orchestrator-direct reconciliation (both
are sweep regressions I introduced).
