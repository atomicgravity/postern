# Post-timefix audit — consolidated summary

Audit pass run 2026-05-13, immediately after the timefix phase closed
(commit `e5c0b5c`). Five independent subagents on disjoint lenses;
read-only; no code changes during the audit.

| Lens | High | Medium | Low | Info | Report |
|---|---|---|---|---|---|
| Overall security | 0 | 4 | 7 | 5 | [`security.md`](./security.md) |
| Broker security deep-dive | 0 | 3 | 5 | 11 | [`broker-security.md`](./broker-security.md) |
| Go conventions / quality / style | 0 | 5 | 9 | 3 | [`quality.md`](./quality.md) |
| Hand-rolled vs library | 1 | 2 | 1 | 3 | [`hand-rolled.md`](./hand-rolled.md) |
| Overall quality | 4 | 9 | 8 | 4 | [`quality-overall.md`](./quality-overall.md) |
| **Total** | **5** | **23** | **30** | **26** | **84 findings** |

Reports are each a self-contained Summary / High / Medium / Low / Info / Methodology document.

## Headline verdict

**No critical security holes.** Both security lenses returned **zero
HIGH findings**. The threat-model commitments in `DESIGN.md` and
`AGENTS.md` are consistently implemented. `go-jose/v4 v4.1.4`
(CVE-2025-27144 fixed), `coreos/go-oidc/v3 v3.11.0` (no `alg=none`
reachable), `x/crypto v0.40.0`, `x/oauth2 v0.35.0` are all on
post-CVE pins. The LD-65 audit-coverage invariant is preserved at
every gate. The LD-90/LD-91 go-jose-on-both-sides swap removed the
highest-risk hand-rolled crypto surface.

**Real product-shipping bugs in the just-closed timefix phase.** Two
HIGH findings in the overall-quality lens are immediate-effect bugs
unwrapped operators hit on first try (cert authorization denied by
default; sshd execs the wrong binary path). One HIGH in the hand-rolled
lens is the same JWT-parse anti-pattern at the CLI seam that TF-E
already swept on the broker + verifier sides. Two HIGH docs-drift items
also need to land.

## All HIGH findings (5)

### F-OQ-H1 — Bundled Terraform Cedar policy doesn't permit `MintTimefixCert`
**Effect**: every unwrapped operator deploys the framework, runs
`postern timefix <device>`, and gets `authorization_denied` from AVP
because the starter Cedar policy only permits `MintOperatorCert`. The
TF-A engineer widened the broker's mode-dispatch (LD-80) and the
starter policy was never updated.
**Fix**: extend `examples/terraform/.../starter-policy.cedar` (or
wherever the bundled starter lives) to permit `MintTimefixCert` for
the same engineer group as `MintOperatorCert`. ~5 lines of Cedar.
**Severity rationale**: ships broken for unwrapped use.

### F-OQ-H2 — sshd `postern.conf` ForceCommand path disagrees with everything else
**Location**: `examples/on-device/sshd/postern.conf` says `ForceCommand
/usr/local/sbin/timefix-apply` but the install path was changed to
`/usr/sbin/timefix-apply` user-wide (your direction earlier in the
session).
**Effect**: sshd reaches for a binary that doesn't exist; timefix
sessions fail at exec time.
**Fix**: one-line path correction in the sample sshd drop-in.
**Severity rationale**: ships broken for unwrapped use; same class as F-OQ-H1.

### F-OQ-H3 — `AGENTS.md` stale on timefix
**Location**: §"What this repo is" still says the on-device timefix
path is "not yet built"; subcommand list in the same paragraph omits
`timefix`. Misleads agents/contributors returning to the repo.
**Effect**: agents resuming work read AGENTS.md and assume timefix is
a v1 gap they should be building. (Caught me during the tunneling
architect dispatch — the architect had to grep to confirm timefix was
actually closed.)
**Fix**: rewrite the "current state" sentence to reflect the closed
phase; add `timefix` to the subcommand list.

### F-OQ-H4 — `docs/team-handoff.md` stale → addressed by tunneling architect
**Original finding**: handoff said "TF-A ready to dispatch" while the
phase spec was CLOSED. **No longer applicable** — the tunneling
architect dispatch updated the handoff with the new current-phase
pointer (`docs/phases/tunneling/spec.md`); the timefix close is now
correctly reflected in §3.

### F-HR-H1 — `accessTokenExpiry` hand-rolls JWT parse on every authenticated CLI call
**Location**: `internal/oauthlogin/token.go:165-199`
**Effect**: same anti-pattern LD-90/LD-91 just swept on the broker and
verifier sides — `strings.Split` on `.` + manual base64url decode +
manual JSON `{exp json.Number}` unmarshal. Sits on every authenticated
CLI hot path (`login`, `mint`, `ssh`, `scp`, `timefix`). Not a security
hole today (the broker re-verifies), but it's the exact class of
crypto-adjacent hand-roll the user has been explicit about avoiding.
**Fix**: replace with `go-jose/v4`'s `jwt.ParseSigned` +
`UnsafeClaimsWithoutVerification` (CLI-side expiry pre-check on a
token the broker is responsible for verifying). ~10 LoC swap.
`go-jose/v4` already a direct dep.

## Notable MEDIUMs worth surfacing

### F-SEC-M1 — OIDC verifier missing `SupportedSigningAlgs`
`internal/idp/oidc.go` does not set `SupportedSigningAlgs` on the
go-oidc verifier. `alg=none` is filtered by the library, but if a
malicious IdP advertised HS256 in its discovery doc, the verifier
would accept it. Explicit asymmetric-only pin is one line.

### F-SEC-M2 — Apparent contradiction with LD-65 (not a real bug)
The Sign-failure path I just landed emits `*_authorized` +
`*_denied/signer_failure` for the same `jti`. The auditor read LD-65's
"exactly one audit row" wording and flagged the pair as a violation.
LD-84 actually restated the invariant under the new shape to allow
this pair for signer-failure. The auditor reading is reasonable; the
LD-65 invariants-table wording could be tightened to reference LD-84's
restatement.

### F-SEC-M3 — `postern timefix --ip <addr>` doesn't whitespace/newline-validate
The `--ip` flag's value is interpolated into the ssh argv as
`-o HostName=<value>` without validating no whitespace/newlines. An
engineer pasting a malformed string from clipboard could inject extra
ssh options. Low-risk because attacker is the engineer themselves, but
worth one-line input validation.

### F-SEC-M4 — `internal/sshconf/writer.go` newline-validates `Device` only
`HostName`, `User`, `Patterns` are interpolated unchecked. Same input
class as F-SEC-M3 (engineer-typed-or-pasted). Worth tightening.

### F-BRK-M1 — No panic recovery middleware in broker pipeline
Panics between TokenVerify and recordAuthorized would bypass the deny
audit. The broker would 500 and the audit log would have no row. Add
a recover-and-emit-denied panic-recovery middleware at the pipeline
root.

### F-BRK-M2 — `IDGenerator.NewID` failure returns 500 with no audit row
`verifyEngineer` calls `i.deps.IDs.NewID(now)` before any other work;
if it fails, the function returns the bare error with no audit row.
Production `UUIDv7Generator` reads `crypto/rand`; failure is
catastrophic but possible. Either treat as "fail open with a denied
row" or accept that audit-row-on-NewID-failure is impossible (because
the JTI for the audit row comes from NewID).

### F-BRK-M3 — `/ssh/tunnel` 501 stub is unauthenticated + auditless
Will be replaced by TN-A. Until then, the stub answers any verb with
501 + no audit. Wraps cleanly once tunneling lands.

### F-OQ-M (multiple) — Doc/sample drift
- `examples/on-device/timefix/README.md` still describes one-line
  verifier stdout (D14 made it two lines).
- DESIGN.md `postern timefix` signature predates D13/D15.
- README mentions `cliapp.Run()` API that doesn't exist.

### F-HR-M1 — Hand-rolled UUIDv7 in `internal/broker/id.go`
Hand-rolled bit-twiddling + hex render. `github.com/google/uuid`
already has `NewV7()`. Would add a small new direct dep.

### F-HR-M2 — `internal/tokenstore/file.go` `Save` reimplements atomic-write
`internal/atomicfile.WriteFile` (same repo) exists and is used
elsewhere. In-repo helper not consumed.

### F-QUAL-M1..M5 (Go quality)
Mode-const split, `SSHSigner` adapter exported but only used in tests,
`truncateRunes` duplicated across two packages, `defaultExecSSHTimefix`
cleanup boilerplate, `NewDynamoDBRateLimiter` test-only on the
wrapping surface.

## Methodology

Five subagents dispatched in parallel against the post-TF-E codebase:

- **overall security**: TLS/JWT/JWS validation, auth boundaries,
  authorization gaps, input validation, privilege boundaries, secrets,
  rate-limit + audit invariants, dependency security.
- **broker security deep-dive**: pipeline ordering + audit coverage
  (LD-64/-65/-83/-84), preamble shape, cert-mint shape, time-payload
  + JWS construction, HTTP surface, rate limiting, Registry, AVP,
  audit sink.
- **Go conventions / quality / style**: CV-1 compliance, user's
  three Go-style rules, idioms (`errors.Is`, `slices.Contains`, etc.),
  naming, function size, package boundaries, concurrency, error
  handling, test quality, doc comments.
- **hand-rolled vs library**: crypto-adjacent hand-rolls, parser
  hand-rolls, network hand-rolls, concurrency primitives, random,
  time / clock injection.
- **overall quality (catch-all)**: wrapping contract integrity,
  documentation accuracy, test coverage gaps, config surface, error
  messages + observability, build/release pipeline, backwards-compat
  hygiene, cross-platform readiness, dependency surface, phase-close
  hygiene.

Each report includes its own methodology + scope. No code changes
during the audit. The audit's recommendations are NOT applied
inline; they are surfaced here for triage.

## Triage recommendation

Three buckets:

**Immediate fix before any further phase work** (3 items, ~30 minutes):
- F-OQ-H1 — Cedar starter policy permits `MintTimefixCert`.
- F-OQ-H2 — sshd sample drop-in `ForceCommand` path correction.
- F-OQ-H3 — AGENTS.md timefix-state refresh.

**Fix in the tunneling phase, opportunistic** (5 items):
- F-HR-H1 — swap `accessTokenExpiry` to go-jose (matches the LD-90/LD-91 lesson; same pattern).
- F-SEC-M1 — `SupportedSigningAlgs` on OIDC verifier.
- F-SEC-M3 — `--ip` flag whitespace validation.
- F-SEC-M4 — `sshconf` `HostName`/`User`/`Patterns` newline-validate.
- F-BRK-M1 — broker panic-recovery middleware.

**Backlog** (rest): MEDIUM / LOW / INFO items addressed
opportunistically as nearby work brings them into scope. Tracked in
`docs/reviewer-observations.md` going forward.
