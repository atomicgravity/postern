# Team Handoff — Postern

> If you are a restarting orchestrator, this is your single entry point.
> Read top to bottom. Then read the three role logs (architect-log.md,
> reviewer-observations.md, tester-baselines.md). Then verify git state.

**Last updated:** 2026-06-08, client-auth phase complete (A–F gated + committed).

## §1. How to use this doc

This project follows the `phased-delivery` skill. Load the skill alongside
this doc — handoff covers project state, skill covers framework.

1. Read §2–§3 for project context + current state.
2. Use §4 to know which engineer specialty to dispatch next.
3. Preserve §5's operating rules.
4. Scan §6–§8 for decisions + open questions + non-blocking carries.
5. Follow §9 to resume work.
6. Reference §10 for this project's paths.

## §2. Project context

Postern is an open-source framework for SSH access to embedded Linux device
fleets — short-lived certificate auth gated by SSO, with handling for offline,
firewalled, and broken-clock devices. Architecture is in `DESIGN.md`; agent
guidance in `CLAUDE.md`. **v1 is complete and released through v1.1.0.** The
broker (long-running + Lambda), engineer CLI, on-device timefix split, all v1
default abstraction impls (KMS Signer, DynamoDB Registry/RateLimit, AVP Policy,
CloudWatch Audit, generic OIDC IdP, AWS IoT secure tunneling + pure-Go V3
source proxy), and the AWS Terraform reference module are all implemented.

Primary references:
- `DESIGN.md` — authoritative architecture
- `CLAUDE.md` — agent guidance + load-bearing invariants
- (no active phase spec — see §3)

## §3. Current state

**Where we are in implementation:** v1 complete except the `postern upgrade`
subcommand, which is a placeholder (`pkg/cliapp/app.go` `placeholderCommand`).

**Last code-carrying commit:** `c953f4c` — *feat(broker): configure
principal-class rules via env (Lambda)*.

**Fix apigw-aud-pin (2026-06-09, `ac26282`):** the APIGW HTTP API JWT
authorizer no longer pins `idp_audience`. It ANDs its constraints, so it
couldn't express the broker's aud-OR-scope acceptance — pinning aud 401'd
scope-only (machine / client-credentials) tokens at the edge before the
broker's v1.4.1 aud-OR-scope check ran. Authorizer now does signature +
issuer + exp only; broker stays the authoritative aud-OR-scope verifier
(cross-app isolation unchanged; audience-only deployments lose the edge pin
but no security). `terraform/postern-broker/lambda.tf` + `variables.tf` +
README round-trip. Needs a release so the sai operator (who runs
`apigw_jwt_authorizer_enabled = true` + `idp_required_scope`) can bump the
module ref.

**Phase broker-aud-scope: COMPLETE + gated.** Broker verifier now accepts a
token matching EITHER configured `idp.audience` OR `idp.required_scope` (was AND);
fail-closed `matched*` form (a fail-open draft was caught + corrected in review);
cross-app isolation preserved. Spec `docs/phases/broker-aud-scope/spec.md`,
decision D-CA-10, docs round-tripped (DESIGN.md/CLAUDE.md=AGENTS.md). Reviewer
APPROVE (mutation-verified the 25-case security matrix) / architect NON-OBJECTION
/ tester PASS. `internal/idp/oidc.go` + `oidc_test.go`. No config change. Carries
O-29/O-30 (optional matrix completeness). Needs a release so the sai operator can
set `idp_required_scope` and finish M2M wiring.

**Prior phase:** client-auth — principal classes for automated callers
(OAuth2 client-credentials). Spec: `docs/phases/client-auth/spec.md`.
Sub-phases A → (B ∥ C) → D, then follow-ons E and F. All complete.

**Phase status:** client-auth COMPLETE and gated end-to-end — sub-phases A–D
plus follow-ons E (`--cert-max-lifetime`) and F (env-configurable principal
classes + STRICT-validation fix). Every sub-phase cleared the 4-way gate
(reviewer/architect/tester/orchestrator) and is committed on `feat/client-auth`;
`make check` green. Decisions D-CA-1..9.

**Sub-phase grid (all gate-cleared + committed):**
- A — classification core + Cedar context (`principal_class`/`client_id`);
  `EngineerClaims`→`CallerClaims`. `03b12c6`. Carries O-4..O-7.
- B — per-class cert-TTL ceiling + Cedar-gated requested TTL (opt c). `74cf916`.
  Carries O-8..O-11.
- C — audit `principal_class`/`client_id` stamping. `49c993d`. Carries O-12/13.
- D — CLI `grant: client_credentials` (env-only secret, no tokenstore write).
  `792282f`. Carries O-14..O-16.
- E — `--cert-max-lifetime` on mint/ssh/scp (distinct from tunnel flag). D-CA-7.
  `e53b241`. Carries O-17..O-19.
- F — `POSTERN_IDP_PRINCIPAL_CLASSES` env config + `principal_class`
  required:true + starter `has client_id` guard. D-CA-8/9. `37ad062`,`c953f4c`.
  Carries O-20/21.
- G — m2m security-review hardening: strict (`KnownFields`) decode of the
  env block (closes O-22) + `claim_absent` empty-string/array edge tests.
  Carries O-23 (file-side strict decode deferred).
- Schema fix `9377ca3` — declared `requested_cert_ttl_minutes` (broker emitted
  it; schema hadn't declared it → would fail STRICT validation).

**Operator-repo work (separate repo `Code/sai/device-management/terraform/
postern`, not framework):** engineer permit asserts `principal_class == "user"`;
m2m permit gated on allowlisted `client_id` + `source_ip` (independent tfvars
lists); schema `required:true`; `idp_principal_classes_json` wired. Needs a
postern release containing client-auth before its broker emits the class —
policy + broker MUST deploy together or engineers lock out. Uncommitted there
(user owns that repo).

**Later v1 gap (deferred):** `postern upgrade` signed-release subcommand —
Sigstore cosign-keyless verification.

**m2m security review (2026-06-09):** no Critical/High findings; partition,
source-IP trust, fail-closed posture, secret handling sound. M2 (strict env
decode) + L1 (edge tests) applied in sub-phase G. M1 (prefer a positive M2M
scope marker over `claim_absent: username`) left as an operator recommendation.

**Open items:** (1) dedup cleanup pass for the duplication carries
(O-4/5/9/12/15/17/20); (2) cut a postern release so the operator repo can
consume client-auth; (3) open a PR.

**Recent commits** (`git log --oneline main..HEAD`):
```
c953f4c feat(broker): configure principal-class rules via env (Lambda)
37ad062 fix(terraform): principal_class required + guard client_id in starter
9377ca3 fix(terraform): declare requested_cert_ttl_minutes in the Cedar schema
2812ce9 docs: document automated callers, principal classes, cert TTL flag
e53b241 feat(cli): --cert-max-lifetime flag to request a shorter cert TTL
792282f feat(cli): client-credentials grant for automated callers
49c993d feat(broker): record principal class and client id on audit rows
74cf916 feat(broker): per-class operator cert TTL with Cedar-gated request
03b12c6 feat(broker): classify callers into principal classes from token claims
```

## §4. Roles (one-shot, dispatched on demand)

This skill uses one-shot sub-agents — there is no persistent team. The
orchestrator (the agent that invoked the skill) is the only persistent entity.
Dispatch sub-agents using the templates in the skill's
`references/briefing-templates.md`.

| Role | When to dispatch | Where state lives |
|---|---|---|
| architect | Spec creation, shape ruling, round-trip | docs/architect-log.md + spec docs |
| reviewer | Each gate's execution review | docs/reviewer-observations.md |
| tester | Each gate's independent verification | docs/tester-baselines.md |
| backend-engineer | Broker / CLI Go implementation | (no log — code is the artifact) |

Engineer specialties this project uses: backend-engineer (Go: broker + CLI).
No device-engineer needed for the upgrade phase (pure CLI + release verification).

Project-specific brief customizations beyond skill defaults: tests run via
`make check` (NOT raw `go test ./...` — timefix verifier suite is build-tagged).

## §5. Operating rules

Per skill — gate sequence, stuck rule, user-authorization, commit discipline,
handoff-doc rule all live there. Project-specific additions:

- **Tests: `make check`, never raw `go test ./...`** (CLAUDE.md). Single
  package: `go test -tags timefix_test_path ./cmd/timefix-apply/...`.
- **No `Co-Authored-By` / AI attribution in commits** (user global rule).
- **Release flow is release-please-driven.** `feat:`/`fix:` to main opens a
  release PR; merging tags `v*` and chains GoReleaser. Orchestrator commits to
  main with conventional-commit prefixes; does not hand-tag releases.
- **Comment hygiene:** no phase / LD-N / TN-X / RO-N identifiers in production
  comments (Go-style memory rule 3; CV-1 audit finding — currently at 0 leaks).

## §6. Locked decisions carried forward

1. One concrete impl per abstraction in v1; no speculative second impls.
2. `postern upgrade` uses Sigstore cosign-keyless verification; no
   Postern-held private key; release URL + cert-identity regex are
   wrapper-overridable constructor params; upgrade does NOT flow through the
   broker (CLAUDE.md "Updates are decoupled from the broker").
3. Access tokens (never ID tokens) at the broker.
4. YAML + env config only; no INI/TOML/JSON.
5. No DI framework; constructor injection in main.go.
6. Cryptographic shapes pinned (EdDSA, typ pins); no algorithm negotiation.

## §7. Open decisions / questions

- **Q-PHASE-1 (answered 2026-06-08):** Next phase = client-auth (principal
  classes for automated callers). Spec at `docs/phases/client-auth/spec.md`.
  `postern upgrade` remains the later v1 gap.
- **Q-CA-APPROVAL (open):** Awaiting user go-ahead to start sub-phase A.

## §8. Non-blocking items

Deferred from the 2026-05-15 audit (Tier-3/4 — pick up when nearby work brings
them into scope; full detail in `docs/audit-2026-05-15/`):
- S-2: tunnel-mode host-key trust (documented design choice — decide if
  AWS-IoT-thingName routing trust is acceptable or invest in SSH host certs).
- BD-3/BD-5: reject (not truncate) over-length / empty OIDC `sub`.
- BD-4: JWKs-fetch DoS pre-rate-limit (coarse per-IP limit or formalize the
  APIGW JWT-authorizer dependency in docs).
- Tier-3 refactors largely landed (three-pipeline denial-emit helper, generic
  handler builder, etc. — verify before re-flagging).

## §9. How to resume

Follow the skill's §"Resume-from-crash pattern". Project paths in §10.

Project-specific resume notes:
- Run `make check` to confirm green baseline before dispatching any engineer.
- Confirm Q-PHASE-1 (§7) with the user before commissioning a phase spec.

## §10. Reference index

- `DESIGN.md` — authoritative architecture
- `CLAUDE.md` — agent guidance + load-bearing invariants
- `docs/architect-log.md` — architect's locked decisions + open questions
- `docs/reviewer-observations.md` — reviewer's forward-looking items
- `docs/tester-baselines.md` — tester's last-gate counts + flake registry
- `docs/audit-2026-05-15/` — 5-lens audit (91 findings; Tier-1 mechanical +
  Tier-3 refactors largely landed; Tier-4 deferred items in §8)
- `docs/registry-http-api.md` — registry HTTP API reference
- Test command: `make check`
- Tooling: `Makefile`, `.goreleaser.yaml`, `release-please-config.json`

## §11. Revision notes

Rev A (2026-06-08): scaffolding reconstructed after `dc3b0c9 docs: remove old
docs` (May 15) cleared the prior timefix/tunneling-phase state files. Reflects
post-1.1.0 reality: v1 complete bar `postern upgrade`; audit remediation
landed. Next phase pending user selection (§7).
