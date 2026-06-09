# Architect log — Postern

> Locked decisions + open questions. Updated by architect at end of each
> dispatch. Read by architect on every spawn; read by engineers when spec
> is ambiguous; read by reviewer for spec-drift checks.
>
> Keep entries terse — bullets, not paragraphs. Rationale is one line.

## Locked decisions

These are carried-forward v1 architectural decisions (authoritative source is
`DESIGN.md` + `CLAUDE.md`; this table is the orchestrator/architect quick-scan).
The prior phase-by-phase decision rows were retired with the May-15 doc cleanup.

| id | date | decision | rationale | sub-phase |
|----|------|----------|-----------|-----------|
| D-UPG-1 | pre-existing | `postern upgrade` verifies via Sigstore cosign-keyless; no Postern-held key | trust GHA OIDC identity + Rekor, not a held secret | (pending) |
| D-UPG-2 | pre-existing | release URL + cert-identity regex are wrapper-overridable constructor params | wrappers ship own releases | (pending) |
| D-UPG-3 | pre-existing | upgrade does not flow through the broker | separates SSH-access infra from software distribution | (pending) |
| D-ABS-1 | pre-existing | one concrete impl per abstraction in v1 | avoid baking first impl's assumptions into interface | — |
| D-CA-1 | 2026-06-08 | principal class derived once in the IdP verifier; stamped on `EngineerClaims.Class` | single source of truth — TTL/audit/Cedar all read one field, no drift | client-auth |
| D-CA-2 | 2026-06-08 | classification = configurable ordered first-match claim rules (`idp.principal_classes`); predicates: present/absent/equals/scope_contains | covers Cognito-by-absence (no `username`) + Auth0/Okta positive marker in one generic verifier | client-auth |
| D-CA-3 | 2026-06-08 | Cedar surface is `context.principal_class` + `context.client_id`, not a typed principal entity | principal type is fixed by AVP identity source under IsAuthorizedWithToken; context is uniform across Cognito+OIDC flavors | client-auth |
| D-CA-4 | 2026-06-08 (rev 2026-06-08) | cert TTL = static per-class ceiling (`cert_ttl.by_class`) **plus** optional CLI-requested lifetime gated by Cedar (`context.requested_cert_ttl_minutes`, deny-only, clamped to ceiling) — option (c). AVP returns only Allow/Deny so Cedar can't emit a TTL; it gates a broker-proposed value, mirroring tunnel's `requested_max_lifetime_minutes`. Audit gains `principal_class`+`client_id`; client id from `client_id` claim. `OperatorClockSkewPadding` preserved; window never exceeds ceiling | TTL/audit are broker decisions around (not inside) the Cedar call; reuse tunnel propose-and-gate precedent | client-auth |
| D-CA-5 | 2026-06-08 | CLI `grant: client_credentials`; secret from `<PREFIX>_IDP_CLIENT_SECRET` env only; re-mint-on-demand, no refresh token, no tokenstore write | browserless M2M path; sidesteps tokenstore RefreshToken-required invariant without schema change | client-auth |
| D-CA-7 | 2026-06-08 | CLI cert-lifetime request flag (B's deferred flag, sub-phase E) is named `--cert-max-lifetime` — **distinct** from the existing `--max-lifetime` — on `mint`/`ssh`/`scp`. Feeds the cert request's `MaxLifetimeMinutes`; zero/absent omits the field (broker ceiling); negative rejected client-side; no client-side ceiling (broker clamps). Threaded through the shared `certflow.go` chokepoint; `tunnelDial` gains a cert-minutes param (ssh/scp pass the resolved value, standalone `tunnel`/`addhost` pass 0); tunnel flag untouched | on `ssh`/`scp` `--max-lifetime` already means the **tunnel** TTL; reusing it for the cert would conflate two independent lifetimes. Mirrors the tunnel propose-and-gate flag shape (D-CA-4) without overloading its name | client-auth |
| D-CA-6 | 2026-06-08 | rename `EngineerClaims`→`CallerClaims` (+ `PolicyRequest`/`RateLimitRequest`/preamble `.Engineer`→`.Caller`); keep `Subject`/`Email`/`Groups`/`Raw` field names; add `Class`+`ClientID`. Wire JSON, Cedar names, and audit-JSON (`engineer_*`) all unchanged | compat is OLD-CLI↔NEW-broker wire only; `EngineerClaims` carries no JSON tags so rename is free and `Engineer*` is a misnomer once machine callers exist | client-auth |
| D-CA-8 | 2026-06-08 | `principal_classes` rule list is env-configurable via `POSTERN_IDP_PRINCIPAL_CLASSES` (whole block as JSON/YAML doc, parsed+validated like a file block); **replaces** any file block — no per-rule merge. `POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT` still overrides the default scalar on top. Wired through Terraform as `idp_principal_classes_json`. Supersedes spec sub-phase A's "rule list is YAML-only" | the file-less Lambda is the primary deployment and had no way to carry the structured list; a first-match rule list has no well-defined per-rule merge, and the env var's deployment has no file rules to merge with, so replace-the-block is honest while the scalar default stays additive (composes cleanly). Reviewer O-20 asymmetry is intended, not a defect | client-auth/F |
| D-CA-9 | 2026-06-08 | bundled Cedar schema declares `context.principal_class` **`required: true`**; `client_id` stays optional. Starter policy gains a `context has client_id` guard. Supersedes spec sub-phase A's "two new optional context attrs" for `principal_class` | `contextMap` emits `principal_class` unconditionally (verifier classifies every request, default `user`) so required:true is honest and lets the starter reference it unguarded; `client_id` is added only when non-empty so it must stay optional+guarded. Fixes AVP STRICT validation rejecting the starter at `CreatePolicy` (caught only at `terraform apply`, not `make check`) | client-auth/F |
| D-CA-10 | 2026-06-09 | broker aud/scope match: **implicit AND→OR** when **both** `idp.audience` + `idp.required_scope` are configured — accept if *either* matches; single-config behavior unchanged. **No** `audience_scope_match` knob. New merged reject string `"access token missing required audience or scope"` replaces the two old strings. Round-tripped DESIGN.md/CLAUDE.md(=AGENTS.md). Spec: `docs/phases/broker-aud-scope/spec.md`. **Spec pseudocode corrected during review:** the original draft `audOK := v.audience == "" || match` form fail-OPENed single-config deployments (an unset field defaulted to `OK=true`, so `!audOK && !scopeOK` never enforced the one configured check); corrected to the fail-closed `matched* := field != "" && match` form (an unset field is never a proof). Added invariants 5 (fail-closed-on-neither-configured) + 6 (single-config-still-enforced) and a 25th test case (`fail-closed/neither-configured`, direct struct construction). Shipped impl matches the corrected form. | AND-both rejects *everyone* in the mixed Cognito human(`aud`)+machine(`scope`-only) case; OR is the documented "and/or" made true at zero config cost. Cross-app isolation preserved — neither-proof still rejected. Knob = speculative second mode (one-concrete ethos); strict-AND is a future explicit-need-only knob. Single-config deploys byte-identical; only AND-relying both-config deploys broaden (low risk; CHANGELOG note suffices) | broker-aud-scope |

## Open questions

| id | date raised | question | status | blocked-by |
|----|-------------|----------|--------|------------|
| Q-PHASE-1 | 2026-06-08 | What is the next phase? (candidate: `postern upgrade`) | answered: next phase = client-auth (principal classes for automated callers); spec at `docs/phases/client-auth/spec.md`. `postern upgrade` remains the later v1 gap. | — |

(status: open / answered / deferred / closed-as-moot)

## Recorded acceptance anchors

| id | anchor | satisfied by |
|----|--------|--------------|
| ACC-CA-IP | Design-success test (user, R2): a specific m2m client may get a cert only from a specific source IP; humans from any IP; all other m2m clients denied — **expressible entirely in Cedar** | `context.principal_class` + `context.client_id` + already-emitted `context.source_ip`; single-IP string equality; "all other m2m denied" falls out of Cedar default-deny. Starter `.cedar` set pinned in spec (sub-phase A acceptance). CIDR/`ip`-type matching is out of scope (future). |

## Notes

Active phase: **client-auth** — spec at `docs/phases/client-auth/spec.md`
(sub-phases A→(B∥C)→D, E follows B, F follow-on). Decisions D-CA-1..9 above;
rulings R1 (naming), R2 (IP success anchor), R3 (TTL feasibility) folded
earlier. Sub-phase F (env-configurable rule list D-CA-8; `principal_class`
required:true + starter strict-validation fix D-CA-9) supersedes two sub-phase-A
spec statements ("rule list is YAML-only"; `principal_class` optional) — spec
corrected this dispatch. The spec carries a "DESIGN.md additions (for round-trip)" section
to fold into `DESIGN.md` at the orchestrator gate (Principal classes subsection
under "Token validation" — now including the propose-and-gate cert-lifetime
paragraph, plus PolicyRequest/context bullet edits naming `principal_class`,
`client_id`, `requested_cert_ttl_minutes`, and a CLI client-credentials note).

Later v1 gap still pending: `postern upgrade` (signed-release + Sigstore). When
that phase opens, expect slices roughly: (a) release-manifest fetch + checksum
verify, (b) Sigstore/cosign-keyless signature + Rekor inclusion verification,
(c) binary swap + atomic self-replace, (d) wrapper-override constructor wiring.
Read `DESIGN.md`'s "Updates are decoupled from the broker" section and the
`.goreleaser.yaml` cosign config before authoring.
