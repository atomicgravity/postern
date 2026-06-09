# Phase: broker aud/scope match — AND → OR

Authoritative spec for the `broker-aud-scope` change. Architect-owned;
engineer implements against this. Docs-only edits already landed (DESIGN.md,
CLAUDE.md, AGENTS.md round-trip). This phase touches source/tests.

## Problem

The broker's access-token verifier (`OIDCVerifier.VerifyAccessToken`,
`internal/idp/oidc.go`) validates audience and required-scope with **AND**
semantics: when both `idp.audience` and `idp.required_scope` are configured, a
token must satisfy *both* (two sequential reject branches, ~lines 185–190).

Real-world break (Cognito, verified with a live token): **human** tokens carry
`aud` (set via the RFC 8707 `resource` param) but **machine** (client-credentials)
tokens carry **no `aud`, only a `scope`** (`{"token_use":"access","scope":
"default-m2m-resource-server-7f300l/read","client_id":"…"}`, no `aud`). With AND
there is no single config that accepts both caller types: audience-only rejects
machines, scope-only rejects humans, both-configured rejects everyone.

CLAUDE.md / AGENTS.md / DESIGN.md already document the intent as *"validates `aud`
**and/or** `scope`"* — the AND implementation mismatches the documented contract.

## Semantics ruling

**Implicit AND → OR. No new config knob.** When both `idp.audience` and
`idp.required_scope` are configured, accept the token if **either** the audience
match **or** the scope match succeeds. When only one is configured, require that
one (unchanged). This is the documented "and/or" made true, costs zero config,
and keeps one-concrete-impl/minimal-config ethos intact. An explicit
`audience_scope_match: any|all` knob was considered and rejected: it adds a
config surface, a validation path, a Terraform variable, and an env override to
serve a hypothetical operator who wants strict-AND across a *single* IdP whose
two caller classes are partitioned by `aud` vs `scope` — the exact case OR
exists to serve. Cross-app isolation (the security property AND was thought to
protect) is fully preserved by OR: a token must still carry **at least one**
configured proof; a token with neither is rejected (see invariants). If a real
operator ever needs strict-AND, that is a future explicit knob with a named
rationale, not a v1 speculative one.

**Backward-compat:** single-config deployments (audience-only or scope-only) are
**byte-for-byte unchanged** — only one branch was ever active. The *only*
behavior change is a deployment that configured BOTH and relied on AND to reject
tokens carrying one proof but not the other. That deployment is broadening
acceptance from "both proofs" to "either proof." Assessment: low real-world risk
— the AND-both config is the one that rejects *everyone* in the mixed
human+machine Cognito case (so it's unlikely to be in production intentionally),
and any deployment that set both did so following docs that said "and/or." A
CHANGELOG entry under the next `feat:`/`fix:` is sufficient; no migration tooling.

## Validation rule (pseudocode)

Replace the two sequential reject branches with a single merged check that runs
in the **same position** (after `token_use`, before `iat`):

```
matchedAudience := v.audience != "" && slices.Contains(token.Audience, v.audience)
matchedScope    := v.requiredScope != "" && hasScope(claims.Scope, claims.SCP, v.requiredScope)

if !matchedAudience && !matchedScope {
    return CallerClaims{}, errors.New("access token missing required audience or scope")
}
```

Notes:
- A `matched*` flag is **false** when its field is unset — an unset check is
  never a *proof of acceptance*. With a single field configured, that field's
  match is the sole gate (single-config behavior preserved exactly); the unset
  field contributes nothing. **Do NOT** write this as
  `audOK := v.audience == "" || match`: that makes an unset field default to
  `OK=true`, and `!audOK && !scopeOK` then **fail-OPENs** a single-config
  deployment (the configured check is never enforced). The
  `matched* := field != "" && match` form is the correct one.
- Neither configured ⇒ both flags false ⇒ **reject (fail-closed)**. This can't be
  reached normally (`NewOIDCVerifier` rejects both-empty via
  `ErrAudienceOrScopeRequired`, `Config.Validate` via
  `ErrIDPAudienceOrRequiredScopeRequired`), but the merged check is now
  fail-closed even if a wrapper constructs the verifier directly — a hardening
  over the prior two-branch logic, which fail-OPENed on both-empty and relied
  solely on the construction guard.
- `hasScope` (exact match: splits space-delimited `scope`, checks `scp` array
  for an exact element) and audience array-membership (`slices.Contains`) are
  **unchanged** — no substring matching anywhere.

## Preserved security invariants (hard acceptance criteria)

1. **Cross-app isolation holds.** A token whose `aud` ≠ configured audience AND
   whose scopes lack the required scope is **REJECTED**. OR broadens only to "has
   ≥1 of the two configured proofs," never to "no proof."
2. **Exact matching only.** Scope match stays exact-element (no substring):
   required `a/read` rejects `a/readonly` and `a/read-x`. Audience stays exact
   array-membership.
3. **All other validations still run and still independently reject**, in
   unchanged order: go-oidc signature + `iss` + `exp` (+ asymmetric-alg pin),
   `token_use == "access"` (when present), `iat` future-skew (`iatFutureSkew`)
   and max-age (`iatMaxAge`), non-empty `sub`, `sub`/`email` rune caps. The OR
   path must NOT short-circuit any of these.
4. **Fail-closed config unchanged.** Both-empty config still rejected at
   construction (`ErrAudienceOrScopeRequired`).
5. **Fail-closed runtime on neither-configured.** The merged check rejects all
   tokens when neither field is set (both flags false ⇒ reject) — defense-in-depth
   over the prior two-branch logic, which fail-OPENed in that case and leaned
   solely on the construction guard.
6. **Single-config still enforced.** With exactly one field configured, that
   field's check is the sole gate; a token failing it is REJECTED (the unset
   field must not turn the merged check into a no-op — the fail-open trap above).

## Security test matrix (engineer MUST implement all)

All in `internal/idp/oidc_test.go`, using the existing `oidcFixture` /
`newVerifier(audience, scope)` / `signToken` helpers. Group the OR cases in a
new table-driven `TestVerifyAccessTokenAudienceScopeOR`; fold the
exact-scope-precision cases into a sibling table. Each named case + outcome:

**Audience-only config** (`newVerifier(aud, "")`):
- `aud-only/match` — token `aud` contains configured → **ACCEPT**
- `aud-only/wrong` — token `aud` = different value → **REJECT**
- `aud-only/absent` — token has no `aud` claim → **REJECT**

**Scope-only config** (`newVerifier("", scope)`):
- `scope-only/match` — token `scope` contains configured → **ACCEPT**
- `scope-only/absent` — token has no `scope`/`scp` → **REJECT**
- `scope-only/wrong` — token `scope` = unrelated scopes → **REJECT**

**Both-configured (OR)** (`newVerifier(aud, scope)`):
- `both/aud-only-present` — has `aud`, no matching scope → **ACCEPT** (the human/Cognito case)
- `both/scope-only-present` — has scope, no `aud` → **ACCEPT** (the machine/Cognito case)
- `both/both-present` — has both → **ACCEPT**
- `both/neither-present` — wrong `aud` + wrong scope → **REJECT** (the load-bearing case)
- `both/aud-absent-scope-absent` — no `aud` claim, no `scope`/`scp` claim → **REJECT**

**Cross-app adversary** (`newVerifier(aud, scope)`):
- `cross-app/other-app-token` — same issuer, `aud` = another app's resource id
  AND `scope` = another app's scope (token validly issued for App B in a shared
  pool) → **REJECT**

**Exact-scope precision** (`newVerifier("", "a/read")`):
- `scope-exact/prefix-collide-readonly` — token scope `a/readonly` → **REJECT**
- `scope-exact/suffix-collide-read-x` — token scope `a/read-x` → **REJECT**
- `scope-exact/match-within-multi-scope-string` — scope `openid a/read x/y` → **ACCEPT**
- `scope-exact/match-within-scp-array` — no `scope`, `scp: ["openid","a/read"]` → **ACCEPT**

**Audience multi-value** (`newVerifier(aud, "")`):
- `aud-multi/match-one-of-many` — `aud: ["x","<configured>","y"]` → **ACCEPT**
- `aud-multi/none-match` — `aud: ["x","y"]` → **REJECT**

**OR path does not bypass other rejections** (`newVerifier(aud, scope)`, token
satisfies aud-or-scope but fails one orthogonal check — each → **REJECT**):
- `or-no-bypass/token_use-id` — valid aud, `token_use: "id"` → REJECT (`token_use must be access`)
- `or-no-bypass/iat-future` — valid scope, `iat` 1h ahead → REJECT (`iat is in the future`)
- `or-no-bypass/iat-too-old` — valid aud, `iat` 25h old → REJECT (`exceeds maximum age`)
- `or-no-bypass/empty-sub` — valid aud, `sub: ""` → REJECT (`sub claim is required`)
- `or-no-bypass/wrong-signature` — valid aud, signed with other key → REJECT (`failed to verify signature`)

Additional adversarial cases:
- `or/empty-string-aud-and-scope-claims` — `aud: []`, `scope: ""`, both
  configured → **REJECT** (empty claims are not proofs).
- `fail-closed/neither-configured` — verifier with **empty** audience AND
  **empty** required scope, a valid well-formed token → **REJECT**. Construct the
  `OIDCVerifier` struct directly (in-package test) with the fixture's signature
  verifier but empty `audience`/`requiredScope`, to exercise the runtime path the
  construction guard normally prevents. Documents the fail-closed hardening
  (invariant 5).

Total: **25 named cases.** Keep the existing
`TestVerifyAccessTokenAcceptsValidToken` (happy path) and
`TestHasScopeSupportsScopeAndSCPClaims` (unit) as-is — they still pass.

## Error-message decision

Merged rejection text: **`"access token missing required audience or scope"`**.

Existing tests in `internal/idp/oidc_test.go` assert the OLD strings and **must
be updated**:
- `TestVerifyAccessTokenRejectsMisbuiltTokens` case `"audience missing required
  value"` asserts `"missing required audience"` — its config sets BOTH aud+scope,
  and the mutate only breaks `aud`, so under OR the scope still matches and the
  token is now **ACCEPTED**. This case must be **reworked**: to keep asserting an
  audience-driven rejection, change it to **audience-only** config
  (`newVerifier(aud, "")`) so breaking `aud` is the sole proof. Then assert the
  new merged string. Same for case `"audience is client-id-shaped value"`
  (audience-only config, assert merged string).
- Case `"scope missing required value"` asserts `"missing required scope"` —
  same issue (both configured, only scope broken → now ACCEPTED under OR). Rework
  to **scope-only** config and assert the merged string.
- The non-aud/scope cases in that table (`wrong signature`, `token_use is id`,
  `iat in the future`, `iat older than 24h`) are unaffected — their asserts stay.

## Files the engineer will touch

- `internal/idp/oidc.go` — replace the two sequential aud/scope reject branches
  with the merged OR check + new error string. No signature/struct changes.
- `internal/idp/oidc_test.go` — rework the three aud/scope cases above; add the
  24-case OR matrix.
- **No config change needed.** `pkg/brokerhandlers/config.go` already permits
  both fields set and only fails closed when both are empty
  (`ErrIDPAudienceOrRequiredScopeRequired`, line 476). `Config.Validate` needs no
  edit — both-configured was always a legal config; only the runtime semantics
  change.
- CHANGELOG: a `fix:`-flavored note ("broker now accepts a token satisfying
  *either* configured `idp.audience` or `idp.required_scope` when both are set,
  matching the documented and/or contract; previously required both").

## Out of scope

- No explicit match-mode config knob (ruled out above).
- No change to `hasScope` / audience-membership matching logic.
- No principal-class, TTL, or Cedar-context changes (separate `client-auth` phase).
