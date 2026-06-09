# Phase spec — client-auth (principal classes for automated callers)

Status: authored 2026-06-08; refined 2026-06-08 (rulings R1–R3, below);
sub-phase F follow-on 2026-06-08 (env-configurable rule list D-CA-8;
`principal_class` required:true + starter strict-validation fix D-CA-9).
Authoritative for this phase. Round-trip the "DESIGN.md additions" section into
`DESIGN.md` at the orchestrator gate.

## Compat boundary (read before any rename)

The **only** backward-compat requirement is the on-the-wire contract between the
**old CLI** and the **new broker**: the request/response JSON on `/ssh/cert`,
`/ssh/tunnel`, `/ssh/time-payload`, plus access-token semantics. Those JSON
field names (`device_id`, `principal_type`, `public_key`, `ssh_cert`,
`max_lifetime_minutes`, …) are frozen.

Everything else is free to rename for clarity:

- **Go-internal identifiers** — `EngineerClaims` and its fields carry no JSON
  tags (verified: `internal/broker/types.go`); they never cross the wire. The
  CLI sends a bearer token and never sees this struct. Renameable.
- **Cedar schema / policy** — no compat requirement; schema and `.cedar` may
  change freely.
- **Audit JSON field names** (`engineer_sub`, `engineer_email`,
  `engineer_groups`) are the CloudWatch-Insights query surface operators filter
  on — **not** the CLI wire. They are *not* renamed here (renaming would break
  operator dashboards for no benefit); this phase only *adds* audit fields.

## Goal

Let the broker distinguish **human users** from **automated callers**
(OAuth2 client-credentials / service accounts) so authorization, cert TTL, and
audit can treat them differently — without a broker-side identity DB and
without any live IdP lookup. The class is inferred from the already-verified
access token via an operator-configurable claim rule, threaded as the single
source of truth into Cedar, cert-TTL selection, and the audit row. The `postern`
CLI gains a client-credentials mode so automated tools run the same binary.

### Locked user decisions (fixed)

- Entry point: CLI gains a client-credentials grant path; the broker also still
  accepts such tokens posted directly.
- Classification: inferred **only from the verified access token**. No
  broker-side identity DB, no live IdP/Cognito lookups. Configurable; must work
  for common IdPs, especially Cognito.
- Blast radius in scope: per-class cert **TTL**; audit rows record class +
  client identity. **Out of scope:** cert principal/identity naming, rate-limit
  partitioning.

### Locked naming (R1 — decided this dispatch)

`EngineerClaims` is now a misnomer (it also carries machine-client claims).
**Locked renames** (all Go-internal; verified to carry no JSON tags):

| old Go symbol | new Go symbol | notes |
|---|---|---|
| `broker.EngineerClaims` (type) | `broker.CallerClaims` | the verifier's output for any caller class |
| `PolicyRequest.Engineer` (field) | `PolicyRequest.Caller` | input to `Policy.Allow` |
| `RateLimitRequest.Engineer` (field) | `RateLimitRequest.Caller` | |
| `engineerContext.Engineer`, `engineerPreambleRequest`/`devicePreambleRequest.Engineer` | `.Caller` | internal preamble plumbing |

**Fields that stay (deliberately not renamed):** `Subject`, `Email`, `Groups`,
`Raw`. A client-credentials token still has a real `sub` (`Subject`); `Email`
and `Groups` are simply empty for machine callers — the names remain accurate,
and churning them touches the SSH-cert `KeyId` builder and audit-stamp sites for
no clarity gain. `keyID()` and the `engineer_*` audit fields keep their existing
spelling (audit JSON is the CloudWatch query surface; see compat boundary).

**New fields on `CallerClaims`:** `Class string`, `ClientID string`.

Rename mechanics: a single rename pass (`EngineerClaims`→`CallerClaims`,
`.Engineer`→`.Caller`) across `internal/broker`, `internal/idp`,
`internal/policy`, and their tests, plus the two new fields. No wire JSON, no
Cedar-name, no audit-JSON changes ride along.

## Background: why classification is by token-claim rule (and Cognito's shape)

Cognito client-credentials (M2M) access tokens carry **no positive "machine"
marker**. They include `sub` (a UUID, not the app-client id), `client_id`,
`scope`, `token_use:access`, `iss`, `exp`, `iat`, `jti`, `version`. They
**omit** `username`, `cognito:groups`, `auth_time`'s user-session companions
(`event_id`, `origin_jti`, `device_key`) that user-pool *user* access tokens
carry. So for Cognito the reliable signal is **absence of `username`** (or
absence of `cognito:groups`), or **presence of an M2M-only scope** the operator
grants exclusively to resource-server app clients.

Other IdPs (Auth0, Okta) usually emit a **positive** marker — e.g. Auth0
`gty: "client-credentials"`, or a custom claim/scope. The rule mechanism must
therefore support both **presence/absence** and **equals-value** predicates,
inside the single generic-OIDC verifier (no Cognito-specific impl).

## Classification design

### Locus: broker derives once, in the verifier path

The verifier (`internal/idp`) already parses the raw claim map. It evaluates the
configured rule and stamps the resulting class onto `broker.CallerClaims`
(new field `Class string`). Every downstream consumer — TTL, audit, Cedar
context — reads that one field. **Cedar does not re-derive the rule.** This is
the single-source-of-truth requirement: TTL and audit are broker decisions made
*around* the Cedar call, so the broker must hold the class; re-encoding the same
predicate inside Cedar would drift from the TTL/audit copy. Cedar receives the
class as an input it trusts, exactly as it already trusts broker-resolved device
attributes.

Rationale for putting it in the verifier (not a separate pipeline step): the
verifier is the one place that already has the parsed claim map and is the
chokepoint every authenticated request passes through. No new pipeline stage,
no second claim-parse.

### Config shape (broker `idp:` section)

Add an optional `principal_classes` block. Absent block → every caller is the
default class `user` (fully backward-compatible; existing deployments unchanged).

```yaml
idp:
  issuer: https://...
  audience: https://broker.example.com
  # New: ordered first-match rule list. Optional.
  principal_classes:
    default: user            # class when no rule matches (optional; defaults to "user")
    rules:
      # Cognito M2M: no username claim on client-credentials tokens.
      - class: machine
        claim_absent: username
      # Auth0/Okta positive marker (alternative form):
      # - class: machine
      #   claim: gty
      #   equals: client-credentials
      # Scope-based marker (alternative form):
      # - class: machine
      #   scope_contains: postern/m2m
```

Per-rule predicate forms (exactly one per rule; validated at load):

| field(s) | semantics |
|---|---|
| `claim_present: <name>` | claim key exists and is non-empty |
| `claim_absent: <name>` | claim key missing or empty |
| `claim: <name>` + `equals: <value>` | claim is a string equal to `<value>`, or a string array containing it |
| `scope_contains: <value>` | the space-delimited `scope` string or `scp` array contains `<value>` |

Semantics: rules evaluated top-to-bottom, **first match wins**; no match → the
`default` class. Class names are operator-defined opaque strings (lowercased,
bounded length); `user` and `machine` are conventional, not reserved. The
verifier caps class length and rejects empty class names at config load.

Env overrides (both apply on top of any file block):

- `POSTERN_IDP_PRINCIPAL_CLASSES` carries the **whole** `principal_classes`
  block as a single JSON (or YAML) document — parsed with the YAML decoder
  (which accepts JSON, the natural shape to emit from IaC) and validated
  identically to a file-provided block. When set it **replaces** any file
  block (no per-rule merge). This is how the Lambda deployment — which mounts
  no config file — configures the structured rule list; the Terraform module
  surfaces it as the `idp_principal_classes_json` variable.
- `POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT` overrides just the default class **on
  top** of the resolved block.

Replace-the-whole-block (not merge) is deliberate: a structured first-match
rule list has no well-defined per-rule merge with a file block, and the env
var's primary deployment (the file-less Lambda) has no file rules to merge
with. The scalar default override stays additive because a single scalar does
compose cleanly.

### How the class reaches each consumer

- **TTL:** the cert-mint pipeline reads `CallerClaims.Class` to select a
  per-class ceiling and to populate the Cedar `requested_*` gate (sub-phase B).
- **Audit:** new `principal_class` and `client_id` fields on `AuditEvent`,
  stamped from `CallerClaims` in the same place `EngineerSub`/`EngineerEmail`
  are stamped today.
- **Cedar:** `PolicyRequest` carries `Caller`; the AVP impl adds
  `principal_class` (and `client_id`) to the `context` map in `contextMap`.

### Client identity for automated callers

Human tokens identify by `sub`/`email`. M2M tokens have a `sub` but it is not a
human; the operationally useful identifier is `client_id`. The verifier reads
the standard `client_id` claim into a new `CallerClaims.ClientID` field
(empty when absent). Audit stamps it; Cedar context exposes it. `Subject`/
`Email` keep their names — `sub` still flows everywhere it does today.

## Cedar surface decision

**Decision: a `context.principal_class` (string) attribute, not a distinct
Cedar principal entity type.**

Why not a typed `Postern::Client` principal: under `IsAuthorizedWithToken` the
principal **entity type is fixed by the AVP identity source**, not by the
broker — the broker cannot choose the principal type per request. Both Terraform
identity-source flavors (Cognito `cognito_user_pool_configuration` and generic
`openid_connect_configuration` with `access_token_only`) map the token to the
schema's single `Postern::User` principal type. Introducing a second principal
type would require identity-source/token-claim-mapping rework (and Cognito's
identity source can't split one user pool into two principal types by a claim).
A broker-injected `context` attribute is uniform across both flavors and needs
no identity-source change — and it keeps the class as a broker-owned input,
consistent with the single-source-of-truth locus above.

### Operator-facing contract

The broker emits `context.principal_class` (string, always present),
`context.client_id` (string, present when the token carries one), and the
already-shipped `context.source_ip` (string) on all three actions. Schema
(`schema.json`) gains the two new context attributes on `MintOperatorCert`,
`MintTimefixCert`, `OpenTunnel`. Because the verifier classifies every request
(defaulting to `user`), `contextMap` emits `principal_class` unconditionally —
so it is declared **`required: true`** in the schema (the broker never omits
it). `client_id` is genuinely optional (a token may carry no `client_id`
claim; `contextMap` adds it only when non-empty), so it stays optional and
policies that reference it must guard with `context has client_id`. (`source_ip`
is already in the emitted context map — verified in `internal/policy/avp.go`
`contextMap` — so the schema either already declares it or gains it alongside.)

The `required: true` for `principal_class` is load-bearing for AVP STRICT
validation: the starter policy references `context.principal_class` without a
`has` guard, which a schema-validated store rejects at `CreatePolicy` unless
the attribute is required. `make check` runs Go tests, not AVP's server-side
Cedar validation (which only happens at `terraform apply`), so this had to be
fixed by reading the schema and starter policy together.

### Design-success scenario (R2 — recorded acceptance anchor)

The phase's success test, expressible **entirely in Cedar**:

> *A specific m2m client may get a cert only when its request comes from a
> specific source IP; human users may from any IP; all other m2m clients are
> denied.*

This is satisfied by `context.principal_class` + `context.client_id` +
`context.source_ip` with no new broker plumbing — `source_ip` is already emitted;
this phase only adds the first two. Default-deny does the "all other m2m clients
denied" work: nothing permits a `machine` caller except the one specific
`permit`, so every other machine request falls through to deny.

`source_ip` is a Cedar **string**. For the success test — a single exact IP — a
plain string equality (`context.source_ip == "203.0.113.7"`) suffices and is
what the starter policy uses. CIDR/range matching would need Cedar's `ip`
extension type and a broker change to emit `source_ip` as an `ip` value; that is
**out of scope** for this phase (a future enhancement, noted in non-goals), not
required by the success test.

### Starter policy set (lands at `terraform/postern-broker/cedar/starter.cedar`)

The engineer writes this file; the spec pins its content. It demonstrates the
success scenario on top of Cedar's implicit default-deny:

```cedar
// Default-deny is implicit in Cedar: a request is authorized only if some
// `permit` matches and no `forbid` matches. Nothing below permits an
// unlisted machine caller, so "all other m2m clients are denied" follows
// from the absence of a matching permit.

// (1) Human users: any source IP, all device actions.
permit (
  principal,
  action in [
    Postern::Action::"MintOperatorCert",
    Postern::Action::"MintTimefixCert",
    Postern::Action::"OpenTunnel"
  ],
  resource
) when {
  context.principal_class == "user"
};

// (2) One specific service account: operator certs only, and only from its
// pinned source IP. Exact string match is sufficient for a single IP.
permit (
  principal,
  action == Postern::Action::"MintOperatorCert",
  resource
) when {
  context.principal_class == "machine" &&
  context has client_id &&
  context.client_id == "EXAMPLEm2mclientid" &&
  context.source_ip == "203.0.113.7"
};

// No permit covers any other machine caller, nor this client from any other
// IP — those requests fall through to the implicit default-deny.
```

The `context has client_id` guard is required: `client_id` is an optional
context attribute, so a strict-validated store rejects an unguarded reference at
`CreatePolicy`. `principal_class` needs no guard — it is `required: true`.

The class string in policy must match the class names the operator configured in
`idp.principal_classes`. That coupling is the operator-facing contract; it lives
in the broker config + the policy store, never in code.

## CLI client-credentials design

### Profile config / secret shape

`Profile.IDP` gains an optional `grant` field; default (`""`/`authorization_code`)
is today's PKCE browser flow. `grant: client_credentials` selects the new path.

```yaml
default:
  broker: https://broker.example.com
  idp:
    issuer: https://...
    client_id: <m2m-app-client-id>
    audience: https://broker.example.com   # or scopes:
    grant: client_credentials
    # secret is NOT read from YAML; see env below
```

The **client secret is never read from the config file.** It is sourced from
`<PREFIX>_IDP_CLIENT_SECRET` (e.g. `POSTERN_IDP_CLIENT_SECRET`), matching the
existing rule that bearer/secret material lives in env, not world-readable YAML.
Validation: when `grant: client_credentials`, the env secret must be present at
login/use time; its absence is a clear actionable error. The PKCE path rejects
the secret env var being set together with `grant: authorization_code` only if
we want strictness — keep it lenient (ignore) to avoid surprising wrappers.

### Code path

- `internal/oauthlogin` gains a `ClientCredentialsToken` entrypoint using
  `golang.org/x/oauth2/clientcredentials` (already in the dependency tree via
  `golang.org/x/oauth2`). No browser, no PKCE, no loopback callback. It performs
  discovery for the token endpoint (reuse the existing `oidc.NewProvider` →
  `Endpoint().TokenURL`), then a client-credentials token request carrying
  `audience`/`resource` (via the configured `audience_param`) and/or `scopes`.
- It does **not** require a refresh token. Client-credentials grants have no
  refresh token; the `ErrOAuthLoginMissingRefreshToken` gate is PKCE-only and is
  not on this path.
- Token lifecycle: **re-mint on demand.** Because re-minting needs only the
  client_id + secret (no human interaction), the CLI does not need durable
  refresh state. `defaultAccessToken` branches on `grant`: for
  `client_credentials` it mints a fresh token each invocation (or caches in
  memory for the process), bypassing the tokenstore entirely. This sidesteps the
  tokenstore's `RefreshToken`-required invariant — no schema change, no
  bypassing of `validateState`.
- `postern login` with `grant: client_credentials` performs one token mint to
  validate the credentials and prints "Authenticated as client <client_id>",
  but persists nothing (or persists nothing requiring a refresh token). This
  keeps `login` meaningful (credential check) without forcing a token store.

### `--no-browser` interaction

Client-credentials is inherently browserless; `--no-browser` is a no-op on this
path (no contradiction, no error). The flag stays a PKCE-path concern.

## Cert-TTL feasibility ruling (R3)

The user asked: "if Cedar can specify TTL that would be neat." Straight ruling:

- **Cedar cannot emit a TTL value the broker reads.** AVP
  `IsAuthorizedWithToken` returns only a `Decision` (Allow/Deny) — there is no
  channel for Cedar to hand back a number. So "Cedar names the TTL" is not
  possible.
- **Cedar can gate a broker-proposed TTL.** The broker passes a *requested*
  lifetime as Cedar context and lets policy permit only when it is within bounds
  — exactly the tunnel precedent: `internal/broker/tunnel.go` injects
  `context.requested_max_lifetime_minutes` (an `int64`) and operators write
  `when { context.requested_max_lifetime_minutes <= N }`. The broker proposes;
  Cedar gates.

**Decision — option (c): static per-class default + optional request-and-gate.**

1. Broker config carries a per-class **hard ceiling** and default
   (`cert_ttl.by_class`). This is the floor of the design and always present.
2. The CLI may *request* a specific cert lifetime; the broker clamps it to the
   per-class ceiling, then passes the (clamped, defaulted) value to Cedar as
   `context.requested_cert_ttl_minutes` so operators can tighten per
   fleet/class/client in policy — mirroring the tunnel TTL gate.
3. The applied window is **always** `min(request, broker per-class ceiling)`,
   and Cedar can only ever *deny* (tighten), never widen. A request above the
   ceiling is clamped down (not denied) — matching how the tunnel default is
   substituted before Cedar sees it, so an omitted request can't bypass a
   `<= N` policy. `OperatorClockSkewPadding` (1h) still applies to `ValidAfter`;
   the resulting window is always bounded by the broker ceiling, never unbounded
   or absurd.

Why (c) over (a)-only or (b)-only: (a) (static map alone) ignores the user's
intent; (b) (request-and-gate alone) drops the always-present per-class ceiling
that bounds the blast radius when no policy gate is written. (c) reuses the
tunnel precedent for the optional request, keeps a broker-enforced hard ceiling
regardless, and adds one context attribute plus one config map — small surface.

## Sub-phases

Dependency order: A → (B ∥ C) → D; E follows B. B and C are independent of each
other and can land in either order once A merges. D depends only on A (it needs
the broker to accept and classify M2M tokens to be end-to-end testable) and can
overlap B/C. E (the CLI cert-lifetime flag deferred from B) depends on B's
`SSHCertIssueRequest.MaxLifetimeMinutes` wire field.

### A. Broker classification core + Cedar context wiring + sample policy

- Deliverable: rename `EngineerClaims`→`CallerClaims` (+ `.Engineer`→`.Caller`)
  per R1; verifier derives `Class` + `ClientID` from the configured rule; both
  flow on `CallerClaims`; AVP `contextMap` emits `principal_class` + `client_id`;
  schema + starter-policy file updated.
- Files: `internal/broker/types.go` (rename + `CallerClaims.Class`, `.ClientID`;
  `PolicyRequest.Caller`, `RateLimitRequest.Caller`); `internal/broker/`
  preamble/sshcert/tunnel/issuetimepayload/denial (`.Engineer`→`.Caller` call
  sites); `internal/idp/oidc.go` (rule eval, claim reads); new rule config type
  in `pkg/brokerhandlers/config.go` (`IDPConfig.PrincipalClasses`, validation,
  default-fill, env for default); `internal/policy/avp.go` (`contextMap`);
  `terraform/postern-broker/cedar/schema.json` (+2 optional context attrs ×3
  actions); `terraform/postern-broker/cedar/starter.cedar` (the starter policy
  set above).
- Acceptance: a token matching no rule classifies as `user`; a Cognito-shaped
  token without `username` classifies `machine` under a `claim_absent: username`
  rule; an Auth0-shaped token classifies `machine` under `claim`+`equals`; AVP
  context carries `principal_class` + `client_id` (and the existing `source_ip`);
  absent `principal_classes` block leaves every caller `user`.
- Acceptance (design-success scenario, R2): with the starter `.cedar` above and
  the `claim_absent: username` rule, evaluate `MintOperatorCert` four ways and
  confirm Cedar Allow/Deny: (a) a `user` token from any IP → Allow; (b) the
  pinned `machine` `client_id` from `203.0.113.7` → Allow; (c) the same
  `machine` `client_id` from any other IP → Deny; (d) any other `machine`
  `client_id` → Deny. Expressed as an AVP `contextMap` + policy-evaluation
  assertion (or a Cedar-eval table test over the four context tuples).
- Tests: verifier table tests for each predicate form (present/absent/equals/
  scope_contains), first-match ordering, default fallback, class-length/empty
  validation; config Validate tests (malformed rule: zero or multiple predicate
  fields per rule → error); AVP `contextMap` test asserting the two new keys and
  that reserved keys still can't be shadowed.

### B. Per-class cert TTL ceiling + Cedar-gated request (R3, option c)

- Deliverable: operator cert validity window = `min(CLI-requested lifetime,
  per-class broker ceiling)`, with the resolved value surfaced to Cedar as
  `context.requested_cert_ttl_minutes` so policy can tighten further (deny only).
- TTL resolution (operator certs only; timefix's 1970→3000 window is fixed and
  class-independent):
  1. Ceiling = `cert_ttl.by_class[class]`, falling back to the existing
     operator default (`operator:` / `DefaultOperatorCertTTL`) when the class is
     unmapped.
  2. Requested = the CLI's optional `max_lifetime_minutes` on `/ssh/cert` (zero/
     absent → the ceiling itself, i.e. today's behavior).
  3. Resolved = `min(requested, ceiling)`. Reject a negative request with a
     `400` and a stable `denied_reason` (mirror the tunnel `max_lifetime_exceeds_
     ceiling` shape; a request *above* the ceiling is **clamped down, not
     denied**, matching the tunnel default-substitution rule so an omitted
     request can't bypass a `<= N` Cedar gate).
  4. `resolveDevice` injects `PolicyContext{"requested_cert_ttl_minutes":
     int64(resolved)}` (same mechanism as tunnel's
     `requested_max_lifetime_minutes`). Cedar may deny; it never widens.
  5. `validBefore = now + resolved`; `validAfter = now - OperatorClockSkewPadding`
     (unchanged).
- Files:
  - `pkg/brokerhandlers/config.go` — `CertTTLConfig` gains `by_class` map
    (e.g. `by_class: {user: 12h, machine: 1h}`); keep `operator:` as default/
    fallback. Validate: non-positive class TTL rejected (mirror
    `ErrCertTTLOperatorPositive`); a per-class ceiling must be a positive
    `time.Duration`.
  - `internal/broker/types.go` — add `MaxLifetimeMinutes int32
    \`json:"max_lifetime_minutes,omitempty"\`` to `SSHCertIssueRequest`. This is
    a **new optional** wire field; old CLIs omit it (zero → ceiling), so the
    old-CLI/new-broker compat holds.
  - `internal/broker/sshcert.go` — accept a per-class ceiling map on
    `SSHCertIssuerDeps`/`SSHCertIssuer`, resolve TTL as above, inject the
    `requested_cert_ttl_minutes` PolicyContext, reuse the tunnel deny-reason
    pattern for a negative request.
  - `cmd/broker` + `cmd/broker-lambda` — wire the per-class map into the issuer
    constructor.
  - CLI (`pkg/cliapp`) — the engineer-facing flag that feeds this request field
    is **deferred to sub-phase E** (see below). The broker-side acceptance here
    needs no CLI change; old/new CLIs that omit the field get the ceiling.
    **Resolved by E** (D-CA-7): the flag is named `--cert-max-lifetime` (distinct
    from the tunnel `--max-lifetime`) and lands on `mint`/`ssh`/`scp`.
- Acceptance: a `machine` caller with no request gets the machine ceiling; a
  `user`/unmapped caller gets the operator default; a request below the ceiling
  is honored; a request above the ceiling is clamped to the ceiling (not
  denied); a negative request is a `400`; Cedar sees
  `context.requested_cert_ttl_minutes` = the resolved value and a
  `when { context.requested_cert_ttl_minutes <= N }` policy denies a resolved
  value above `N`; timefix window unchanged.
- Tests: `sshcert_test.go` — `ValidBefore` per class; default fallback when
  class is unmapped; request-below-ceiling honored; request-above-ceiling
  clamped; negative-request `400`; `PolicyContext` carries
  `requested_cert_ttl_minutes` as `int64(resolved)`. Config Validate — non-
  positive class TTL rejected. AVP `contextMap` test asserting the gated value
  is emitted as a Cedar `Long` (it already maps `int64`→`Long`).

### C. Audit class + client-identity stamping

- Deliverable: every audit row (authorized / issued / denied across all three
  pipelines) carries `principal_class` and `client_id` when known.
- Files: `internal/broker/types.go` (`AuditEvent.PrincipalClass`,
  `.ClientID` JSON fields); `internal/broker/preamble.go` (stamp onto the
  templates where `EngineerSub`/`EngineerEmail` are set); `internal/broker/`
  sshcert/tunnel/issuetimepayload (carry through their authorized/issued rows).
- Acceptance: success pairs and post-identity denies carry the class; pre-
  identity denies (invalid token, missing bearer) omit it, consistent with how
  `engineer_sub` is omitted there.
- Tests: audit-row assertions in each pipeline's existing tests extended for the
  two fields; deny-path test confirms absence pre-identity.

### D. CLI client-credentials mode

- Deliverable: `grant: client_credentials` profile path; env-sourced secret;
  browserless token mint; re-mint-on-demand lifecycle.
- Files: `pkg/cliapp/profile.go` (`IDPConfig.Grant`, validation); `pkg/cliapp/`
  env wiring for `<PREFIX>_IDP_CLIENT_SECRET`; `internal/oauthlogin/` new
  client-credentials entrypoint; `pkg/cliapp/defaults.go` (`defaultAccessToken`
  + `defaultLoginRunner` branch on grant). No tokenstore schema change.
- Acceptance: with `grant: client_credentials` and the secret env set,
  `postern mint`/`ssh`/`tunnel` obtain a broker-accepted token with no browser;
  `postern login` validates creds and prints the client identity; missing secret
  yields an actionable error; the PKCE path is unchanged when `grant` is unset.
- Tests: oauthlogin client-credentials unit test against a fake token endpoint
  (no refresh token in response is fine); profile Validate test for the new
  grant + secret-presence; `defaultAccessToken` branch test (in-memory mint, no
  store touched).

### E. CLI cert-lifetime request flag (follow-on; deferred from B)

- Deliverable: an engineer-facing flag that feeds the sub-phase-B
  `SSHCertIssueRequest.MaxLifetimeMinutes` field. Named **`--cert-max-lifetime`**
  (a `time.Duration`) on `mint`, `ssh`, and `scp`. Zero/absent → omit the field
  (today's behavior: broker substitutes the per-class ceiling); a positive value
  is sent for the broker to clamp; a **negative** value is rejected client-side
  before any broker round-trip.
- Cert-vs-tunnel-flag distinction (D-CA-7): the name is deliberately distinct
  from the existing `--max-lifetime`, which on `ssh`/`scp` means the **tunnel**
  TTL, not the cert TTL. The two are independent: `--cert-max-lifetime` feeds the
  cert request's `MaxLifetimeMinutes`; `--max-lifetime` feeds the tunnel-open
  request. On one invocation they map to different request fields and must not
  cross. (`mint` has no tunnel, so it carries only `--cert-max-lifetime`.)
- Files: `pkg/cliapp/certflow.go` (new `certLifetimeMinutesFromDuration` helper —
  sibling of the tunnel `lifetimeMinutesFromDuration`, but with **no client-side
  ceiling**: the broker clamps, so the CLI only rejects negatives; thread
  `certMaxLifetimeMinutes int32` through the shared `mintAndCache`/
  `ensureFreshCert` chokepoint); `pkg/cliapp/mint.go`, `ssh.go`, `scp.go`
  (flag + plumbing); `pkg/cliapp/sshargv.go` (`flagCertMaxLifetime` const);
  `pkg/cliapp/tunnel.go` (`tunnelDial` gains the cert-minutes param);
  `pkg/cliapp/tunnel_open.go`, `addhost.go` (pass `0` — neither has the flag).
- Acceptance: `--cert-max-lifetime 1h` lands as `MaxLifetimeMinutes=60` in the
  cert request on `mint`/`ssh`/`scp`; omitting it leaves the field zero;
  a negative value short-circuits with a stable client-side error and no broker
  call; on `ssh --tunnel` both flags set map to their separate fields without
  crossing; the user-resolution chokepoint and the tunnel flag are untouched.
- Tests: `mint_test.go`, `ssh_test.go`, `scp_test.go` — flag populates the cert
  request; omitted leaves zero; negative rejected before any round-trip; ssh
  cert-vs-tunnel independence.

## Non-goals (explicit)

- **Cert principal/identity naming** — M2M certs keep the existing
  `device-{serial}-operator` principal; no new principal string.
- **Rate-limit partitioning** — the per-engineer/`sub` rate-limit key is
  unchanged; classes are not a rate-limit dimension in this phase.
- **A second IdP impl** — classification stays inside the one generic-OIDC
  verifier; no Cognito-specific impl.
- **Broker-side identity DB / live IdP or Cognito lookups** — classification is
  pure token-claim evaluation.
- **Typed Cedar principal entities** for the class — class is a context
  attribute (see Cedar decision).
- **Cedar `ip`/CIDR matching on `source_ip`** — `source_ip` stays a Cedar
  string; the design-success scenario needs only single-IP equality. Emitting
  `source_ip` as a Cedar `ip` extension value for CIDR/range policies is a
  future enhancement, not this phase.
- **Cedar-emitted TTL values** — Cedar gates a broker-proposed lifetime
  (deny-only); it does not return a number the broker reads (R3).

## Whole-phase acceptance criteria

1. A Cognito M2M token (no `username`) and an Auth0/Okta M2M token (positive
   marker) both classify as `machine` under appropriate operator config; a user
   token classifies as `user`; absent config → all `user`.
2. The class is derived exactly once (verifier) and consumed by TTL, audit, and
   Cedar from that one field — no duplicated predicate.
3. Cedar policies can branch on `context.principal_class` and `context.client_id`
   under both AVP identity-source flavors with no identity-source change.
4. `machine` callers' operator certs are bounded by the per-class ceiling;
   default/unmapped classes fall back to the operator default; a CLI-requested
   lifetime is honored only up to the ceiling (clamped, not denied, when over);
   Cedar can tighten via `context.requested_cert_ttl_minutes` but never widen;
   `OperatorClockSkewPadding` still applies; timefix window unchanged.
5. Audit rows carry `principal_class` + `client_id` where identity is known.
6. The `postern` CLI obtains a broker-accepted token via client-credentials with
   no browser and no refresh-token dependency; the PKCE path is untouched.
7. No new abstraction impl; no identity DB; no live IdP lookup; no rate-limit or
   cert-principal change. `make check` green.

## DESIGN.md additions (for round-trip)

Add a subsection under "Token validation" (after the validation-criteria list,
before "Authorization policy"), titled **Principal classes**:

> Beyond verifying the token, the broker classifies each caller into a
> **principal class** so authorization, certificate lifetime, and audit can
> treat automated callers differently from humans. The class is inferred purely
> from claims already present in the verified access token — there is no
> identity database and no live IdP lookup. Operators configure an ordered list
> of first-match rules; each rule maps a claim predicate (a claim being present,
> absent, equal to a value, or a scope being present) to a class name, with a
> default class when no rule matches. The default configuration classifies every
> caller as a human user, so deployments that don't need the distinction are
> unaffected.
>
> The mechanism accommodates how different providers mark machine-to-machine
> tokens. Some providers emit a positive marker (a grant-type claim or a custom
> claim/scope granted only to service-account clients); others, notably Cognito,
> emit no positive machine marker, so the distinguishing signal is the *absence*
> of a user-only claim (such as the user's username) on a client-credentials
> token. Supporting both presence and absence predicates lets one generic OIDC
> verifier classify either family without a provider-specific implementation.
>
> The class is derived once, by the verifier, and becomes the single source of
> truth. The broker uses it to bound the certificate validity window by a
> per-class ceiling, to stamp the class (and, for automated callers, the issuing
> client identifier) onto every audit row, and to supply the class and client
> identifier to the authorization layer as request context. The authorization
> layer does not re-derive the class; it consumes the broker's classification as
> a trusted input, the same way it consumes broker-resolved device attributes.
> This keeps the lifetime, audit, and policy views of "who is calling" from
> drifting.
>
> Certificate lifetime follows a propose-and-gate model. The caller may request
> a lifetime; the broker clamps it to the per-class ceiling and supplies the
> resolved value to the authorization layer as request context, so policy can
> tighten it further per fleet, class, or client. The authorization layer can
> only deny, never widen: the applied window never exceeds the broker's
> per-class ceiling, and the usual clock-skew padding still applies. This mirrors
> how the tunnel pipeline already gates a requested tunnel lifetime through
> policy context. The authorization service returns only an allow/deny decision,
> so it never names a lifetime the broker reads back — it gates a value the
> broker proposes.
>
> The class is delivered to the policy layer as request **context**, not as a
> distinct principal entity type. Under token-based authorization the principal
> entity type is fixed by the policy service's identity source, not chosen by
> the broker per request, and both supported identity-source flavors map a token
> to the same principal type. Expressing the class as a context attribute is
> uniform across identity sources, requires no identity-source change, and keeps
> the class a broker-owned input consistent with its role as the single source
> of truth. Policies branch on the class and client identifier through context
> conditions.

Also extend the existing `PolicyRequest` sketch's `Context` note and the
"The broker per-request call passes" Context bullet to mention the
`principal_class`, `client_id`, and `requested_cert_ttl_minutes` context
attributes (alongside the already-documented `source_ip` and the tunnel's
`requested_max_lifetime_minutes`). `principal_class` is always present
(required in the policy schema); `client_id` is present only for tokens that
carry it.

The "Config is YAML + env" narrative round-trips separately, but keep it
accurate: the `principal_classes` rule list is configurable **both** as a file
block and via the `POSTERN_IDP_PRINCIPAL_CLASSES` env var (a JSON/YAML
document, replacing any file block), which is how the file-less Lambda
deployment carries it; `POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT` overrides just the
default class on top.

Add to the CLI/engineer-onboarding narrative (the section describing
`postern login` and the YAML snippet) a sentence noting that automated callers
configure `grant: client_credentials` with the client secret supplied via
environment (never the config file), and that this path is browserless and
needs no cached refresh token because the credentials can re-mint on demand.

> Mermaid (optional, for the Principal classes subsection):
>
> ```mermaid
> flowchart LR
>   T[Verified access token] --> R{First-match<br/>claim rule}
>   R -->|match| C[principal_class]
>   R -->|no match| D[default class]
>   C --> TTL[per-class cert TTL]
>   C --> AUD[audit row]
>   C --> CTX[Cedar context.principal_class]
>   D --> TTL
>   D --> AUD
>   D --> CTX
> ```
