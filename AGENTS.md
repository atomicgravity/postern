# AGENTS.md

Guidance for AI agents working in this repository.

## What this repo is

Postern is an open-source framework for SSH access to embedded Linux device fleets — short-lived certificate auth gated by SSO, with handling for offline devices, firewalled devices, and devices with broken clocks. The design is captured in `DESIGN.md`. The repo is **v1 in flight**: the broker (long-running + Lambda), the engineer CLI (`login`, `mint`, `ssh`, `scp`, `add-host`, `remove-host`, `cache`, `tunnel`, `timefix`, `logout`, `configure`, `version`), the on-device timefix path (`cmd/timefix-apply` + `cmd/timefix-set-clock`), all v1 default abstraction impls (KMS Signer, DynamoDB Registry + RateLimit, AVP Policy, CloudWatch Audit, generic OIDC IdP verifier, AWS IoT Secure Tunneling), the pure-Go AWS V3 secure-tunneling source proxy powering `postern ssh --tunnel` / `postern scp --tunnel` / `postern tunnel`, and the AWS Terraform reference module at `terraform/postern-broker/` are implemented end-to-end. The `postern upgrade` signed-release subcommand is the only remaining v1 gap (placeholder in the CLI; signed-release fetch + Sigstore verification still to land). Current state and punch list: `docs/team-handoff.md`.

## What goes here vs elsewhere

- **In-scope for this repo**: anything generic to embedded-device-fleet SSH access. The cloud broker, engineer CLI (`postern`), on-device timefix binaries, the abstractions (IdP / Signer / Tunneling / Audit / Registry) with their default implementations, IaC reference templates, packaging examples.
- **Out-of-scope**: anything organization-specific or branding-specific. Postern is intentionally generic so downstream operators can wrap it with their own tooling. If a feature only makes sense for one operator or has a baked-in name/brand assumption, it belongs in their wrapper, not in Postern.

## Read this first

When opening this repo, read `DESIGN.md` end-to-end before touching code or making proposals. The doc captures:

- Why Postern exists (the recurring problem and the alternatives we considered)
- Why the specific design choices (one CA vs three, JWS vs CMS, file capabilities vs SUID, hardware serial vs cloud-derived identity, broker-mediated tunneling vs direct, etc.)
- The component shape and wire formats
- The wrapping pattern that downstream operators rely on

Don't reinvent any of these decisions without first checking what `DESIGN.md` says about them. If you have a reason to revisit a decision, surface that as an explicit reconsideration with the original rationale named.

## Critical context

### Postern is a complete unwrapped product, with wrapping possible at well-defined seams

Postern's primary mode is **unwrapped**: an operator runs `postern` directly. Postern-branded defaults apply. The CLI, broker, and on-device binaries work end-to-end with no wrapper. **This is a complete product**, not a foundation that requires wrapping to be useful.

A **wrapped** mode is also supported, but is not the primary design driver: an operator imports Postern's building blocks and adds their own branding, subcommands, or alternate abstraction implementations. Used when the operator wants their own CLI name or extra org-specific commands. The supported wrapping surface is composition at the `pkg/cliapp` / `pkg/brokerhandlers` boundary plus constructor injection of concrete abstraction impls — **not** wrapper-side reimplementation of broker pipeline internals or cliapp runtime deps. Internal seams may reference `internal/` types and don't owe wrappers a stable surface.

The unwrapped path must stay polished; the wrapping seams must stay open at the composition boundary, but agents should not speculatively widen them. **Don't bake the name `postern` into anything a wrapper would need to override**, but also **don't make the unwrapped path feel unfinished**. Practical guidance:

- CLI binary name is a constructor parameter to `cliapp.New()`, **defaulting to `postern`**. Unwrapped use works without that param ever being touched.
- Subcommand handlers live in importable packages (`pkg/cliapp/`), not just `cmd/postern/main.go`. The unwrapped CLI binary in `cmd/postern/` uses these handlers itself.
- Broker HTTP handlers are exported types (`pkg/brokerhandlers/`), composable on a wrapper's own router. The unwrapped broker mounts them on its own default router.
- All abstraction implementations accept their concrete impl via constructor injection. **The default config wires the v1 concretes (generic OIDC IdP verifier, AWS KMS Signer, etc.)** so unwrapped use needs only environment-specific config (IdP issuer URL, KMS key ARN, etc.), not implementation choices.
- Branding (copyright, support URL, logo) flows through structured config with Postern-branded defaults.

Two questions to keep front-of-mind:

- "Could an operator run unwrapped Postern as their primary tool?" If no, you've over-abstracted. (This is the primary question.)
- "Could a downstream wrapper compose `cliapp.New()` + `brokerhandlers.New()` + their own subcommands / branding / abstraction-impl swaps without forking?" If no, the composition seam needs work. Note: this question is scoped to the cliapp/brokerhandlers composition boundary — wrapper reimplementation of broker pipeline internals or cliapp runtime deps is **not** something the framework owes its wrappers, and adding speculative export surface in pursuit of it is over-abstraction.

### One concrete impl per abstraction in v1

For each pluggable abstraction (IdP, Signer, Tunneling, Audit, Registry), v1 ships exactly one concrete implementation. **Don't add a second implementation speculatively.** Adding "for completeness" or "in case someone wants this" is the textbook anti-pattern that bakes the first concrete impl's assumptions into the interface. Real second implementations come when a real downstream user requests one.

### Privilege-split is load-bearing

The on-device split between `timefix-apply` (unprivileged verifier) and `timefix-set-clock` (`cap_sys_time+ep` setter) is a security architectural choice, not a stylistic one. Don't merge them, don't add features to the setter, don't expand the setter's input surface beyond a single integer timestamp. The setter is intentionally trivial because that's where the privileged code lives.

### Cryptographic shapes are pinned

`alg: EdDSA` and `typ: postern-timefix+jwt` are pinned in the on-device verifier — no fallback, no negotiation. If you're tempted to add algorithm flexibility ("maybe RSA later?"), don't — that's the door through which algorithm-confusion attacks walk. If a future need arises, that's a v2 explicit deprecation, not a v1 flexibility point.

### Access tokens, not ID tokens

The CLI sends the IdP-issued **access token** to the broker (`Authorization: Bearer`). The ID token is local-display-only — it tells the CLI who the engineer is for the "Logged in as ..." line and is never sent to the broker. **Never validate ID tokens at the broker** — they're meant for the client (CLI), not for resource servers, and accepting them as broker auth opens cross-app token misuse where a token issued for App A can be replayed against App B if both share a client_id. The broker validates `aud` and/or `scope` against its config to ensure the token was issued *for this broker*. The IdP doesn't enforce this — the broker does.

### Principal classification is token-claim-only

The broker classifies each caller into a **principal class** (e.g. `user` vs `machine`) to let authorization, certificate TTL, and audit treat automated callers (OAuth2 client-credentials / service accounts) differently from humans. Classification is inferred **purely from claims in the already-verified access token** — there is no broker-side identity database and no live IdP/Cognito lookup. Operators configure an ordered, first-match rule list under `idp.principal_classes` (predicates `claim_present` / `claim_absent` / `claim`+`equals` / `scope_contains`, plus a `default` class). An absent block classifies every caller as `user`, so existing deployments are unaffected. **Don't add an identity-DB lookup or a per-request IdP call to "improve" classification** — supporting both presence and absence predicates is what lets one generic OIDC verifier handle providers that emit a positive machine marker and providers (notably Cognito) that mark M2M tokens only by the *absence* of a user-only claim, without a provider-specific impl.

The class is **derived exactly once, in the verifier**, and stamped onto the verifier's caller-claims output as the single source of truth for the three consumers — per-class cert TTL, audit, and Policy context. **Don't re-derive the rule anywhere downstream** (the cert-TTL or audit path, or inside Cedar); re-encoding the predicate would let the TTL/audit/policy views of "who is calling" drift.

The class reaches the Policy layer as a **Cedar `context` attribute (`principal_class`), not a distinct principal entity type** — alongside `client_id` and the existing `source_ip`. This is deliberate: under token-based authorization (`IsAuthorizedWithToken`) the principal entity type is fixed by the AVP identity source, not chosen by the broker per request, and both identity-source flavors map the token to the same principal type. A context attribute is uniform across both flavors and needs no identity-source change. **Don't introduce a typed Cedar principal entity for the class.** Cert TTL follows the same propose-and-gate model as the tunnel pipeline: the broker clamps a caller-requested lifetime to the per-class ceiling and exposes the resolved value to Cedar as `context.requested_cert_ttl_minutes` (deny-only; Cedar never widens).

The `postern` CLI gains a **client-credentials grant** (`idp.grant: client_credentials`) for automated callers running the same binary. The client secret is read **only** from `<PREFIX>_IDP_CLIENT_SECRET` (e.g. `POSTERN_IDP_CLIENT_SECRET`), never the config file. This path is browserless and **bypasses the token store** — it re-mints on demand and persists nothing, so it does not touch the PKCE `RefreshToken`-required tokenstore invariant (that gate stays PKCE-only). **Don't route client-credentials tokens through the token store or add a refresh-token dependency to that path.**

### IdP impl is generic OIDC, not Cognito-specific

The v1 `IdP` abstraction's concrete impl is a generic OIDC verifier built on `github.com/coreos/go-oidc/v3` (single dep — handles discovery, JWKs, signature verification, claim parsing). **It works with any spec-compliant OIDC provider** (Cognito, Auth0, Okta, Keycloak, Azure AD, Google Workspace, internal OIDC). With RFC 8707 resource binding, Cognito access tokens carry a normal `aud` claim too — Cognito's only remaining v1 quirk is the `token_use` check (defends against ID-token misuse), handled inside the impl, not in the abstraction surface. **Don't add a Cognito-specific impl.** When operators bring different IdPs, the same impl handles them via different YAML config (audience and/or required_scope).

The token-verification library set is **not pluggable** — there's no value in operators swapping JWT-validation libraries. Authorization (the `Policy` interface) is what's pluggable; verification is just "use a standards-compliant OIDC lib correctly."

### Config is YAML + env

Both the CLI and the broker read config from a YAML file. The CLI uses a profile structure (top-level keys are profile names; `--profile` and `POSTERN_PROFILE` for selection, defaulting to `default`). The broker uses a single YAML document with sectioned subkeys (`idp:`, `signer:`, etc.). Per-field env-var overrides apply on top of the file in both cases. The CLI profile's `idp:` map carries an optional `grant` field (empty / `authorization_code` → browser PKCE; `client_credentials` → the browserless service-account path, with its secret sourced only from the `<PREFIX>_IDP_CLIENT_SECRET` env var). The broker's `idp:` section carries an optional `principal_classes` block (ordered first-match rules → class name; absent → all callers `user`), and `cert_ttl.by_class` sets per-class operator-cert ceilings (falling back to the operator default for unmapped classes).

Engineer onboarding is a YAML snippet the operator publishes (`broker`, plus a nested `idp:` map containing `issuer`, `client_id`, and one or both of `audience` and `scopes` depending on the IdP). **Upstream Postern binaries are usable as-is** — engineers download from Postern's GitHub releases, paste the snippet under their config file (`~/.postern/config.yaml` for the unwrapped `postern` binary; wrappers use `~/.<binary-name>/config.yaml`), run `postern login`. No build, no wrapper required. The wrapper repo path stays available for operators who want their own binary name, branding, or extra subcommands.

The CLI **never makes a pre-auth call to the broker**. Earlier designs included a `/v1/config` bootstrap endpoint to let the engineer's config hold only `broker = URL`; that was dropped because saving two lines of pasted YAML didn't justify the extra endpoint, cache logic, and trust-model concession. All IdP details live in the engineer's local config file.

**Don't add INI, TOML, or JSON config formats.** YAML is the format — single dep on `gopkg.in/yaml.v3`. The `Config` struct in `pkg/cliapp` and `pkg/brokerhandlers` is the source of truth — the YAML loader is one of several ways to populate it; wrappers that populate it directly (with literals or their own loader) just don't call the loader. Loader is exposed as a helper for wrappers that want Postern's fields readable from their own config file.

**Don't bake CLI config into the binary at build time** for the upstream `postern` binary. Build-time injection (ldflags, //go:embed) was considered and rejected: requiring operators to maintain their own builds was the source of friction the YAML config model removes. Wrappers that hardcode in their `main.go` are a separate path — that's the wrapper-repo route, not build-time injection of the upstream binary.

**Don't reintroduce a broker bootstrap endpoint.** A future temptation will be "let's just have the broker publish IdP details so engineers don't have to type them." Resist — it adds an unauthenticated endpoint, cache invalidation logic, and a second trust-model bootstrap step, all to save the engineer two lines of YAML they paste once. The broker is for SSH access only; everything pre-auth lives in the engineer's local config.

### Updates are decoupled from the broker

The `postern upgrade` subcommand fetches signed release artifacts from Postern's own GitHub releases (hardcoded URL), verifying via Sigstore — cosign-keyless signature on `checksums.txt` checked against the Postern repo's GitHub Actions OIDC identity, with Rekor inclusion proof. There is no Postern-held private signing key. Updates do not flow through the operator's broker. Wrappers can supply their own release URL and expected certificate-identity regex via constructor params, or omit the upgrade subcommand entirely. Don't reintroduce broker-served update verification — it conflates SSH access infrastructure with software distribution and forces every operator to run release signing they don't otherwise need.

### No DI framework

Dependencies for the broker (and CLI) are wired in `main.go` via plain Go constructor injection — a `Deps` struct passed to `New(deps)`. **Don't introduce `wire`, `fx`, `dig`, or any other DI framework.** The dep graph is small enough that hand-wiring is clearer, and a DI framework would hurt the wrapping story (wrappers would have to learn whichever framework we picked).

### One user-resolution chokepoint

`postern add-host`, `postern tunnel`, `postern ssh`, and `postern scp` all resolve the ssh user through the single `resolveUser` helper in `pkg/cliapp/sshuser.go`. Four-tier precedence (highest first): explicit `--user` flag → persistent `<device>` stanza's `User` directive (via `internal/sshconf.Writer.LookupUser`) → profile `default_ssh_user` (YAML or env) → built-in `DefaultSSHUser` ("engineer") fallback. The function returns `(string, explicit bool)` so ssh / scp can skip emitting `-l` / `-o User=` when only the implicit fallback applies — preserving any `Host *` wildcard `User` directive in the engineer's `~/.ssh/config`.

Two non-negotiables here. **`Profile.WithDefaults` must NOT inject `DefaultSSHUser`** when the YAML omits the field. The whole point of returning `explicit bool` is to distinguish "engineer set `default_ssh_user: engineer` deliberately" from "no one set anything and the framework filled in 'engineer'." Eagerly injecting collapses those cases and reintroduces the bug where vanilla `postern ssh <device>` emits a useless `-l engineer` that overrides wildcard directives. **And "engineer" is not a sentinel** — fleets really do use it as a username. The explicit bool, not a value-match check, gates emission; an engineer who chooses `engineer` via flag / stanza / profile config gets it honored. Don't add value-based skip rules.

`addhost` and `tunnel_open` discard the explicit bool — they always write a concrete User into the stanza they own. `ssh` and `scp` consume the bool. New consumers (e.g. a future `rsync` wrapper) should go through `resolveUser` the same way, not reimplement the chain locally.

### Default Policy is AVP

The v1 default `Policy` impl is **Amazon Verified Permissions** (Cedar-as-a-service), called via `IsAuthorizedWithToken`. Cedar policies live in an AVP policy store; broker config has one knob (`policy.avp_policy_store_id`). Policy changes don't require broker redeploy; CloudTrail logs every authorization decision. Consistent with the rest of the AWS-native v1 stack (KMS, IoT, CloudWatch, DynamoDB).

The starter Cedar policy under `examples/` is permissive (any authenticated engineer in an allowed group); operators tighten as their access model matures.

**Don't ship CEL, OPA, or cedar-go-local as additional v1 Policy concretes.** One concrete per abstraction. Wrappers needing those swap the whole `Policy` impl via constructor injection — that path stays open, but the upstream framework ships only AVP.

**Don't reintroduce a "permissive default that doesn't call AVP."** A future temptation will be "AVP is heavy/AWS-locked, let's ship a no-op default for evaluators." Resist — the entire policy-management story (externalized policy, audit, governance) collapses if the default is no-op. Operators evaluating without AWS run the broker locally and write a small Go `Policy` impl in their wrapper; that's the documented path for non-AWS evaluation.

### Cognito uses access-token claims, not broker auth in the IdP

For Cognito-using operators specifically: AVP can only see what's in the access token. Cognito access tokens include `cognito:groups` when the user belongs to Cognito groups, so the Cognito sample relies on that native claim for broker Policy.

Authorization still belongs in the broker Policy. Users outside Postern groups may receive Cognito tokens, but the broker must deny certificate issuance unless Policy authorizes the request. Do not add a required pre-authentication Lambda just to duplicate broker-side group checks; it complicates shared user pools and app-client scoping.

**Don't try to "fix" Cognito group visibility by using ID tokens at the broker, or by having the broker call /userinfo per request.** ID tokens at resource servers reopen cross-app misuse. Userinfo per request adds an IdP dependency on the cert-mint hot path. Broker Policy should consume access-token claims.

Other IdPs (Auth0, Okta, Keycloak, Azure AD) commonly carry group/role claims in access tokens too. Operators add IdP-side token customization only for claims their policy model needs and the IdP does not already emit.

### Postern is not in the IdP business

The core Terraform module at `terraform/postern-broker/` does not provision the IdP. Operators bring their own (Cognito, Okta, Auth0, Google Workspace, internal OIDC). A reference Cognito sample lives at `examples/terraform/cognito/` for operators who want to use Cognito, but it's a sample, not a framework component — don't move it into `terraform/` or treat it as load-bearing. Same principle as on-device packaging: framework owns the contract, operator owns the integration.

### Terraform only for IaC

`terraform/postern-broker/` is a Terraform module — the only IaC path the framework maintains. **No CDK variant in v1.** The design doc previously mentioned both; that's been narrowed. Community CDK contributions are welcome but not part of the framework's maintained surface. The module supports two AVP identity-source flavors (Cognito + generic OIDC) via the `avp_identity_source_type` variable; don't add a third without an actual user request.

## Doc style rules

- **Don't reference specific filenames or line numbers in the design doc.** Describe components, behaviors, and boundaries by name. The code can change locations; the design shouldn't depend on file paths.
- **Don't include rhetorical flourishes** ("a real ceiling, not a hopeful claim", "wins by elimination", etc.). State the rationale plainly. Explain choices, but trust the reader.
- **Mermaid diagrams are welcome** for sequence flows and architecture overviews.
- **Refer to the abstractions and their default impls by their interface names** (IdP, Signer, Tunneling, Audit, Registry), not the concrete impl's vendor name. The framework is designed to support other concretes later.

## Workflow rules

- The `DESIGN.md` is the authoritative source for the architecture. If code disagrees with the doc, decide which is right and update the loser. Don't let drift accumulate.
- **No copy-paste from internal/proprietary docs** into this repo. This is a public OSS project; everything here should be appropriate for public release.
- License is Apache 2.0. Don't introduce dependencies under incompatible licenses.
- **Always use `make check` to run tests**, not raw `go test ./...`. Every `cmd/timefix-apply/` test file is gated behind the `timefix_test_path` build tag (env-var CA-pubkey override seam excluded from production binaries; see `cmd/timefix-apply/capubpath_testbuild.go`). Raw `go test ./...` silently reports the package as `[no test files]`; `make check` runs the verifier suite under a second tagged pass. If you need a single-package test run, use `go test -tags timefix_test_path ./cmd/timefix-apply/...`.

## What the v1 implementation needs to ship

Per `DESIGN.md`. Status as of 2026-05-15 in parentheses; current punch list lives in `docs/team-handoff.md`.

- `cmd/broker/` — the long-running broker HTTP server, with the SSH endpoints (`/ssh/cert`, `/ssh/time-payload`, `/ssh/tunnel`) and the operational endpoint `/healthz`. Plus a `--print-config` flag mode for resolved-config debugging. (Done. `/ssh/tunnel` returns 501 only when the deployment has no `tunneling:` section configured — the architectural opt-in path; not a placeholder.)
- `cmd/broker-lambda/` — the API-Gateway-fronted Lambda entrypoint. Shares the handler stack and dep wiring with `cmd/broker`; consumed by the `terraform/postern-broker/` module. (Done.)
- `cmd/postern/` — the CLI with subcommands `login`, `mint`, `ssh`, `scp`, `add-host`, `remove-host`, `cache` (`ls`/`prune`), `tunnel`, `timefix`, `upgrade`, `logout`, `configure`, `version`. (All done except `upgrade`, which is a placeholder pending the signed-release subcommand.)
- `cmd/timefix-apply/` — the on-device verifier. (Done; closed in the timefix phase 2026-05-13.)
- `cmd/timefix-set-clock/` — the on-device setter. (Done; closed in the timefix phase 2026-05-13.)
- `internal/` — shared internals + the default impls of all abstractions. (Done: `atomicfile`, `audit`, `broker`, `brokerclient`, `brokerwire`, `certcache`, `idp`, `oauthlogin`, `policy`, `ratelimit`, `registry`, `signer`, `sshconf`, `tokenstore`, `version`.)
- `pkg/` — publicly importable handlers + CLI builder for downstream wrappers. (Done: `brokerhandlers`, `cliapp`.)
- IaC reference module at `terraform/postern-broker/`. (Done — KMS, DynamoDB, AVP with Cognito+OIDC identity-source variants and operator-customizable schema/policy set, CloudWatch, IAM, Lambda, API Gateway HTTP API, optional Route 53 + ACM custom domain, optional pre-built Lambda zip path, configurable HTTP-registry timeout. Tunneling backend IAM lands with the tunneling impl.)
- Example packaging artifacts in `examples/` (Yocto, Buildroot, etc. — references, not framework concerns). (`examples/terraform/cognito/` (Cognito IdP), `examples/terraform/deployment/` (module consumer), and `examples/on-device/sshd/` (partial sshd_config drop-in) shipped; principals-init script + other on-device packaging samples not yet authored.)
- Release pipeline: `.goreleaser.yaml` + GitHub Actions (`test.yml`, `release.yml`) + `release-please-config.json`. (Done — release-please opens a release PR on every `feat:`/`fix:` push to main; merging it tags `v*` and chains GoReleaser, which publishes a GitHub Release with cosign-keyless-signed checksums via Sigstore Fulcio. First tag `v0.1.0` was cut manually; subsequent versions are release-please-driven.)
- A pure-Go implementation of the AWS V3 secure-tunneling source proxy (for the AWS IoT Tunneling default impl). The protocol is documented at https://github.com/aws-samples/aws-iot-securetunneling-localproxy/blob/main/V3WebSocketProtocolGuide.md. A community Go reference implementation exists at https://github.com/mizosukedev/securetunnel for cross-checking. (Current phase; spec at `docs/phases/tunneling/spec.md`.)

## Things AI agents should NOT do

- Don't add features beyond what `DESIGN.md` describes. New design proposals belong in PRs against the design doc, not in code.
- Don't add organization-specific or vendor-specific code. This repo stays generic.
- Don't introduce a second implementation of any abstraction without an explicit user request and a real use case behind it.
- Don't break the wrapping contract at the composition boundary — `cliapp.New()` / `brokerhandlers.New()` constructor signatures, the abstraction interfaces (IdP, Signer, Tunneling, Audit, Registry, Policy, RateLimit) for constructor injection, the exported HTTP handlers, and the structured `Config` types are load-bearing. Internal seams (broker pipeline interfaces like `SSHCertIssuer`, cliapp runtime func-typed deps) are not part of the wrapping contract and may reference `internal/` types.
