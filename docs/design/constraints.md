# Constraints

Locked constraints and invariants. Rows are removed when they stop being true.

## Crypto & tokens

- The on-device time-payload verifier pins alg EdDSA and typ postern-timefix+jwt with no fallback or negotiation (algorithm-confusion defense).
- The JWS time-payload pipeline pins alg=EdDSA at both signing and verification.
- The KMS Signer pins Ed25519 at construction and per-sign call.
- The OIDC access-token verifier's alg allowlist excludes HS* and none.
- Any future algorithm change is a v2 explicit deprecation, never a v1 flexibility or negotiation point.
- The on-device verifier reads the JWS under a size cap and verifies the signature before inspecting any claim, with the typ check applied post-parse.
- The token-verification library set is not pluggable; only Policy (authorization) is.
- The source (tunnel) access token is never logged.
- PKCE is applied to both the authorize URL and the token exchange.

## Broker auth (aud / scope / ID tokens)

- The CLI sends the IdP access token (never the ID token) to the broker as Bearer; the ID token is local-display-only.
- The broker never validates ID tokens (SkipClientIDCheck is intentional); accepting an ID token as broker auth is forbidden (cross-app misuse).
- The broker re-verifies every token itself regardless of any edge authorizer.
- The broker validates aud and/or scope: with one of idp.audience/idp.required_scope configured that one is required; with both, either match suffices (OR); a token with neither proof is rejected.
- The aud/scope check is fail-closed — an unset field is never a proof (matched := field != "" && match); neither field configured rejects all tokens.
- Scope matching is exact-element only (no substring); audience matching is exact array-membership.
- There is no audience_scope_match / match-mode knob, and AND-both semantics are not restored (strict-AND is the case OR exists to serve).
- Both-empty aud+scope config is rejected at verifier construction.
- The verifier enforces token_use == "access" when present (ID-token-misuse defense), handled inside the OIDC impl, not the abstraction surface.
- The verifier requires a non-empty sub; all orthogonal checks (signature, iss, exp, iat skew/max-age) independently reject and the aud-OR-scope path short-circuits none of them.
- Rate-limiting runs before all external calls except the IdP token verification (caller identity is the partition key).

## APIGW edge authorizer

- The APIGW JWT authorizer, when enabled, is a defense-in-depth pre-filter only (signature + issuer + exp + audience), not the authority.
- The edge authorizer pins an audience list (idp_audience + apigw_jwt_additional_audiences) and cannot express aud-OR-scope (it can only AND).
- Machine (client-credentials) tokens carry no aud and are admitted at the edge only by listing their client IDs in apigw_jwt_additional_audiences (APIGW matches aud, or client_id when aud is absent).
- The edge audience pin is not dropped and scope is not pinned at the edge.

## Principal classes

- The broker classifies each caller into a principal class inferred purely from verified access-token claims — no identity DB, no live IdP/Cognito lookup.
- Classification is an operator-configured ordered first-match rule list (idp.principal_classes) with predicates claim_present / claim_absent / claim+equals / scope_contains plus a default class.
- An absent principal_classes block classifies every caller as user (backward compatible).
- The class is derived exactly once, in the verifier, stamped on CallerClaims as the single source of truth; it is never re-derived in the TTL, audit, or Cedar path.
- The rule mechanism supports both presence and absence predicates (one generic OIDC verifier covers positive-marker and absence-marker providers without a provider-specific impl).
- The class reaches Policy as a Cedar context attribute (principal_class), never a typed principal entity, alongside client_id and source_ip.
- principal_class is emitted unconditionally and declared required:true in the Cedar schema; client_id is optional and policies must guard it with `context has client_id`.
- The verifier reads the client_id claim into CallerClaims.ClientID (empty when absent) as the M2M caller identifier.
- principal_classes is configurable via POSTERN_IDP_PRINCIPAL_CLASSES env (whole block as JSON/YAML, strict-decoded, replacing any file block — no per-rule merge); POSTERN_IDP_PRINCIPAL_CLASS_DEFAULT overrides only the default class additively.
- Class names are operator-defined opaque strings (user/machine conventional, not reserved); the verifier caps class length and rejects empty class names at load.

## Cert TTL

- The operator-cert validity window is min(CLI-requested lifetime, per-class broker ceiling); Cedar can only deny/tighten it, never widen.
- Per-class cert ceilings come from cert_ttl.by_class, falling back to the operator default for unmapped classes.
- The broker exposes the resolved cert TTL to Cedar as context.requested_cert_ttl_minutes (deny-only propose-and-gate, mirroring the tunnel lifetime gate).
- A cert-lifetime request above the ceiling is clamped down (not denied); a negative request is rejected 400.
- OperatorClockSkewPadding still applies to ValidAfter and the window never exceeds the per-class ceiling.
- The timefix cert window is fixed and class-independent.
- The authorization service returns only Allow/Deny and can never emit a TTL value the broker reads back.

## CLI client-credentials grant

- The CLI supports a client_credentials grant (idp.grant) that is browserless, bypasses the token store, re-mints on demand, and persists nothing.
- The client-credentials secret is read only from <PREFIX>_IDP_CLIENT_SECRET env, never the config file.
- The client-credentials path carries no refresh-token dependency; the RefreshToken-required tokenstore gate stays PKCE-only.

## CLI cert-lifetime flag

- The CLI cert-lifetime request flag is --cert-max-lifetime, distinct from --max-lifetime (the tunnel TTL on ssh/scp); on one invocation they map to separate request fields and never cross.
- --cert-max-lifetime omits the field when zero/absent, rejects negatives client-side, and applies no client-side ceiling (the broker clamps).

## CLI & config

- Config is YAML + env only; no INI, TOML, or JSON config formats.
- The Config structs in pkg/cliapp and pkg/brokerhandlers are the source of truth; the YAML loader is one populator among several and is exposed as a helper.
- The CLI uses a profile structure (top-level keys are profile names; --profile / POSTERN_PROFILE, default "default"); the broker uses a single sectioned YAML document; per-field env overrides apply on top in both.
- The CLI never makes a pre-auth call to the broker; all IdP details live in the engineer's local config.
- No broker bootstrap / config-publishing endpoint is reintroduced.
- The upstream postern binary never has CLI config baked in at build time (no ldflags, no go:embed injection).

## User resolution

- add-host, tunnel, ssh, and scp resolve the ssh user only through the single resolveUser helper (precedence: --user flag → device-stanza User → profile default_ssh_user → built-in DefaultSSHUser "engineer").
- resolveUser returns (string, explicit bool) so ssh/scp skip emitting -l / -o User= when only the implicit fallback applies (preserving a Host * wildcard User directive).
- Profile.WithDefaults does not inject DefaultSSHUser when the YAML omits the field (the explicit bool must distinguish a deliberate value from a framework-filled one).
- "engineer" is not a sentinel; the explicit bool, not a value-match, gates -l/-o emission — no value-based skip rules.
- New user-consuming subcommands go through resolveUser rather than reimplementing the precedence chain.

## setup-ssh

- Only postern setup-ssh writes ~/.ssh/config; add-host, mint, and tunnel stay read-only on it and only point the engineer at setup-ssh.

## On-device

- The on-device split between timefix-apply (unprivileged verifier) and timefix-set-clock (cap_sys_time+ep setter) is load-bearing; the two are never merged.
- The timefix-set-clock setter's input surface stays a single integer timestamp, range-checked independently of the verifier; no features are added to it.

## Tunneling

- /ssh/tunnel returns 501 only when the deployment has no tunneling: section configured (architectural opt-in), not as a placeholder.
- The tunnel lifetime follows the same propose-and-gate model via context.requested_max_lifetime_minutes (deny-only).

## Updates & release

- Releases are signed via Sigstore cosign-keyless on checksums.txt (GitHub Actions OIDC identity, Rekor inclusion proof); there is no Postern-held private signing key.
- The self-update path targets Postern's own GitHub releases and verifies those signatures; its release URL and expected cert-identity regex are wrapper-overridable constructor params, and wrappers may omit the upgrade subcommand entirely.
- Updates never flow through the broker; broker-served update verification is not reintroduced.

## Architecture & abstractions

- Each pluggable abstraction (IdP, Signer, Tunneling, Audit, Policy, RateLimit) ships exactly one concrete impl (Registry excepted: DynamoDB and HTTP both ship); second impls are added on real downstream demand, never speculatively.
- The default Policy impl is AVP (Cedar-as-a-service) via IsAuthorizedWithToken, configured by the single knob policy.avp_policy_store_id.
- No CEL, OPA, or cedar-go-local Policy concrete ships upstream; wrappers swap the whole Policy impl via constructor injection.
- No permissive / no-op default Policy that bypasses AVP is reintroduced.
- The IdP concrete impl is a generic OIDC verifier (go-oidc/v3) working with any spec-compliant provider; no Cognito-specific impl.
- Authorization lives in the broker Policy; the broker denies cert issuance unless Policy authorizes, and no pre-auth Lambda duplicates broker group checks.
- Broker Policy consumes access-token claims only — not ID tokens and not a per-request /userinfo call.
- No DI framework (wire/fx/dig); dependencies are hand-wired via a Deps struct passed to New().
- Terraform is the only maintained IaC path; there is no CDK variant in v1.
- The Terraform module supports exactly two AVP identity-source flavors (Cognito + generic OIDC) via avp_identity_source_type; no third without a real user request.
- The core Terraform module does not provision the IdP; operators bring their own and the Cognito sample stays under examples/, not moved into terraform/.
- The wrapping surface is composition at the pkg/cliapp / pkg/brokerhandlers boundary plus constructor injection of concrete impls — not wrapper reimplementation of broker pipeline internals or cliapp runtime deps.
- The load-bearing wrapping contract is cliapp.New()/brokerhandlers.New() signatures, the abstraction interfaces, the exported HTTP handlers, and the structured Config types; internal seams (e.g. SSHCertIssuer, cliapp func-typed deps) are not part of it.
- The CLI binary name is a cliapp.New() constructor param defaulting to postern; the name postern is not baked into anything a wrapper must override.
- No organization-specific or vendor-specific code enters the repo; it stays generic.

## Audit & pipeline invariants

- Every request produces exactly one outcome audit row (*_issued or *_denied); an authorized request emits its *_authorized row first, across all three pipelines.
- recordAuthorized is fail-closed and runs before any Sign / AWS call.
- Audit JSON field names (engineer_sub / engineer_email / engineer_groups) are the frozen CloudWatch-Insights query surface — new fields are added, never renamed.
- Every POST endpoint caps the body with MaxBytesReader and decodes JSON with DisallowUnknownFields.
- The device serial is regex-validated from the Registry response and fail-closed on empty.

## Wire compatibility

- The on-the-wire request/response JSON field names on /ssh/cert, /ssh/tunnel, /ssh/time-payload are frozen (old-CLI/new-broker compat); Go-internal identifiers and Cedar schema/policy are free to change.

## Docs & workflow

- DESIGN.md is authoritative; code that disagrees is reconciled against it — drift is not allowed to accumulate.
- New design proposals go into PRs against DESIGN.md, not into code ahead of the doc.
- License is Apache 2.0; no dependency under an incompatible license is introduced.
- No content is copy-pasted from internal/proprietary docs (public OSS project).
