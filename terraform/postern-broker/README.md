# Postern broker — Terraform module

A reusable Terraform module that provisions the AWS infrastructure the unwrapped Postern broker needs to run. Consumable as a module from your own infrastructure repo via a git source, or directly via the in-repo example at `examples/terraform/deployment/`.

The v1 broker depends on AWS abstractions for KMS (signing), DynamoDB (registry + rate-limit), AWS Verified Permissions (policy), and CloudWatch Logs (audit). Compute is included: the broker runs on AWS Lambda behind an API Gateway HTTP API. No VPC required.

The IdP is **not** provisioned by this module. Postern is not in the IdP business (`DESIGN.md`); operators bring their own (Cognito, Auth0, Okta, Keycloak, Azure AD, Google Workspace, internal OIDC). For a quickstart Cognito IdP, see `examples/terraform/cognito/`.

## Usage

### As a Terraform module in your own repo

```hcl
module "postern_broker" {
  source = "github.com/atomicgravity/postern//terraform/postern-broker?ref=v1.0.0"

  name_prefix = "postern"
  tags        = { Project = "postern", Env = "prod" }

  idp_issuer   = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_XXX"
  idp_audience = "https://postern-broker.example.com"

  avp_identity_source_type  = "cognito"
  avp_cognito_user_pool_arn = "arn:aws:cognito-idp:us-west-2:123:userpool/us-west-2_XXX"
  avp_cognito_client_ids    = ["abc123"]

  # Optional custom domain
  route53_zone_name  = "example.com"
  broker_domain_name = "postern-broker.example.com"
}

output "broker_url" {
  value = module.postern_broker.broker_url
}
```

Pin `?ref=v<tag>` to a Postern release tag (or a commit SHA) so module upgrades are explicit.

### Direct apply from the Postern repo

See [`examples/terraform/deployment/`](../../examples/terraform/deployment/) for a directly-deployable example that consumes this module by relative path. Copy that directory to your own repo, switch the `source` line to the git form above, and pin to a tag.

## What this creates

- A KMS asymmetric Ed25519 signing key (the SSH CA), with an alias.
- Two DynamoDB tables: device registry and per-engineer rate-limit, both PAY_PER_REQUEST.
- An AVP policy store with the broker's Cedar schema, a permissive starter policy, and an identity source — **either Cognito or generic OIDC**, controlled by `avp_identity_source_type`.
- A CloudWatch log group for broker audit events plus the fixed `ssh-cert-issued` log stream.
- A Lambda function packaged from `cmd/broker-lambda` (provided.al2023, arm64) with broker config injected via `POSTERN_*` environment variables.
- An API Gateway HTTP API with a `$default` route forwarding all paths and methods to the Lambda.
- (Optional) An ACM certificate, an API Gateway custom domain, and Route 53 records (DNS validation + alias A) when `route53_zone_name` and `broker_domain_name` are set.
- An IAM role for the Lambda scoped to exactly the resources above.

## Prereqs

- Terraform `>= 1.9.0` (cross-variable validation + `terraform_data` are used).
- AWS provider `>= 5.70.0` (configured at the caller; the module declares `required_providers` but no `provider` block).
- An existing IdP (the module wires the broker to it, but does not provision it).
- For the in-tree Lambda build: `make`, `go`, and `zip` on the apply machine. For pre-built artifacts, set `broker_lambda_zip_path` and skip the toolchain requirement.

## Inputs

See `variables.tf` for the full list with descriptions. Highlights:

| Variable | Purpose |
|---|---|
| `name_prefix` | Prefix for all created resources (default `"postern"`); multiple deployments coexist by varying this. |
| `tags` | Map applied to every taggable resource. |
| `idp_issuer` | OIDC issuer URL for broker token validation. |
| `idp_audience` / `idp_required_scope` | At least one is required; how the broker scopes accepted tokens. |
| `idp_principal_classes_json` | JSON (or YAML) document of principal-classification rules, set on the broker via `POSTERN_IDP_PRINCIPAL_CLASSES`. Empty (default) classifies every caller as `user`. See "Principal classes" below. |
| `avp_identity_source_type` | `"cognito"` or `"oidc"`. |
| `avp_cognito_user_pool_arn`, `avp_cognito_client_ids` | Required when type is `"cognito"`. |
| `avp_oidc_issuer`, `avp_oidc_audiences`, `avp_oidc_principal_id_claim`, `avp_oidc_entity_id_prefix` | Required when type is `"oidc"`. |
| `avp_cognito_group_entity_type` | When set (e.g. `"Postern::Group"`), AVP maps `cognito:groups` token claims to Cedar entities of this type — policies can use `principal in Postern::Group::"engineers"`. Requires `avp_schema_json` to declare the entity. Only meaningful when `avp_identity_source_type = "cognito"`. |
| `avp_install_starter_policy` | `true` (default) creates the bundled permissive starter policy. Set to `false` to manage the full policy set yourself via `aws_verifiedpermissions_policy` resources in the caller. |
| `avp_schema_json` | Cedar schema JSON to install on the policy store. Empty (default) uses the bundled schema. Override when policies need additional `Device` attributes (bool, Long, or extra String) — Cedar STRICT validation rejects policies referencing undeclared attributes. |
| `registry_backend` | `"dynamodb"` (default) provisions the device-registry table; `"http"` wires the broker to an external HTTP registry service via `registry_http_*` vars and skips the table. |
| `registry_http_url` | URL of the operator's HTTP registry service. Required when `registry_backend = "http"`. See `docs/registry-http-api.md` for the endpoint contract. |
| `registry_http_auth_mode` | `"none"` (default), `"bearer"`, or `"aws_sigv4"`. Bearer sends `Authorization: Bearer <token>`. SigV4 signs each request with the broker's Lambda IAM role for an API-Gateway-fronted registry — the Lambda role needs `execute-api:Invoke` attached separately via `broker_lambda_role_name`. |
| `registry_http_bearer_token` | Bearer token (sensitive). Required when `registry_http_auth_mode = "bearer"`. Pass via env (`TF_VAR_registry_http_bearer_token`). |
| `registry_http_aws_region` | SigV4 region. Empty defers to the broker's AWS SDK default-region chain. |
| `registry_http_timeout` | Per-request HTTP timeout for registry calls (Go duration string, e.g. `"15s"`, `"30s"`). Empty (default) uses the broker's built-in ≈15s default, sized for Lambda cold-start budgets. Loosen up to `lambda_timeout_seconds` for slower registries; tighten when on-network with sub-second p99. |
| `route53_zone_name` + `broker_domain_name` | Optional custom-domain wiring; empty disables. |
| `broker_lambda_zip_path` | Absolute path to a pre-built `broker-lambda.zip`. Empty → in-tree build via `make broker-lambda.zip` (requires make / go / zip on the apply machine). Released artifacts live at `https://github.com/atomicgravity/postern/releases/download/v<version>/broker-lambda_<version>_linux_arm64.zip` — operators applying from CI typically fetch this in a prior step and pass the local path here. |
| `cert_ttl_operator`, `ratelimit_limit`, `ratelimit_window`, `trusted_proxies`, `log_level` | Broker tunables passed as env vars. |
| `lambda_memory_mb`, `lambda_timeout_seconds`, `lambda_log_retention_days`, `audit_log_retention_days` | AWS-side tunables. |
| `apigw_access_logs_enabled` | `true` by default. APIGW writes a JSON access log line per request to a separate CloudWatch log group. Independent of the JWT authorizer. |
| `apigw_access_log_retention_days` | `30`. Retention for the APIGW access log group. |
| `apigw_jwt_authorizer_enabled` | `false` by default. When `true`, API Gateway validates the bearer JWT (signature, issuer, expiration) before invoking Lambda; bad tokens get a 401 from APIGW without consuming a Lambda invocation. Audience is not pinned at the edge — the broker enforces aud-OR-scope. Layered defense — the broker still does its full check (audience, scope, token_use, etc.). See "Layered JWT defense at API Gateway" below. |
| `tunneling_enabled` | `false` by default. When `true`, the module grants the broker Lambda `iot:OpenTunnel` and passes `POSTERN_TUNNELING_IOT_REGION` + `POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES` env vars so `/ssh/tunnel` mints AWS IoT Secure Tunnels for the firewalled-device path. When `false`, the broker returns 501 on `/ssh/tunnel` and carries no `iot:` permission. See "Tunneling (firewalled-device recovery)" below. |
| `tunneling_iot_region` | Empty by default. AWS region for the broker's IoT secure-tunneling client; empty resolves to the deployment region. Cross-region operators set this explicitly. Only consulted when `tunneling_enabled = true`. |
| `tunneling_default_max_lifetime_minutes` | `480` (8 hours) by default. Broker fallback TTL when the engineer omits `--max-lifetime`. AWS caps individual tunnels at 720 (12 hours); the module validation enforces the (0, 720] range. Only consulted when `tunneling_enabled = true`. |
| `tunneling_thing_name_format` | `"device-{serial}"` by default. Format the broker substitutes the resolved device serial into when calling AWS IoT `OpenTunnel`; `{serial}` is replaced with the registry-resolved hardware serial, other characters pass through verbatim. The placeholder must appear exactly once. Only consulted when `tunneling_enabled = true`. |

## Outputs

| Output | Purpose |
|---|---|
| `broker_url` | URL engineers paste into `~/.postern/config.yaml` under `broker:`. Resolves to `https://<broker_domain_name>` when the custom-domain path is enabled, otherwise the API Gateway invoke URL. |
| `broker_apigw_invoke_url` | Raw API Gateway invoke URL (diagnostics). |
| `ssh_ca_kms_key_arn` / `ssh_ca_kms_key_id` | KMS key identifying the SSH CA. |
| `ratelimit_table_name` | DynamoDB rate-limit table. |
| `audit_log_group_name` | Audit log group. |
| `apigw_access_log_group_name` | APIGW access log group (or `null` when the JWT authorizer is disabled). |
| `avp_policy_store_id` | AVP policy store id. |
| `broker_lambda_function_name` | Lambda function name (for log streaming, manual invocation, etc.). |
| `broker_lambda_role_name` / `broker_lambda_role_arn` | IAM role of the broker Lambda. Attach additional policies (e.g. `execute-api:Invoke` for a SigV4 HTTP registry) via `aws_iam_role_policy_attachment` in the caller. |
| `registry_table_name` | DynamoDB registry table name. **Null** when `registry_backend = "http"`. |

## Composing with examples/terraform/cognito

The cognito sample is standalone — this module does not import it. With the custom domain set everything is single-pass:

1. **Apply this module** with `idp_issuer` left as a placeholder. Capture `broker_url`.
2. **Apply `examples/terraform/cognito/`** with `broker_url` and `broker_resource` both set to the captured value (audience = broker URL).
3. **Re-apply this module** with:
   - `idp_issuer`                ← cognito output `issuer`
   - `avp_cognito_user_pool_arn` ← derived from cognito output `user_pool_id` (`arn:aws:cognito-idp:<region>:<account>:userpool/<id>`)
   - `avp_cognito_client_ids`    ← `[cognito user_pool_client_id]`
   - `idp_audience`              ← cognito output `resource` (which defaults to `broker_url`, so step-1's captured value is the right input in the default case; operators who set `broker_resource` to a custom URI follow the cognito `resource` output).
4. **Engineer config.** `broker:` from this module's `broker_url`; the nested `idp:` map from cognito's `engineer_config_yaml` output.

## Authorization (Cedar)

The starter Cedar policy at `cedar/starter.cedar` permits any authenticated principal to mint an operator certificate for any device. Tighten as your access model matures — by group, by device tag, by source IP, by time of day. The schema at `cedar/schema.json` declares the entities and context attributes the broker passes to AVP; extend it as your policies need to reference more attributes. The broker's hot-path call is `IsAuthorizedWithToken` — no policy redeploy beyond `terraform apply` after editing the Cedar files.

### Principal classes

To distinguish automated callers (OAuth2 client-credentials / service accounts) from humans, the broker classifies each caller from its token claims and emits `context.principal_class` (e.g. `user` / `machine`) and `context.client_id` (the issuing client, when present), alongside the existing `context.source_ip`. Policies branch on them — the starter policy demonstrates permitting one specific `machine` `client_id` only from a pinned `source_ip`. The broker also passes `context.requested_cert_ttl_minutes` (the per-class-clamped certificate lifetime) for `when { context.requested_cert_ttl_minutes <= N }` gating, mirroring the tunnel's `requested_max_lifetime_minutes`.

Configure the rules with `idp_principal_classes_json` — an ordered first-match list, set on the Lambda as `POSTERN_IDP_PRINCIPAL_CLASSES`:

```hcl
idp_principal_classes_json = jsonencode({
  default = "user"
  rules   = [{ class = "machine", claim_absent = "username" }]
})
```

Each rule sets exactly one predicate: `claim_present`, `claim_absent`, `claim` + `equals`, or `scope_contains`. The `claim_absent = "username"` rule above is the Cognito M2M signal (client-credentials tokens carry no `username`). With no rules configured, every caller is the default class.

Two ways to manage your own policies alongside (or instead of) the starter:

- **Add policies in the caller.** Leave `avp_install_starter_policy = true` and define your own policies as `aws_verifiedpermissions_policy` resources in the caller, pointing them at `module.<name>.avp_policy_store_id`. Both your policies and the starter evaluate together (AVP grants when any policy permits and none forbids).
- **Replace the starter entirely.** Set `avp_install_starter_policy = false` to skip the bundled starter, then manage the full policy set in the caller. Useful when "any authenticated user can mint" is wider than your access model permits from day one.

**Cognito-entity namespacing gotcha.** When `avp_cognito_group_entity_type` is set, AVP namespaces both the User principal and the Group parents with the user-pool ID. Entity IDs are of the form `<pool_id>|<value>` (e.g. `Postern::Group::"us-west-2_ABC123|engineers"`, `Postern::User::"us-west-2_ABC123|<sub>"`). Policies using the bare group name produce silent DENY with no error — AVP simply doesn't find a matching permit. Build policies with the pool ID interpolated:

```hcl
locals {
  cognito_pool_id = element(split("/", var.user_pool_arn), length(split("/", var.user_pool_arn)) - 1)
}

resource "aws_verifiedpermissions_policy" "engineers_can_mint" {
  policy_store_id = module.broker.avp_policy_store_id
  definition {
    static {
      description = "Engineers group can mint operator certs"
      statement = <<-EOT
        permit (
          principal in Postern::Group::"${local.cognito_pool_id}|engineers",
          action == Postern::Action::"MintOperatorCert",
          resource
        );
      EOT
    }
  }
}
```

Device attributes from the Registry (DynamoDB or HTTP) flow into Cedar policy evaluation as native Cedar types: strings → `String`, booleans → `Boolean`, integers → `Long`. The bundled schema only declares `serial` + `friendly_id`. When your Registry emits additional attributes (e.g. `in_production`, `firmware_revision`, `fleet`) **and** your policies reference them, extend the schema's `Device` shape and pass the JSON via the `avp_schema_json` variable — AVP runs in STRICT validation mode, so undeclared attributes cause policies that reference them to fail to compile.

## Layered JWT defense at API Gateway

The unwrapped broker validates every access token in the broker pipeline (signature, issuer, audience, scope, `token_use`, plus the full Cedar authorization decision). With `apigw_jwt_authorizer_enabled = true`, API Gateway HTTP API additionally validates the JWT's signature, issuer, and expiration **before** invoking the broker Lambda — bad tokens get a 401 from APIGW and never burn a Lambda invocation.

The trust model is deliberately one-way: the broker does not trust APIGW's parsed claims and re-verifies the token in its own pipeline. APIGW is a pre-filter, not the authority. The broker's behavior is identical whether the authorizer is on or off.

What this protects against:
- **Pre-Lambda DoS.** Crafted JWTs that trigger CVEs in the JWS parsing library (e.g. CVE-2025-27144 in go-jose) never reach the broker's parser. The attack surface against parser bugs shrinks to APIGW's verifier, which is a separately maintained codebase.
- **Cold-start amplification.** No-token / wrong-issuer / expired probes bounce at APIGW, saving Lambda concurrency and cold-start time.
- **Lambda billing.** Bad-token probes don't generate Lambda invocations to pay for.

What this does NOT do:
- **Replace the broker's checks.** Audience, scope, `token_use`, the cert-mint pipeline gates, and AVP authorization all stay broker-side. APIGW does not understand them.
- **Check audience or scope.** APIGW validates signature, issuer, and expiration only. Audience and scope are enforced broker-side as an aud-OR-scope decision; the edge authorizer ANDs its constraints and can't express that, so pinning `aud` there would reject scope-only tokens (client-credentials carry no `aud`).

Routing:
- Every route — including `/healthz` — is gated by the authorizer when it's on. The Lambda+APIGW deployment doesn't need an unauthenticated `/healthz`: APIGW is HA AWS-managed (no operator probing required) and Lambda's own lifecycle handles function health. The `/healthz` endpoint stays in the broker handler for the long-running `cmd/broker` deployment behind an ALB, where the operator's load-balancer health check configures auth-bypass on its side. Leaving `/healthz` under JWT auth at APIGW shrinks the unauthenticated attack surface here to zero without giving up any operational capability we actually use.

Observability:
- APIGW access logs land in a separate CloudWatch log group (`/<name_prefix>/apigw-access`), with shorter default retention than the audit log group. Operators query both for incident response: the audit group captures every request the broker saw (including `ssh_cert_denied` for everything that reached the pipeline); the access group captures every request APIGW rejected before the broker saw it (no JWT, expired JWT, wrong issuer). Together they cover every probe of `/ssh/cert`.
- Log format is JSON, with: `requestId`, `requestTime`, `httpMethod`, `routeKey`, `status`, `protocol`, `responseLength`, `sourceIp`, `userAgent`, `authorizerError`, `authorizerLatency`.

## Tunneling (firewalled-device recovery)

When `tunneling_enabled = true`, the module wires the broker for the firewalled-device path: engineers reach devices that aren't on the engineer's LAN by minting an AWS IoT Secure Tunnel. The broker calls `iot:OpenTunnel`; the CLI runs a pure-Go V3 WebSocket source proxy that bridges a localhost TCP listener to the AWS-managed tunneling data plane; the device's destination-side component (operator concern) consumes the tunnel via MQTT. See the top-level `README.md` "Tunneling" section for the engineer-facing entry points (`postern ssh --tunnel`, `postern scp --tunnel`, `postern tunnel`).

What this module provisions for the path:

- An IAM statement on the broker Lambda role granting `iot:OpenTunnel`.
- `POSTERN_TUNNELING_IOT_REGION` on the broker Lambda's environment. Empty `tunneling_iot_region` resolves to the deployment region (`data.aws_region.current.region`) so single-region operators don't need to set it.
- `POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES` on the broker Lambda's environment. Default `480` (8 hours); validation pins the range to (0, 720] minutes (AWS caps individual tunnels at 12 hours).
- `POSTERN_TUNNELING_THING_NAME_FORMAT` on the broker Lambda's environment. Carries the `tunneling_thing_name_format` value through to the broker.

What this module does **not** provision:

- **The destination-side component.** Operators install the AWS IoT Greengrass `aws.greengrass.SecureTunneling` component (or equivalent) on the device. See `examples/on-device/secure-tunnel/README.md` for the device-side reference.
- **The AVP Cedar policy for `OpenTunnel`.** The bundled starter Cedar policy permits any authenticated principal to mint operator certs, time payloads, and open tunnels. Operators tightening for production write a Cedar `permit (principal, action == Action::"OpenTunnel", ...)` policy with the desired group / fleet / source-IP constraints (the AVP `Postern::Action::"OpenTunnel"` action is already declared in the bundled schema).
- **MQTT topic management.** AWS IoT publishes the destination access token to `$aws/things/device-<serial>/tunnels/notify` on `OpenTunnel`; the device's secure-tunneling component subscribes to it directly. The broker has no MQTT involvement.

Operators that don't need the firewalled-device path leave `tunneling_enabled = false` (the default). The /ssh/tunnel handler returns 501; the broker carries no `iot:` IAM permission; there is no AWS-side cost.

## Extracting the SSH CA public key for devices

The broker's KMS-backed CA needs its public key on each device's `TrustedUserCAKeys`. Extract it with:

```sh
KEY_ID=$(terraform output -raw ssh_ca_kms_key_id)

{
  printf '\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
  aws kms get-public-key --key-id "$KEY_ID" --query PublicKey --output text \
    | base64 -d \
    | tail -c 32
} | base64 | tr -d '\n' | awk '{print "ssh-ed25519 " $0}'
```

The pipeline prints `ssh-ed25519 AAAA...` ready for `/etc/ssh/trusted_user_ca_keys` on every device. Sanity-check the result with `echo "ssh-ed25519 AAAA..." | ssh-keygen -l -f -` — it should report a 256-bit ED25519 fingerprint.

The manual byte-assembly is necessary because `aws kms get-public-key` returns DER-encoded SPKI but `ssh-keygen -i -m PKCS8` doesn't accept Ed25519 SPKI on macOS (the rest of the keytypes work; Ed25519's PKCS8 import path is missing). Ed25519's SPKI is a fixed 44-byte structure whose last 32 bytes are the raw public key, so the OpenSSH wire format is easy to assemble directly.

## What this does not do

- **No IdP provisioning.** Bring your own. `examples/terraform/cognito/` is one option.
- **No device population.** Operators write devices into the registry table out of band — the broker only reads.
- **No multi-region or DR.** Single-region deployment; the asymmetric KMS key is regional and not multi-region by default.

## Tearing down

```sh
terraform destroy
```

KMS keys enter a 30-day deletion window before final removal. The audit log group is removed with the rest of the stack — back up audit history elsewhere if you need it past `destroy`.
