variable "name_prefix" {
  description = "Prefix applied to every named AWS resource so multiple Postern deployments can coexist in one account."
  type        = string
  default     = "postern"
}

variable "tags" {
  description = "Tags applied to every taggable resource the module creates. Operators typically pass cost-allocation / ownership / environment tags here."
  type        = map(string)
  default     = {}
}

# IdP wiring -------------------------------------------------------------------
#
# The module provisions the broker; the IdP is the operator's choice (DESIGN.md).
# These variables tell the broker how to validate access tokens. For the
# examples/terraform/cognito reference, copy:
#   idp_issuer   ← cognito output `issuer`
#   idp_audience ← cognito output `resource` (which defaults to `broker_url`)
# The module's audience and the IdP's issued audience must agree.

variable "idp_issuer" {
  description = "OIDC issuer URL the broker uses to discover JWKs and validate access tokens."
  type        = string
}

variable "idp_audience" {
  description = "Access-token audience the broker requires. Set to the resource identifier the IdP issues against. Either this or idp_required_scope must be set."
  type        = string
  default     = ""
}

variable "idp_required_scope" {
  description = "Access-token scope the broker requires. Either this or idp_audience must be set."
  type        = string
  default     = ""
}

variable "idp_principal_classes_json" {
  description = "Principal-classification rules as a JSON (or YAML) document, set on the broker via POSTERN_IDP_PRINCIPAL_CLASSES. The Lambda has no config file, so this env var is how the structured rule list is configured. Shape: {\"default\":\"user\",\"rules\":[{\"class\":\"machine\",\"claim_absent\":\"username\"}]}. Empty (default) classifies every caller as \"user\". Predicates per rule (exactly one): claim_present, claim_absent, claim+equals, scope_contains."
  type        = string
  default     = ""
}

# AVP identity source ----------------------------------------------------------
#
# AVP needs an identity source so IsAuthorizedWithToken can map the engineer's
# access token to a Cedar principal entity. Two flavors are supported:
#
#  - "cognito" — set avp_cognito_user_pool_arn + avp_cognito_client_ids.
#  - "oidc"    — set avp_oidc_issuer + avp_oidc_audiences (and optionally
#                avp_oidc_principal_id_claim, avp_oidc_entity_id_prefix).
#
# Token cryptographic verification happens inside the broker; AVP only uses
# the identity source to populate the Cedar evaluation context.

variable "avp_identity_source_type" {
  description = "Which AVP identity source flavor to provision. One of: \"cognito\" or \"oidc\"."
  type        = string
  default     = "cognito"

  validation {
    condition     = contains(["cognito", "oidc"], var.avp_identity_source_type)
    error_message = "avp_identity_source_type must be \"cognito\" or \"oidc\"."
  }
}

variable "avp_cognito_user_pool_arn" {
  description = "Cognito user pool ARN that issues broker access tokens. Required when avp_identity_source_type = \"cognito\"."
  type        = string
  default     = ""
}

variable "avp_cognito_client_ids" {
  description = "Cognito app-client IDs whose tokens AVP accepts. Typically the postern-cli client created by examples/terraform/cognito. Required when avp_identity_source_type = \"cognito\"."
  type        = list(string)
  default     = []
}

variable "avp_oidc_issuer" {
  description = "OIDC issuer URL for the AVP identity source. Required when avp_identity_source_type = \"oidc\". Typically the same value as idp_issuer."
  type        = string
  default     = ""
}

variable "avp_oidc_audiences" {
  description = "List of audience-claim values AVP accepts on incoming access tokens. Required when avp_identity_source_type = \"oidc\"."
  type        = list(string)
  default     = []
}

variable "avp_oidc_principal_id_claim" {
  description = "Access-token claim AVP uses as the Cedar principal id. Defaults to \"sub\"; operators using a different stable claim name override here."
  type        = string
  default     = "sub"
}

variable "avp_oidc_entity_id_prefix" {
  description = "Optional prefix AVP prepends to the principal id claim when building the Cedar entity id. Useful when the same policy store sees principals from multiple identity sources."
  type        = string
  default     = ""
}

variable "avp_cognito_group_entity_type" {
  description = "When set, the AVP Cognito identity source maps `cognito:groups` token claims to Cedar entities of this type instead of leaving them as a Set<String> attribute on the principal. Set to e.g. \"Postern::Group\" so policies can write `principal in Postern::Group::\"engineers\"` against group membership. Requires `avp_schema_json` to declare the Group entity and the User entity's `memberOfTypes`. Empty (default) keeps the v1 behavior — groups are visible to Cedar only as a `cognito:groups` attribute. Only meaningful when `avp_identity_source_type = \"cognito\"`."
  type        = string
  default     = ""
}

# AVP policy + schema customization -------------------------------------------
#
# The module ships a permissive starter Cedar policy and a minimal schema
# (User / Device entities, MintOperatorCert action). Operators tighten policy
# and extend the schema as their access model matures.
#
# Two ways to manage your own policies:
#
#  - Leave `avp_install_starter_policy = true` (default) and add your own
#    policies alongside the starter via `aws_verifiedpermissions_policy`
#    resources in the caller, referencing `module.<name>.avp_policy_store_id`.
#  - Set `avp_install_starter_policy = false` to skip the bundled starter
#    entirely and manage the full policy set in the caller. Useful when the
#    starter's "any authenticated user can mint" stance is wider than you
#    want from day one.
#
# The schema variable accepts a JSON document (Cedar's `aws_verifiedpermissions_schema`
# value field). When empty, the bundled `cedar/schema.json` is used. Override
# when your policies reference attributes the bundled schema doesn't declare —
# bool / Long device attributes flow through from the Registry, but Cedar
# STRICT validation rejects policies that reference attributes not in the
# schema.

variable "avp_install_starter_policy" {
  description = "When true (default), the module creates a permissive starter Cedar policy that allows any authenticated principal to mint an operator cert. Set to false to manage the full policy set yourself via `aws_verifiedpermissions_policy` resources in the caller."
  type        = bool
  default     = true
}

variable "avp_schema_json" {
  description = "Cedar schema JSON document to install on the AVP policy store. When empty (default), the module uses its bundled schema (User + Device entities, MintOperatorCert action). Override when policies need to reference additional Device attributes (bool, Long, or extra String attributes) — Cedar STRICT validation rejects policies referencing attributes the schema doesn't declare."
  type        = string
  default     = ""
}

# Registry backend ------------------------------------------------------------
#
# The broker's device Registry has two concrete implementations:
#
#  - "dynamodb" (default): module provisions a DynamoDB table that the broker
#    reads device records from. Operators populate the table out of band.
#  - "http": module wires the broker to an operator-managed HTTP service via
#    POSTERN_REGISTRY_HTTP_URL + auth env vars. The DynamoDB registry table is
#    not created and the Lambda role does not grant dynamodb:GetItem.
#
# The two are mutually exclusive; pick one. The rate-limit table is unaffected
# by this choice — it's a separate DynamoDB table for per-engineer counters.

variable "registry_backend" {
  description = "Registry backend type. \"dynamodb\" (default) provisions the device-registry table; \"http\" wires the broker to an external HTTP registry service via registry_http_* variables and skips the table."
  type        = string
  default     = "dynamodb"

  validation {
    condition     = contains(["dynamodb", "http"], var.registry_backend)
    error_message = "registry_backend must be \"dynamodb\" or \"http\"."
  }
}

variable "registry_http_url" {
  description = "URL of the operator's HTTP registry service. Required when registry_backend = \"http\". See `docs/registry-http-api.md` in the Postern repo for the endpoint contract."
  type        = string
  default     = ""
}

variable "registry_http_auth_mode" {
  description = "Authentication mode the broker uses for HTTP registry calls. One of: \"none\" (trusted-network deployments), \"bearer\" (sends Authorization: Bearer <token>), or \"aws_sigv4\" (signs requests with the broker's IAM role for an API-Gateway-fronted registry; the Lambda role needs execute-api:Invoke on the target API separately — attach via the broker_lambda_role_name output)."
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "bearer", "aws_sigv4"], var.registry_http_auth_mode)
    error_message = "registry_http_auth_mode must be \"none\", \"bearer\", or \"aws_sigv4\"."
  }
}

variable "registry_http_bearer_token" {
  description = "Bearer token sent as `Authorization: Bearer <token>` when registry_http_auth_mode = \"bearer\". Sensitive — pass via env (`TF_VAR_registry_http_bearer_token`) or a secret-store ref, not a literal in committed YAML."
  type        = string
  default     = ""
  sensitive   = true
}

variable "registry_http_aws_region" {
  description = "AWS region for SigV4 signing when registry_http_auth_mode = \"aws_sigv4\". Empty defers to the AWS SDK's default-region chain inside the broker."
  type        = string
  default     = ""
}

variable "registry_http_timeout" {
  description = "Per-request HTTP timeout the broker enforces on registry calls (Go duration string, e.g. \"15s\", \"30s\"). Empty (default) uses the broker's built-in ≈15s default, sized for the typical Lambda-fronted-by-API-Gateway cold-start budget. Tighten when the registry is on-network with sub-second p99 latency; loosen (up to the lambda_timeout_seconds ceiling) when registry cold starts run longer."
  type        = string
  default     = ""
}

# Broker tunables --------------------------------------------------------------

variable "cert_ttl_operator" {
  description = "TTL for issued operator certificates (Go duration string)."
  type        = string
  default     = "12h"
}

variable "ratelimit_limit" {
  description = "Per-engineer rate-limit count within the window."
  type        = number
  default     = 60
}

variable "ratelimit_window" {
  description = "Rate-limit window (Go duration string)."
  type        = string
  default     = "1m"
}

variable "trusted_proxies" {
  description = "CIDRs the broker treats as trusted reverse proxies for X-Forwarded-For parsing. Empty for direct deploy. Set to API Gateway egress ranges if a proxy sits between API GW and the engineer."
  type        = list(string)
  default     = []
}

variable "log_level" {
  description = "Broker slog level (debug, info, warn, error)."
  type        = string
  default     = "info"
}

# Custom domain (optional) -----------------------------------------------------
#
# When set, the module provisions an ACM certificate (DNS-validated against the
# named Route 53 zone), attaches it to the API Gateway HTTP API as a custom
# domain, and creates an alias A-record pointing the FQDN at the API Gateway.
# Engineers reach the broker at https://<broker_domain_name>.
#
# When unset, the module skips all DNS work and the broker is reachable at the
# AWS-generated execute-api URL (terraform output broker_url falls back to it).

variable "route53_zone_name" {
  description = "Public Route 53 hosted-zone name that owns the broker FQDN, e.g. \"example.com\". Trailing dot is optional. Required when broker_domain_name is set."
  type        = string
  default     = ""
}

variable "broker_domain_name" {
  description = "Fully-qualified broker hostname, e.g. \"broker.example.com\". Empty disables the custom-domain path."
  type        = string
  default     = ""

  validation {
    condition     = var.broker_domain_name == "" || var.route53_zone_name != ""
    error_message = "broker_domain_name requires route53_zone_name to be set too."
  }
}

# Lambda packaging -------------------------------------------------------------

variable "broker_lambda_zip_path" {
  description = "Absolute path to a prebuilt broker-lambda.zip. When empty, the module builds the zip at apply time via `make broker-lambda.zip` (which requires make / go / zip on the apply machine and assumes the module is consumed from within the Postern repo). Module consumers running terraform from a CI runner without the Go toolchain should build the zip in a prior CI step and pass its path here."
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = "Lambda memory size. Memory also scales CPU — 512 is comfortable for the cert-issuance hot path with KMS Sign + AVP + DynamoDB + CloudWatch."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Lambda invocation timeout. Cold start runs OIDC discovery + KMS GetPublicKey; 30 leaves headroom."
  type        = number
  default     = 30
}

variable "lambda_log_retention_days" {
  description = "Retention for the Lambda function's CloudWatch log group (Lambda's own logs, not the audit log)."
  type        = number
  default     = 30
}

variable "audit_log_retention_days" {
  description = "Retention for the broker audit log group."
  type        = number
  default     = 365
}

# API Gateway access logging + JWT authorizer ---------------------------------
#
# Two independent knobs that often pair together but don't have to:
#
#   apigw_access_logs_enabled (default true) — APIGW writes a JSON access
#   log line per request to a separate CloudWatch log group. Standard
#   observability; useful regardless of whether the JWT authorizer is on.
#
#   apigw_jwt_authorizer_enabled (default false) — APIGW pre-validates the
#   bearer JWT's signature, issuer, and exp before invoking the broker
#   Lambda. Defense-in-depth against parser-side CVEs and cold-start
#   amplification on bad-token probes. Audience is NOT pinned at the edge
#   (the broker enforces aud-OR-scope, which the edge's AND-only authorizer
#   can't express). The broker still does its full check; APIGW is a
#   pre-filter, not the authority.
#
# When the authorizer is on, every route — including `/healthz` — is
# JWT-gated; the Lambda+APIGW path doesn't need an unauthenticated probe
# (see the README "Layered JWT defense" section).

variable "apigw_access_logs_enabled" {
  description = "When true (default), API Gateway writes a JSON access log line per request to a separate CloudWatch log group (one line per Lambda invocation attempt, including pre-Lambda rejections when the JWT authorizer is on). Independent of apigw_jwt_authorizer_enabled. Operators with strict log-cost budgets can turn this off."
  type        = bool
  default     = true
}

variable "apigw_access_log_retention_days" {
  description = "Retention for the API Gateway HTTP API access log group (only created when apigw_access_logs_enabled = true). Distinct from audit_log_retention_days because access logs are operational debug data while audit logs are forensic — they typically have different retention requirements."
  type        = number
  default     = 30
}

variable "apigw_jwt_authorizer_enabled" {
  description = "Enable the API Gateway HTTP API JWT authorizer in front of the broker Lambda. When true, APIGW validates the access token's signature, issuer, and expiration before invoking Lambda — defense-in-depth that drops bad-token probes before they reach broker code. Audience is not pinned at the edge; the broker enforces aud-OR-scope and does the full check. Recommended on for internet-facing deployments. See the README \"Layered JWT defense\" section."
  type        = bool
  default     = false
}

# Tunneling (firewalled-device recovery) --------------------------------------
#
# When tunneling_enabled = true, the broker mints AWS IoT Secure Tunnels in
# response to /ssh/tunnel requests so engineers can reach firewalled devices
# via `postern ssh --tunnel`, `postern scp --tunnel`, and `postern tunnel`.
# The destination side (device-resident proxy) is an operator concern — the
# framework documents AWS IoT Greengrass's `aws.greengrass.SecureTunneling`
# component as the v1 reference (see examples/on-device/secure-tunnel/).
#
# Three variables wire the path end-to-end:
#
#  - tunneling_enabled (default false) gates the IAM grant AND the Lambda
#    env-var injection. With it off, /ssh/tunnel returns 501 and the
#    broker carries no iot:OpenTunnel permission — opt-in by design.
#  - tunneling_iot_region selects which AWS region the broker's iot
#    secure-tunneling client targets. Empty defers to the deployment
#    region (resolved via data.aws_region.current) so single-region
#    operators leave it alone.
#  - tunneling_default_max_lifetime_minutes is the broker's fallback TTL
#    when the engineer omits --max-lifetime. Defaults to 480 (8 hours,
#    a full engineer workday); AWS caps individual tunnels at 720 (12
#    hours).

variable "tunneling_enabled" {
  description = "When true, the broker is wired for the firewalled-device path: IAM grant for iot:OpenTunnel + Lambda env vars for the tunneling backend region/default-TTL. The /ssh/tunnel handler returns 501 when this is false. Opt-in because the AWS IoT Secure Tunneling control plane is operator-paid and not all deployments need the firewalled-device recovery path."
  type        = bool
  default     = false
}

variable "tunneling_iot_region" {
  description = "AWS region for the broker's iot secure-tunneling client. Empty (default) resolves to the deployment region via data.aws_region.current so single-region operators leave it alone. Cross-region operators that run the broker in one region and the IoT control plane in another set this explicitly. Only consulted when tunneling_enabled = true."
  type        = string
  default     = ""
}

variable "tunneling_default_max_lifetime_minutes" {
  description = "Broker fallback TTL (in minutes) for tunnels when the engineer omits --max-lifetime. AWS caps individual tunnels at 720 (12 hours); the default here is 480 (8 hours), matching a full engineer workday so a tunnel left idle through meetings survives. Only consulted when tunneling_enabled = true."
  type        = number
  default     = 480

  validation {
    condition     = var.tunneling_default_max_lifetime_minutes > 0 && var.tunneling_default_max_lifetime_minutes <= 720
    error_message = "tunneling_default_max_lifetime_minutes must be in (0, 720] — AWS IoT Secure Tunneling caps individual tunnels at 12 hours."
  }
}

variable "tunneling_thing_name_format" {
  description = "Format the broker substitutes the resolved device serial into when calling AWS IoT OpenTunnel. The literal substring `{serial}` is replaced with the registry-resolved hardware serial; other characters pass through verbatim. The placeholder must appear exactly once. The default `device-{serial}` preserves Postern's historical thing-name convention; operators whose AWS IoT thing names use a different scheme set this to match (e.g. `{serial}` for no prefix, `prefix-{serial}-suffix` for both). Only consulted when tunneling_enabled = true."
  type        = string
  default     = "device-{serial}"

  validation {
    condition     = length(regexall("\\{serial\\}", var.tunneling_thing_name_format)) == 1
    error_message = "tunneling_thing_name_format must contain exactly one {serial} placeholder."
  }
}
