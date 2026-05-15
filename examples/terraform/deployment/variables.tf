variable "aws_region" {
  description = "AWS region for all broker resources."
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to every named AWS resource so multiple Postern deployments can coexist in one account."
  type        = string
  default     = "postern"
}

variable "tags" {
  description = "Tags applied to every taggable resource the module creates."
  type        = map(string)
  default     = {}
}

# IdP --------------------------------------------------------------------------

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

# AVP identity source ----------------------------------------------------------

variable "avp_identity_source_type" {
  description = "AVP identity source flavor: \"cognito\" or \"oidc\"."
  type        = string
  default     = "cognito"
}

variable "avp_cognito_user_pool_arn" {
  description = "Cognito user pool ARN. Required when avp_identity_source_type = \"cognito\"."
  type        = string
  default     = ""
}

variable "avp_cognito_client_ids" {
  description = "Cognito app-client IDs. Required when avp_identity_source_type = \"cognito\"."
  type        = list(string)
  default     = []
}

variable "avp_oidc_issuer" {
  description = "OIDC issuer URL for the AVP identity source. Required when avp_identity_source_type = \"oidc\"."
  type        = string
  default     = ""
}

variable "avp_oidc_audiences" {
  description = "Audience-claim values AVP accepts. Required when avp_identity_source_type = \"oidc\"."
  type        = list(string)
  default     = []
}

variable "avp_oidc_principal_id_claim" {
  description = "Access-token claim AVP uses as the Cedar principal id. Defaults to \"sub\"."
  type        = string
  default     = "sub"
}

variable "avp_oidc_entity_id_prefix" {
  description = "Optional prefix AVP prepends to the principal id when building the Cedar entity id."
  type        = string
  default     = ""
}

variable "avp_cognito_group_entity_type" {
  description = "When set, AVP maps `cognito:groups` token claims to Cedar entities of this type (e.g. \"Postern::Group\"). Requires avp_schema_json to declare the Group entity. Only meaningful when avp_identity_source_type = \"cognito\"."
  type        = string
  default     = ""
}

variable "avp_install_starter_policy" {
  description = "When true (default), the module creates a permissive starter Cedar policy. Set to false to manage the full policy set yourself via aws_verifiedpermissions_policy resources in the caller."
  type        = bool
  default     = true
}

variable "avp_schema_json" {
  description = "Cedar schema JSON to install on the AVP policy store. Empty (default) uses the module's bundled schema. Override when policies need to reference additional Device attributes."
  type        = string
  default     = ""
}

# Registry backend ------------------------------------------------------------

variable "registry_backend" {
  description = "Registry backend type: \"dynamodb\" (default) or \"http\"."
  type        = string
  default     = "dynamodb"
}

variable "registry_http_url" {
  description = "HTTP registry URL. Required when registry_backend = \"http\"."
  type        = string
  default     = ""
}

variable "registry_http_auth_mode" {
  description = "HTTP registry auth mode: \"none\", \"bearer\", or \"aws_sigv4\"."
  type        = string
  default     = "none"
}

variable "registry_http_bearer_token" {
  description = "Bearer token for the HTTP registry. Required when registry_http_auth_mode = \"bearer\"."
  type        = string
  default     = ""
  sensitive   = true
}

variable "registry_http_aws_region" {
  description = "AWS region for SigV4 signing of HTTP registry calls. Empty defers to the broker's AWS SDK default chain."
  type        = string
  default     = ""
}

variable "registry_http_timeout" {
  description = "Per-request HTTP timeout for registry calls (Go duration string). Empty (default) uses the broker's built-in ≈15s default."
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
  description = "Trusted reverse-proxy CIDRs for X-Forwarded-For parsing."
  type        = list(string)
  default     = []
}

variable "log_level" {
  description = "Broker slog level (debug, info, warn, error)."
  type        = string
  default     = "info"
}

# Custom domain ----------------------------------------------------------------

variable "route53_zone_name" {
  description = "Public Route 53 hosted-zone name that owns the broker FQDN. Required when broker_domain_name is set."
  type        = string
  default     = ""
}

variable "broker_domain_name" {
  description = "Fully-qualified broker hostname. Empty disables the custom-domain path."
  type        = string
  default     = ""
}

# Lambda packaging -------------------------------------------------------------

variable "broker_lambda_zip_path" {
  description = "Absolute path to a prebuilt broker-lambda.zip. When empty, the module builds at apply time via make."
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = "Lambda memory size in MB."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Lambda invocation timeout in seconds."
  type        = number
  default     = 30
}

variable "lambda_log_retention_days" {
  description = "Retention for the Lambda function's CloudWatch log group."
  type        = number
  default     = 30
}

variable "audit_log_retention_days" {
  description = "Retention for the broker audit log group."
  type        = number
  default     = 365
}

# API Gateway tunables --------------------------------------------------------

variable "apigw_access_logs_enabled" {
  description = "When true (default), API Gateway writes a JSON access log line per request to a separate CloudWatch log group. Independent of apigw_jwt_authorizer_enabled."
  type        = bool
  default     = true
}

variable "apigw_access_log_retention_days" {
  description = "Retention for the API Gateway HTTP API access log group (only created when apigw_access_logs_enabled = true)."
  type        = number
  default     = 30
}

variable "apigw_jwt_authorizer_enabled" {
  description = "When true, API Gateway validates the bearer JWT (signature, issuer, expiration, audience if idp_audience is set) before invoking Lambda. Defense-in-depth; the broker still does its full check."
  type        = bool
  default     = false
}
