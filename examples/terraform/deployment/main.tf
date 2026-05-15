# Minimal example consumer of the postern-broker module.
#
# In this in-repo example we point at the module by relative path so a
# `terraform init && terraform apply` here just works against a fresh
# checkout. When adopting Postern in your own infrastructure repo, replace
# the source line with a git ref:
#
#   source = "github.com/atomicgravity/postern//terraform/postern-broker?ref=v1.0.0"
#
# Pin to a tag (or a commit SHA) so module upgrades are explicit. The
# variables, outputs, and resource shapes are the same in either form.

module "broker" {
  source = "../../../terraform/postern-broker"

  name_prefix = var.name_prefix
  tags        = var.tags

  idp_issuer         = var.idp_issuer
  idp_audience       = var.idp_audience
  idp_required_scope = var.idp_required_scope

  avp_identity_source_type      = var.avp_identity_source_type
  avp_cognito_user_pool_arn     = var.avp_cognito_user_pool_arn
  avp_cognito_client_ids        = var.avp_cognito_client_ids
  avp_oidc_issuer               = var.avp_oidc_issuer
  avp_oidc_audiences            = var.avp_oidc_audiences
  avp_oidc_principal_id_claim   = var.avp_oidc_principal_id_claim
  avp_oidc_entity_id_prefix     = var.avp_oidc_entity_id_prefix
  avp_cognito_group_entity_type = var.avp_cognito_group_entity_type
  avp_install_starter_policy    = var.avp_install_starter_policy
  avp_schema_json               = var.avp_schema_json

  registry_backend           = var.registry_backend
  registry_http_url          = var.registry_http_url
  registry_http_auth_mode    = var.registry_http_auth_mode
  registry_http_bearer_token = var.registry_http_bearer_token
  registry_http_aws_region   = var.registry_http_aws_region
  registry_http_timeout      = var.registry_http_timeout

  cert_ttl_operator  = var.cert_ttl_operator
  ratelimit_limit    = var.ratelimit_limit
  ratelimit_window   = var.ratelimit_window
  trusted_proxies    = var.trusted_proxies
  log_level          = var.log_level
  route53_zone_name  = var.route53_zone_name
  broker_domain_name = var.broker_domain_name

  broker_lambda_zip_path    = var.broker_lambda_zip_path
  lambda_memory_mb          = var.lambda_memory_mb
  lambda_timeout_seconds    = var.lambda_timeout_seconds
  lambda_log_retention_days = var.lambda_log_retention_days
  audit_log_retention_days  = var.audit_log_retention_days

  apigw_access_logs_enabled       = var.apigw_access_logs_enabled
  apigw_access_log_retention_days = var.apigw_access_log_retention_days
  apigw_jwt_authorizer_enabled    = var.apigw_jwt_authorizer_enabled
}
