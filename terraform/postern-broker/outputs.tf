output "module_version" {
  description = "The Postern release version this module was tagged with (e.g. \"0.9.0\"). release-please bumps the value on every release. Consumers can compare against their own pinned version to catch `?ref=` drift at plan time: `condition = module.broker.module_version == replace(var.postern_version, \"v\", \"\")`."
  value       = local.module_version
}

output "broker_url" {
  description = "Base URL engineers paste into ~/.postern/config.yaml as the broker field. Resolves to https://<broker_domain_name> when the custom-domain path is enabled, otherwise the API Gateway invoke URL."
  value       = local.custom_domain_enabled ? "https://${var.broker_domain_name}" : aws_apigatewayv2_api.broker.api_endpoint
}

output "broker_apigw_invoke_url" {
  description = "Raw API Gateway invoke URL. Engineers should not use this when a custom domain is set; kept for diagnostics."
  value       = aws_apigatewayv2_api.broker.api_endpoint
}

output "ssh_ca_kms_key_arn" {
  description = "KMS key ARN of the SSH CA. Use `aws kms get-public-key` to extract the public key for device TrustedUserCAKeys provisioning."
  value       = aws_kms_key.ssh_ca.arn
}

output "ssh_ca_kms_key_id" {
  description = "KMS key ID of the SSH CA."
  value       = aws_kms_key.ssh_ca.id
}

output "registry_table_name" {
  description = "DynamoDB device registry table name. Operators populate this table out of band; the broker only reads. Returns null when registry_backend = \"http\" (no table is provisioned in that case)."
  value       = var.registry_backend == "dynamodb" ? aws_dynamodb_table.registry[0].name : null
}

output "ratelimit_table_name" {
  description = "DynamoDB rate-limit table name."
  value       = aws_dynamodb_table.ratelimit.name
}

output "audit_log_group_name" {
  description = "CloudWatch log group the broker writes audit events to."
  value       = aws_cloudwatch_log_group.audit.name
}

output "apigw_access_log_group_name" {
  description = "CloudWatch log group for API Gateway HTTP API access logs (rejections by the JWT authorizer, request status, latency). Null when apigw_jwt_authorizer_enabled = false."
  value       = var.apigw_jwt_authorizer_enabled ? aws_cloudwatch_log_group.apigw_access[0].name : null
}

output "avp_policy_store_id" {
  description = "AVP policy store ID."
  value       = aws_verifiedpermissions_policy_store.broker.id

  # Force downstream consumers (operators attaching their own
  # aws_verifiedpermissions_policy resources via this output) to wait for
  # the schema to settle before applying their policies. AVP's STRICT
  # validation mode rejects policies that reference undeclared actions or
  # entity types; without this depends_on, Terraform's parallel apply can
  # race a schema-add against a downstream policy update that references
  # the new action, producing a transient apply failure on the first
  # `terraform apply` after a coordinated schema+policy change.
  depends_on = [aws_verifiedpermissions_schema.broker]
}

output "broker_lambda_function_name" {
  description = "Lambda function name (for log streaming, manual invocation, etc.)."
  value       = aws_lambda_function.broker.function_name
}

output "broker_lambda_role_name" {
  description = "IAM role name of the broker Lambda. Attach additional policies via `aws_iam_role_policy_attachment` when operator-specific permissions are needed — typical case: granting execute-api:Invoke on an HTTP registry's API Gateway when registry_http_auth_mode = \"aws_sigv4\"."
  value       = aws_iam_role.broker_lambda.name
}

output "broker_lambda_role_arn" {
  description = "IAM role ARN of the broker Lambda. Same use cases as broker_lambda_role_name."
  value       = aws_iam_role.broker_lambda.arn
}
