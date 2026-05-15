output "broker_url" {
  description = "Base URL engineers paste into ~/.postern/config.yaml as the broker field."
  value       = module.broker.broker_url
}

output "broker_apigw_invoke_url" {
  description = "Raw API Gateway invoke URL for diagnostics."
  value       = module.broker.broker_apigw_invoke_url
}

output "ssh_ca_kms_key_arn" {
  description = "KMS key ARN of the SSH CA. Use `aws kms get-public-key` to extract the public key for device TrustedUserCAKeys."
  value       = module.broker.ssh_ca_kms_key_arn
}

output "ssh_ca_kms_key_id" {
  description = "KMS key ID of the SSH CA."
  value       = module.broker.ssh_ca_kms_key_id
}

output "registry_table_name" {
  description = "DynamoDB device registry table name."
  value       = module.broker.registry_table_name
}

output "ratelimit_table_name" {
  description = "DynamoDB rate-limit table name."
  value       = module.broker.ratelimit_table_name
}

output "audit_log_group_name" {
  description = "CloudWatch log group the broker writes audit events to."
  value       = module.broker.audit_log_group_name
}

output "avp_policy_store_id" {
  description = "AVP policy store ID."
  value       = module.broker.avp_policy_store_id
}
