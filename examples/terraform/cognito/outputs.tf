output "user_pool_id" {
  description = "Cognito user pool ID."
  value       = aws_cognito_user_pool.postern.id
}

output "user_pool_client_id" {
  description = "Cognito app client ID for Postern CLI login."
  value       = aws_cognito_user_pool_client.postern_cli.id
}

output "issuer" {
  description = "OIDC issuer URL for Postern CLI config."
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.postern.id}"
}

output "managed_login_domain" {
  description = "Cognito managed-login domain."
  value       = "https://${aws_cognito_user_pool_domain.postern.domain}.auth.${var.aws_region}.amazoncognito.com"
}

output "resource" {
  description = "OAuth resource value requested by Postern CLI and validated by the broker as aud."
  value       = local.broker_resource
}

output "engineer_config_yaml" {
  description = "YAML snippet engineers can paste into ~/.postern/config.yaml."
  value = yamlencode({
    default = {
      broker = var.broker_url
      idp = {
        issuer         = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.postern.id}"
        client_id      = aws_cognito_user_pool_client.postern_cli.id
        audience       = local.broker_resource
        audience_param = "resource"
      }
    }
  })
}