locals {
  callback_urls   = [for port in var.loopback_ports : "http://127.0.0.1:${port}/cb"]
  broker_resource = coalesce(var.broker_resource, var.broker_url)
}

resource "aws_cognito_user_pool" "postern" {
  name = "${var.name_prefix}-users"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }
}

resource "aws_cognito_resource_server" "postern" {
  user_pool_id = aws_cognito_user_pool.postern.id
  identifier   = local.broker_resource
  name         = "Postern broker"
}

resource "aws_cognito_user_pool_client" "postern_cli" {
  name         = "${var.name_prefix}-cli"
  user_pool_id = aws_cognito_user_pool.postern.id

  # This is a public CLI client. Postern uses Authorization Code + S256 PKCE;
  # this Cognito flag enables OAuth flows for the app client, not client-secret auth.
  generate_secret                      = false
  explicit_auth_flows                  = []
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  callback_urls                        = local.callback_urls
  supported_identity_providers         = ["COGNITO"]

  access_token_validity  = var.access_token_validity_minutes
  id_token_validity      = var.id_token_validity_minutes
  refresh_token_validity = var.refresh_token_validity_days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"

  refresh_token_rotation {
    feature                    = "ENABLED"
    retry_grace_period_seconds = 60
  }

  depends_on = [
    aws_cognito_resource_server.postern,
  ]
}

resource "aws_cognito_user_pool_domain" "postern" {
  domain                = var.managed_login_domain_prefix
  managed_login_version = 2
  user_pool_id          = aws_cognito_user_pool.postern.id
}

resource "aws_cognito_managed_login_branding" "postern_cli" {
  client_id                   = aws_cognito_user_pool_client.postern_cli.id
  user_pool_id                = aws_cognito_user_pool.postern.id
  use_cognito_provided_values = true

  depends_on = [
    aws_cognito_user_pool_domain.postern,
  ]
}
