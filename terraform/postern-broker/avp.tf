# AVP policy store + Cedar schema + identity source + starter policy.
#
# The broker calls IsAuthorizedWithToken with the engineer's access token.
# AVP uses the identity source to map the token to a Cedar principal and
# evaluates the policy store's policies. The module supports two identity-
# source flavors (cognito and oidc), selected by var.avp_identity_source_type.
# Token cryptographic verification happens inside the broker; AVP only uses
# the identity source for principal mapping.

resource "aws_verifiedpermissions_policy_store" "broker" {
  validation_settings {
    mode = "STRICT"
  }
  description = "Postern broker policies (${var.name_prefix})"
}

resource "aws_verifiedpermissions_schema" "broker" {
  policy_store_id = aws_verifiedpermissions_policy_store.broker.id

  definition {
    value = var.avp_schema_json != "" ? var.avp_schema_json : file("${path.module}/cedar/schema.json")
  }
}

resource "aws_verifiedpermissions_policy" "starter_allow" {
  count = var.avp_install_starter_policy ? 1 : 0

  policy_store_id = aws_verifiedpermissions_policy_store.broker.id

  definition {
    static {
      description = "Starter: any authenticated user may mint an operator cert."
      statement   = file("${path.module}/cedar/starter.cedar")
    }
  }

  depends_on = [aws_verifiedpermissions_schema.broker]
}

# Cross-variable validation. The identity-source resource below would also
# fail at apply time with the right inputs missing, but a precondition here
# surfaces the operator-side fix earlier (at plan) with a clear message.
resource "terraform_data" "avp_identity_source_inputs_present" {
  lifecycle {
    precondition {
      condition     = var.avp_identity_source_type != "cognito" || (var.avp_cognito_user_pool_arn != "" && length(var.avp_cognito_client_ids) > 0)
      error_message = "avp_identity_source_type=\"cognito\" requires avp_cognito_user_pool_arn and avp_cognito_client_ids to be set."
    }
    precondition {
      condition     = var.avp_identity_source_type != "oidc" || (var.avp_oidc_issuer != "" && length(var.avp_oidc_audiences) > 0)
      error_message = "avp_identity_source_type=\"oidc\" requires avp_oidc_issuer and avp_oidc_audiences to be set."
    }
  }
}

# Cross-variable validation for the registry backend selection. Same pattern
# as the AVP block above — preconditions surface input mistakes at plan time
# rather than letting the broker fail at startup with a less obvious error.
resource "terraform_data" "registry_backend_inputs_present" {
  lifecycle {
    precondition {
      condition     = var.registry_backend != "http" || var.registry_http_url != ""
      error_message = "registry_backend=\"http\" requires registry_http_url to be set."
    }
    precondition {
      condition     = var.registry_backend != "http" || var.registry_http_auth_mode != "bearer" || var.registry_http_bearer_token != ""
      error_message = "registry_http_auth_mode=\"bearer\" requires registry_http_bearer_token to be set."
    }
    precondition {
      condition = (
        var.registry_backend == "http" ||
        (var.registry_http_url == "" && var.registry_http_bearer_token == "" && var.registry_http_aws_region == "")
      )
      error_message = "registry_http_* variables are only valid when registry_backend = \"http\"."
    }
  }
}

resource "aws_verifiedpermissions_identity_source" "broker" {
  policy_store_id = aws_verifiedpermissions_policy_store.broker.id

  configuration {
    dynamic "cognito_user_pool_configuration" {
      for_each = var.avp_identity_source_type == "cognito" ? [1] : []
      content {
        user_pool_arn = var.avp_cognito_user_pool_arn
        client_ids    = var.avp_cognito_client_ids

        dynamic "group_configuration" {
          for_each = var.avp_cognito_group_entity_type != "" ? [1] : []
          content {
            group_entity_type = var.avp_cognito_group_entity_type
          }
        }
      }
    }

    dynamic "open_id_connect_configuration" {
      for_each = var.avp_identity_source_type == "oidc" ? [1] : []
      content {
        issuer           = var.avp_oidc_issuer
        entity_id_prefix = var.avp_oidc_entity_id_prefix != "" ? var.avp_oidc_entity_id_prefix : null

        token_selection {
          access_token_only {
            audiences          = var.avp_oidc_audiences
            principal_id_claim = var.avp_oidc_principal_id_claim
          }
        }
      }
    }
  }

  principal_entity_type = "Postern::User"

  depends_on = [terraform_data.avp_identity_source_inputs_present]
}
