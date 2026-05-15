# Broker Lambda + API Gateway HTTP API. The HTTP API uses the $default route
# so all paths/methods reach the broker; method/path validation happens
# inside brokerhandlers.New (4 endpoints + method/auth checks).

# Build the Lambda zip during `terraform apply` whenever the Go source tree
# changes. The trigger also fires when the zip file is missing, so a fresh
# checkout (no bin/) self-bootstraps on first apply.
#
# Skipped entirely when the caller supplied a pre-built zip via
# var.broker_lambda_zip_path — typical for module consumers running terraform
# from a CI runner that doesn't have make / go / zip installed.
resource "terraform_data" "broker_lambda_build" {
  count = local.build_required ? 1 : 0

  input = local.broker_lambda_source_hash

  triggers_replace = {
    sources_hash = local.broker_lambda_source_hash
    zip_present  = fileexists(local.broker_lambda_zip_path)
  }

  provisioner "local-exec" {
    command     = "make broker-lambda.zip"
    working_dir = "${path.module}/../.."
  }
}

resource "aws_cloudwatch_log_group" "broker_lambda" {
  name              = "/aws/lambda/${var.name_prefix}-broker"
  retention_in_days = var.lambda_log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "broker" {
  function_name = "${var.name_prefix}-broker"
  role          = aws_iam_role.broker_lambda.arn
  filename      = local.broker_lambda_zip_path
  # source_code_hash: when building in-tree, propagate the source-hash output
  # from terraform_data; when caller supplied a zip, hash the zip itself so
  # the Lambda function re-uploads on zip-content changes.
  source_code_hash = local.build_required ? terraform_data.broker_lambda_build[0].output : filebase64sha256(local.broker_lambda_zip_path)
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_seconds
  tags             = var.tags

  # Broker reads its config from POSTERN_* env vars. No file is mounted.
  # Optional fields use empty strings; the broker treats them as "unset"
  # and falls back to defaults.
  environment {
    variables = merge(
      {
        POSTERN_IDP_ISSUER                 = var.idp_issuer
        POSTERN_IDP_AUDIENCE               = var.idp_audience
        POSTERN_IDP_REQUIRED_SCOPE         = var.idp_required_scope
        POSTERN_SIGNER_KMS_KEY_ARN         = aws_kms_key.ssh_ca.arn
        POSTERN_RATELIMIT_DYNAMODB_TABLE   = aws_dynamodb_table.ratelimit.name
        POSTERN_RATELIMIT_LIMIT            = tostring(var.ratelimit_limit)
        POSTERN_RATELIMIT_WINDOW           = var.ratelimit_window
        POSTERN_AUDIT_CLOUDWATCH_LOG_GROUP = aws_cloudwatch_log_group.audit.name
        POSTERN_POLICY_AVP_POLICY_STORE_ID = aws_verifiedpermissions_policy_store.broker.id
        POSTERN_CERT_TTL_OPERATOR          = var.cert_ttl_operator
        POSTERN_TRUSTED_PROXIES            = join(",", var.trusted_proxies)
        POSTERN_LOG_LEVEL                  = var.log_level
      },
      # Registry backend wiring. Exactly one of the two blocks below is non-
      # empty per the registry_backend variable; the broker's env-override
      # resolver picks the matching backend at startup.
      var.registry_backend == "dynamodb" ? {
        POSTERN_REGISTRY_DYNAMODB_TABLE = aws_dynamodb_table.registry[0].name
        } : {
        POSTERN_REGISTRY_HTTP_URL          = var.registry_http_url
        POSTERN_REGISTRY_HTTP_AUTH_MODE    = var.registry_http_auth_mode
        POSTERN_REGISTRY_HTTP_BEARER_TOKEN = var.registry_http_bearer_token
        POSTERN_REGISTRY_HTTP_AWS_REGION   = var.registry_http_aws_region
        POSTERN_REGISTRY_HTTP_TIMEOUT      = var.registry_http_timeout
      },
      # Tunneling backend. Both env vars are absent when the feature is
      # off; the broker's TunnelingConfig stays nil and /ssh/tunnel
      # returns 501. When on, IOT_REGION defaults to the deployment region
      # so single-region operators don't need to set tunneling_iot_region.
      var.tunneling_enabled ? {
        POSTERN_TUNNELING_IOT_REGION                   = var.tunneling_iot_region != "" ? var.tunneling_iot_region : data.aws_region.current.region
        POSTERN_TUNNELING_DEFAULT_MAX_LIFETIME_MINUTES = tostring(var.tunneling_default_max_lifetime_minutes)
        POSTERN_TUNNELING_THING_NAME_FORMAT            = var.tunneling_thing_name_format
      } : {}
    )
  }

  # Make sure prerequisite resources exist before the Lambda starts; the
  # broker fails closed at init if KMS, DynamoDB, AVP, or the audit stream
  # is missing. The build resource ensures the zip is on disk before upload.
  depends_on = [
    terraform_data.broker_lambda_build,
    aws_iam_role_policy.broker_lambda_inline,
    aws_iam_role_policy_attachment.broker_lambda_basic,
    aws_cloudwatch_log_group.broker_lambda,
    aws_cloudwatch_log_stream.audit_ssh_cert_issued,
    aws_verifiedpermissions_identity_source.broker,
    aws_verifiedpermissions_policy.starter_allow,
  ]
}

resource "aws_apigatewayv2_api" "broker" {
  name          = "${var.name_prefix}-broker"
  protocol_type = "HTTP"
  tags          = var.tags
}

resource "aws_apigatewayv2_integration" "broker" {
  api_id                 = aws_apigatewayv2_api.broker.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.broker.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.broker.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.broker.id}"

  # When apigw_jwt_authorizer_enabled, APIGW pre-validates the bearer JWT
  # (signature, issuer, audience) on every route — INCLUDING /healthz —
  # before invoking Lambda. The broker still does its full check; this is
  # a defense-in-depth filter.
  #
  # Lambda+APIGW doesn't need an unauthenticated /healthz: APIGW is HA
  # AWS-managed (no probing needed by the operator) and Lambda's own
  # lifecycle handles function-level health. The /healthz endpoint exists
  # in the broker handler for the long-running cmd/broker deployment
  # behind an ALB; for that path, the operator's ALB target-group health
  # check configures auth-bypass on its side. Leaving /healthz under JWT
  # auth at APIGW shrinks the unauthenticated attack surface to zero
  # without losing any operational capability we actually use here.
  authorization_type = var.apigw_jwt_authorizer_enabled ? "JWT" : "NONE"
  authorizer_id      = var.apigw_jwt_authorizer_enabled ? aws_apigatewayv2_authorizer.jwt[0].id : null
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  count = var.apigw_jwt_authorizer_enabled ? 1 : 0

  api_id           = aws_apigatewayv2_api.broker.id
  name             = "${var.name_prefix}-jwt"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  # APIGW's JWT authorizer enforces signature + issuer + exp/nbf
  # unconditionally. Audience is optional — when the audience list is
  # empty, APIGW skips the aud check entirely. Operators running scope-
  # only auth (idp_required_scope set, idp_audience empty) still get
  # signature+issuer pre-filtering at APIGW; the broker enforces scope.
  jwt_configuration {
    issuer   = var.idp_issuer
    audience = var.idp_audience != "" ? [var.idp_audience] : []
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.broker.id
  name        = "$default"
  auto_deploy = true

  # Access logging activates with the JWT authorizer: without the
  # authorizer there's no pre-Lambda rejection path to log. The format
  # captures the minimum operators need for incident response — request
  # id, source IP, method, route, status, and any authorizer error.
  dynamic "access_log_settings" {
    for_each = var.apigw_jwt_authorizer_enabled ? [1] : []
    content {
      destination_arn = aws_cloudwatch_log_group.apigw_access[0].arn
      format = jsonencode({
        requestId         = "$context.requestId"
        requestTime       = "$context.requestTime"
        httpMethod        = "$context.httpMethod"
        routeKey          = "$context.routeKey"
        status            = "$context.status"
        protocol          = "$context.protocol"
        responseLength    = "$context.responseLength"
        sourceIp          = "$context.identity.sourceIp"
        userAgent         = "$context.identity.userAgent"
        authorizerError   = "$context.authorizer.error"
        authorizerLatency = "$context.authorizer.latency"
      })
    }
  }
}

resource "aws_lambda_permission" "broker_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.broker.execution_arn}/*/*"
}
