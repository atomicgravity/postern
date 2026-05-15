# Audit log group + the fixed "ssh-cert-issued" stream the broker writes to.
# internal/audit/cloudwatch.go does NOT auto-create the stream — both the
# group and stream must exist before broker traffic flows.
resource "aws_cloudwatch_log_group" "audit" {
  name              = local.audit_log_group_name
  retention_in_days = var.audit_log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_stream" "audit_ssh_cert_issued" {
  name           = local.audit_log_stream_name
  log_group_name = aws_cloudwatch_log_group.audit.name
}

# API Gateway HTTP API access logs. Created when apigw_access_logs_enabled
# is true (default). The group is parallel to the audit group — operators
# query both during incident response: the audit group records "what the
# broker did" (including ssh_cert_denied for everything the broker saw);
# this group records every request APIGW accepted or rejected, including
# the pre-Lambda rejections from the JWT authorizer when it's on.
resource "aws_cloudwatch_log_group" "apigw_access" {
  count = var.apigw_access_logs_enabled ? 1 : 0

  name              = local.apigw_access_log_group_name
  retention_in_days = var.apigw_access_log_retention_days
  tags              = var.tags
}

# Resource policy granting API Gateway permission to write access log
# events into the log group. For HTTP API v2 there's no service-linked
# role to lean on; the explicit policy is the portable path and works on
# first-time-in-account deployments without an additional CLI step.
#
# Uses `resource_arn` (not `policy_name`) so the policy is attached to
# the log group itself rather than at the account level. Resource-scoped
# policies don't count against the 10-policy-per-region account limit,
# so each postern deployment gets its own policy without crowding the
# account's slot budget.
#
# Trust scoping:
#   - aws:SourceAccount confines the trust to this account.
#   - aws:SourceArn pins to this broker's specific API Gateway, so a
#     different APIGW in the same account can't be coerced into writing
#     into our log group via the shared apigateway.amazonaws.com
#     service principal.
resource "aws_cloudwatch_log_resource_policy" "apigw_access" {
  count = var.apigw_access_logs_enabled ? 1 : 0

  resource_arn = aws_cloudwatch_log_group.apigw_access[0].arn
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "APIGatewayAccessLogs"
      Effect = "Allow"
      Principal = {
        Service = "apigateway.amazonaws.com"
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.apigw_access[0].arn}:*"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          "aws:SourceArn"     = "${aws_apigatewayv2_api.broker.execution_arn}/*"
        }
      }
    }]
  })
}
