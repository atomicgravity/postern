# Broker Lambda execution role. Permissions are scoped to the resources this
# stack creates: the SSH CA key, the two DynamoDB tables, the AVP policy
# store, and the audit log group's ssh-cert-issued stream.
data "aws_iam_policy_document" "broker_lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "broker_lambda" {
  name               = "${var.name_prefix}-broker-lambda"
  assume_role_policy = data.aws_iam_policy_document.broker_lambda_assume.json
  tags               = var.tags
}

# AWSLambdaBasicExecutionRole grants logs:CreateLogStream + logs:PutLogEvents
# scoped to the function's own log group, so per-invocation Lambda logs land
# without us reinventing the policy.
resource "aws_iam_role_policy_attachment" "broker_lambda_basic" {
  role       = aws_iam_role.broker_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "broker_lambda_inline" {
  # KMS Sign + GetPublicKey on the SSH CA only.
  statement {
    sid     = "SshCaSign"
    actions = ["kms:Sign", "kms:GetPublicKey"]
    resources = [
      aws_kms_key.ssh_ca.arn,
    ]
  }

  # DynamoDB GetItem on registry; UpdateItem on rate-limit. The rate limiter
  # uses a conditional UpdateItem (no GetItem); the registry only reads. The
  # registry-read statement is conditional on the DynamoDB backend; HTTP
  # registries reach their service over the network and the broker's IAM
  # role doesn't grant any registry table access in that case.
  dynamic "statement" {
    for_each = var.registry_backend == "dynamodb" ? [1] : []
    content {
      sid       = "RegistryRead"
      actions   = ["dynamodb:GetItem"]
      resources = [aws_dynamodb_table.registry[0].arn]
    }
  }

  statement {
    sid       = "RateLimitWrite"
    actions   = ["dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.ratelimit.arn]
  }

  # AVP IsAuthorizedWithToken on the broker policy store only.
  statement {
    sid       = "PolicyAuthorize"
    actions   = ["verifiedpermissions:IsAuthorizedWithToken"]
    resources = [aws_verifiedpermissions_policy_store.broker.arn]
  }

  # CloudWatch Logs PutLogEvents for the audit stream. Scope to the audit
  # log group's stream ARN; the stream name is fixed by the broker.
  statement {
    sid     = "AuditWrite"
    actions = ["logs:PutLogEvents"]
    resources = [
      "${aws_cloudwatch_log_group.audit.arn}:log-stream:${local.audit_log_stream_name}",
    ]
  }

  # iot:OpenTunnel for the firewalled-device path. Gated by
  # tunneling_enabled so operators that don't need the firewalled-device
  # path don't carry the IAM permission.
  dynamic "statement" {
    for_each = var.tunneling_enabled ? [1] : []
    content {
      sid       = "TunnelingOpen"
      actions   = ["iot:OpenTunnel"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "broker_lambda_inline" {
  name   = "${var.name_prefix}-broker-lambda-inline"
  role   = aws_iam_role.broker_lambda.id
  policy = data.aws_iam_policy_document.broker_lambda_inline.json
}
