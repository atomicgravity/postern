# Optional custom-domain wiring. All resources here are gated on
# local.custom_domain_enabled (= var.broker_domain_name != ""). When the
# operator leaves the domain vars empty, this file produces zero resources
# and the broker is reachable at the API Gateway invoke URL.
#
# The audience the broker validates and the URL engineers paste both want
# to be the same string. With the custom domain set, that's
# https://<broker_domain_name> — picked once, no bootstrap two-step.

data "aws_route53_zone" "broker" {
  count        = local.custom_domain_enabled ? 1 : 0
  name         = var.route53_zone_name
  private_zone = false
}

resource "aws_acm_certificate" "broker" {
  count             = local.custom_domain_enabled ? 1 : 0
  domain_name       = var.broker_domain_name
  validation_method = "DNS"
  tags              = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "broker_acm_validation" {
  for_each = local.custom_domain_enabled ? {
    for option in aws_acm_certificate.broker[0].domain_validation_options : option.domain_name => {
      name  = option.resource_record_name
      type  = option.resource_record_type
      value = option.resource_record_value
    }
  } : {}

  zone_id         = data.aws_route53_zone.broker[0].zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.value]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "broker" {
  count                   = local.custom_domain_enabled ? 1 : 0
  certificate_arn         = aws_acm_certificate.broker[0].arn
  validation_record_fqdns = [for record in aws_route53_record.broker_acm_validation : record.fqdn]
}

resource "aws_apigatewayv2_domain_name" "broker" {
  count       = local.custom_domain_enabled ? 1 : 0
  domain_name = var.broker_domain_name
  tags        = var.tags

  domain_name_configuration {
    certificate_arn = aws_acm_certificate.broker[0].arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  depends_on = [aws_acm_certificate_validation.broker]
}

resource "aws_apigatewayv2_api_mapping" "broker" {
  count       = local.custom_domain_enabled ? 1 : 0
  api_id      = aws_apigatewayv2_api.broker.id
  domain_name = aws_apigatewayv2_domain_name.broker[0].id
  stage       = aws_apigatewayv2_stage.default.id
}

resource "aws_route53_record" "broker_alias" {
  count   = local.custom_domain_enabled ? 1 : 0
  zone_id = data.aws_route53_zone.broker[0].zone_id
  name    = var.broker_domain_name
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.broker[0].domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.broker[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
