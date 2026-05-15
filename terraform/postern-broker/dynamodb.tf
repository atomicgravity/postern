# Device registry table. Schema is fixed by internal/registry/dynamodb.go:
# partition key device_id (S). Operators populate this table out of band —
# the broker only reads. Optional non-key attributes (serial, friendly_id,
# plus arbitrary tags) are stored on each item; only key attributes are
# declared at table-creation time.
resource "aws_dynamodb_table" "registry" {
  count = var.registry_backend == "dynamodb" ? 1 : 0

  name         = local.registry_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"

  attribute {
    name = "device_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = var.tags
}

# Rate-limit table. Schema is fixed by internal/ratelimit/dynamodb.go:
# composite key (engineer_sub, window). Items are short-lived and swept by
# the expires_at TTL attribute. PAY_PER_REQUEST avoids unused capacity.
resource "aws_dynamodb_table" "ratelimit" {
  name         = local.ratelimit_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "engineer_sub"
  range_key    = "window"

  attribute {
    name = "engineer_sub"
    type = "S"
  }

  attribute {
    name = "window"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = var.tags
}
