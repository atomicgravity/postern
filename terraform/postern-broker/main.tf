data "aws_caller_identity" "current" {}

# aws_region.current is consulted by the tunneling block when
# tunneling_iot_region is left at its default empty value. Pulled
# unconditionally because data sources have no per-deployment cost and
# the alternative (count = var.tunneling_enabled ? 1 : 0) loses single-
# index access (`data.aws_region.current[0].region`) for no real benefit.
data "aws_region" "current" {}

locals {
  # module_version is the Postern release this module was tagged with.
  # release-please updates the version string on this line on every
  # release (see `extra-files` in release-please-config.json). Exposed
  # via the module_version output so consumers can drift-check their
  # `?ref=` against what the module actually is — when those drift,
  # the consumer's precondition catches the mismatch at plan time.
  module_version = "1.0.0" # x-release-please-version

  registry_table_name  = "${var.name_prefix}-registry"
  ratelimit_table_name = "${var.name_prefix}-ratelimit"
  audit_log_group_name = "/${var.name_prefix}/audit"

  # Audit stream name is fixed by internal/audit/cloudwatch.go; the stream
  # must exist before broker traffic flows. Don't change without a code update.
  audit_log_stream_name = "ssh-cert-issued"

  # API Gateway access log group (created only when the JWT authorizer is
  # enabled). Operationally separate from the audit log group: different
  # retention, different shape (APIGW access events vs broker AuditEvents),
  # different consumers.
  apigw_access_log_group_name = "/${var.name_prefix}/apigw-access"

  # broker_lambda_zip_path: caller-supplied wins; otherwise default to the
  # in-tree build output at <repo-root>/bin/broker-lambda.zip.
  broker_lambda_zip_path = var.broker_lambda_zip_path != "" ? var.broker_lambda_zip_path : "${path.module}/../../bin/broker-lambda.zip"

  # build_required toggles the in-tree `make broker-lambda.zip` provisioner.
  # When the caller supplied a pre-built zip path, skip the build (and the
  # implicit make / go / zip toolchain requirement on the apply machine).
  build_required = var.broker_lambda_zip_path == ""

  # Custom-domain toggle. When custom_domain_enabled is true, the route53.tf
  # resources stand up and broker_url resolves to https://<broker_domain_name>.
  custom_domain_enabled = var.broker_domain_name != ""

  # Source-tree fingerprint that gates the broker-lambda.zip rebuild. Covers
  # every Go file the Lambda binary links in, plus go.mod / go.sum / Makefile.
  # Test files are excluded so test-only edits do not trigger rebuilds.
  # Only consulted when build_required = true; the fileglob still resolves
  # against the module's fetched repo when caller supplies a zip path, but
  # the result is unused.
  broker_lambda_source_files = local.build_required ? sort([
    for file in setunion(
      fileset("${path.module}/../..", "cmd/broker-lambda/**/*.go"),
      fileset("${path.module}/../..", "internal/**/*.go"),
      fileset("${path.module}/../..", "pkg/**/*.go"),
    ) : file if !endswith(file, "_test.go")
  ]) : []

  broker_lambda_source_hash = local.build_required ? sha1(join("", concat(
    [for file in local.broker_lambda_source_files : filesha1("${path.module}/../../${file}")],
    [
      filesha1("${path.module}/../../go.mod"),
      filesha1("${path.module}/../../go.sum"),
      filesha1("${path.module}/../../Makefile"),
    ],
  ))) : ""
}
