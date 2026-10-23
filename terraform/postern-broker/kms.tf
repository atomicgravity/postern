# SSH CA signing key.
#
# Load-bearing: customer_master_key_spec MUST be ECC_NIST_EDWARDS25519. The
# broker hardcodes SigningAlgorithmSpec=ED25519_SHA_512, the on-device
# timefix verifier pins alg=EdDSA, and SSH certs the broker issues are
# Ed25519. Any other KMS key spec (RSA_*, ECC_NIST_P*, ECC_SECG_*) signs a
# different algorithm and the broker fails closed at first kms:Sign.
#
# Asymmetric keys do not support automatic rotation. The broker fetches the
# public key once at startup, so rotation is an operator-driven event:
# create a new key, add its pubkey to device TrustedUserCAKeys (and the
# timefix-apply pinned CA pubkey) alongside the current one, then point
# var.ssh_ca_kms_key_arn at it and reapply. That apply moves the broker to
# the new key, so devices must trust it first.
#
# prevent_destroy: devices trust this key's pubkey, and a destroyed key can't
# be recreated with the same one. Any plan that drops it fails instead —
# switching to var.ssh_ca_kms_key_arn without create_ssh_ca_key = true, or
# terraform destroy. Retiring it is a deliberate out-of-band step (state rm,
# then schedule-key-deletion); see the README.
resource "aws_kms_key" "ssh_ca" {
  count = local.create_ssh_ca_key ? 1 : 0

  description              = "Postern SSH CA — signs SSH certificates issued by the broker."
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  tags                     = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

# Only while this key is the signer: a retained rollback key under the
# canonical alias would hand out the wrong CA pubkey.
resource "aws_kms_alias" "ssh_ca" {
  count = local.create_ssh_ca_key && !local.ssh_ca_key_external ? 1 : 0

  name          = "alias/${var.name_prefix}-ssh-ca"
  target_key_id = aws_kms_key.ssh_ca[0].id
}

locals {
  ssh_ca_key_external = var.ssh_ca_kms_key_arn != ""
  create_ssh_ca_key   = var.create_ssh_ca_key != null ? var.create_ssh_ca_key : !local.ssh_ca_key_external
  ssh_ca_kms_key_arn  = local.ssh_ca_key_external ? var.ssh_ca_kms_key_arn : aws_kms_key.ssh_ca[0].arn
  ssh_ca_kms_key_id   = local.ssh_ca_key_external ? element(split("/", var.ssh_ca_kms_key_arn), 1) : aws_kms_key.ssh_ca[0].id
}
