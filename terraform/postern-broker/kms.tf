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
# create a new key, update terraform.tfvars and reapply, then re-deploy
# device TrustedUserCAKeys to include the new pubkey.
#
# Skipped when var.ssh_ca_kms_key_arn supplies an operator-managed key; every
# consumer reads local.ssh_ca_kms_key_arn so both modes resolve the same way.
resource "aws_kms_key" "ssh_ca" {
  count = local.ssh_ca_key_external ? 0 : 1

  description              = "Postern SSH CA — signs SSH certificates issued by the broker."
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  tags                     = var.tags
}

resource "aws_kms_alias" "ssh_ca" {
  count = local.ssh_ca_key_external ? 0 : 1

  name          = "alias/${var.name_prefix}-ssh-ca"
  target_key_id = aws_kms_key.ssh_ca[0].id
}

# Pre-count addresses; keeps existing deployments at a zero-diff plan.
moved {
  from = aws_kms_key.ssh_ca
  to   = aws_kms_key.ssh_ca[0]
}

moved {
  from = aws_kms_alias.ssh_ca
  to   = aws_kms_alias.ssh_ca[0]
}

locals {
  ssh_ca_key_external = var.ssh_ca_kms_key_arn != null
  ssh_ca_kms_key_arn  = local.ssh_ca_key_external ? var.ssh_ca_kms_key_arn : aws_kms_key.ssh_ca[0].arn
  ssh_ca_kms_key_id   = local.ssh_ca_key_external ? element(split("/", var.ssh_ca_kms_key_arn), 1) : aws_kms_key.ssh_ca[0].id
}
