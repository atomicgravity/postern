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
resource "aws_kms_key" "ssh_ca" {
  description              = "Postern SSH CA — signs SSH certificates issued by the broker."
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  tags                     = var.tags
}

resource "aws_kms_alias" "ssh_ca" {
  name          = "alias/${var.name_prefix}-ssh-ca"
  target_key_id = aws_kms_key.ssh_ca.id
}
