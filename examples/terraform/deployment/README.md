# Postern broker — deployment example

A directly-deployable example consumer of the `postern-broker` Terraform module. This is the end-to-end "stand up the broker on AWS" entry point; copy it into your own infra repo and switch the module source to a pinned git ref to make it your production deployment.

## Usage from this repo

```sh
cd examples/terraform/deployment
cp terraform.tfvars.example terraform.tfvars   # edit the operator-specific values
terraform init
terraform apply
```

The module's `source` is a relative path (`../../../terraform/postern-broker`) so a fresh checkout works without a git ref. The Lambda zip builds in-tree at apply time via `make broker-lambda.zip`, which requires `make`, `go`, and `zip` on the apply machine.

## Usage from your own infra repo

Copy this directory to your own infra repo, then change the module source in `main.tf` from the relative path to a git ref pinned to a Postern release tag:

```hcl
module "broker" {
  source = "github.com/atomicgravity/postern//terraform/postern-broker?ref=v1.0.0"
  # ...
}
```

Pinning to a tag (or a commit SHA) makes module upgrades explicit. The module's variables, outputs, and resource shapes are the same in either form.

When applying from a CI runner that doesn't have `make` / `go` / `zip` installed, fetch the pre-built artifact from a Postern release and pass its path via `broker_lambda_zip_path`. The module skips the in-tree build when that path is supplied.

```sh
VERSION=v0.1.0
curl -sLo /tmp/broker-lambda.zip \
  "https://github.com/atomicgravity/postern/releases/download/${VERSION}/broker-lambda_${VERSION#v}_linux_arm64.zip"
# Then in terraform.tfvars:
#   broker_lambda_zip_path = "/tmp/broker-lambda.zip"
```

Pin to a release tag; don't track "latest" — module upgrades should be explicit.

## What this creates

See the [module README](../../../terraform/postern-broker/README.md) for the full list. Headline resources:

- KMS Ed25519 signing key (the SSH CA)
- Two DynamoDB tables: device registry and per-engineer rate-limit
- AVP policy store with the Cedar schema, a permissive starter policy, and an identity source (Cognito or OIDC)
- CloudWatch audit log group + the fixed `ssh-cert-issued` stream
- Lambda function (provided.al2023, arm64) + API Gateway HTTP API
- IAM role scoped to exactly the resources above
- (Optional) ACM certificate + custom domain + Route 53 alias

## Outputs

After `terraform apply`, the engineer-facing handoff is `terraform output broker_url`. Paste that into `~/.postern/config.yaml` as the `broker` field, alongside the IdP-issued audience / scope / issuer values.
