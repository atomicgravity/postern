# Cognito IdP Example

This example creates a Cognito user pool that can issue access tokens for Postern. It is sample infrastructure for operators to adapt, not part of Postern's core deployment surface.

It creates:

- A Cognito user pool and managed-login domain.
- A public app client for Authorization Code + PKCE.
- Loopback callback URLs for Postern's fixed callback ports.
- A Cognito resource server with a custom broker resource/audience for RFC 8707 resource binding.

## Use

Copy this directory into your own infrastructure repo, review every variable, and adapt it to your IdP and policy model.

```sh
terraform init
terraform apply \
  -var='aws_region=us-west-2' \
  -var='managed_login_domain_prefix=postern-example-your-org' \
  -var='broker_url=https://postern.example.com'
```

`broker_resource` defaults to `broker_url`. Set it explicitly if the broker's token audience should differ from the operator-facing broker URL, for example `-var='broker_resource=api://postern-broker'`.

After apply, configure the broker Policy to require the appropriate access-token claims for certificate issuance. If your policy uses Cognito groups, create those groups in the user pool and assign users to them.

Publish the `engineer_config_yaml` output to engineers. It has the shape they paste into `~/.postern/config.yaml`:

```yaml
default:
  broker: https://postern.example.com
  idp:
    issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example
    client_id: exampleclientid
    audience: https://postern.example.com
    audience_param: resource
```

## Token Notes

Postern sends the Cognito **access token** to the broker as `Authorization: Bearer`. The broker validates that the access token was issued for the broker audience.

The Terraform sample creates a Cognito resource server whose identifier is `broker_resource`. Postern sends that value as the OAuth `resource` parameter during login, so Cognito places it in the access token `aud` claim. The sample does not define or request a custom broker scope; the audience binding identifies the API, and broker Policy authorizes the request.

The ID token is for local CLI display only. Do not use ID tokens at the broker.

Cognito access tokens include the native `cognito:groups` claim when the user belongs to Cognito groups. Map that claim to the broker Policy principal in your Policy implementation or AVP identity source. Group enforcement belongs in broker Policy, not in Cognito triggers.

## Callback URLs

Postern uses fixed loopback callback URLs. This example registers all default callback ports:

```text
http://127.0.0.1:50001/cb
...
http://127.0.0.1:50010/cb
```

If a wrapper changes Postern's callback port set in code, update `loopback_ports` here to match.

## Security Notes

- `refresh_token_validity_days` defaults to 1 day.
- Access and ID tokens default to 60 minutes.
- The app client is public, so it intentionally has no client secret.
- `allowed_oauth_flows_user_pool_client = true` enables Cognito OAuth flows for the app client; it is not client authentication.
- `explicit_auth_flows = []` leaves Cognito SDK authentication flows disabled for this app client. Postern uses managed-login OAuth, not `InitiateAuth` or custom auth challenges.
- Self sign-up and self-service account recovery are disabled; operators create and recover users through admin workflows or their upstream IdP process.
- The domain uses Cognito managed login, not classic hosted UI, because Cognito resource binding requires managed login. The sample applies Cognito-provided managed-login branding defaults so fresh browser sessions can render the login page.
- Postern always uses Authorization Code + S256 PKCE. Cognito verifies `code_verifier` for requests that include a `code_challenge`; Cognito does not expose a separate Terraform setting to require PKCE on the app client.
- Users outside the configured Postern groups may still authenticate to Cognito and receive access tokens. The broker must deny certificate issuance unless Policy authorizes the request.

## Cedar policy gotcha: Cognito entity ID namespacing

When the broker module's `avp_cognito_group_entity_type` is set (so `cognito:groups` claims map into Cedar `Group` entities), AVP namespaces both the User principal and the Group parents with the Cognito user-pool ID. Entity IDs take the form `<pool_id>|<value>` — e.g. `Postern::Group::"us-west-2_ABC123|engineers"`, not `Postern::Group::"engineers"`. Policies that reference the bare group name compile fine and silently DENY at evaluation time with no error message — AVP simply doesn't find a matching `permit`.

Always interpolate the pool ID into Cedar entity IDs when authoring policies against Cognito groups. The fuller treatment — including a copy-pasteable `aws_verifiedpermissions_policy` example that derives the pool ID from the user-pool ARN — is in [`terraform/postern-broker/README.md`](../../../terraform/postern-broker/README.md) §"Authorization (Cedar)".