// Starter Postern Cedar policy: any authenticated user can mint an operator
// certificate, mint a timefix certificate, or open an AWS IoT secure tunnel
// to any registered device. AVP authenticates the principal via the
// configured identity source; this policy adds no further constraint. The
// three actions are listed together because most deployments grant all of
// them to engineers by default; deployments that haven't enabled the
// recovery flow will simply never call MintTimefixCert, and deployments
// that haven't enabled tunneling (Terraform `tunneling_enabled = false`)
// will simply never call OpenTunnel.
//
// **OpenTunnel is the meaningful escalation** to gate separately: plain
// `postern ssh` requires LAN access to reach the device, while
// `postern ssh --tunnel` / `postern scp --tunnel` / `postern tunnel` open
// an AWS IoT secure tunnel that reaches the device from anywhere. Operators
// who want to limit remote access to a subset of engineers split the
// permit below into a broad MintOperatorCert/MintTimefixCert grant + a
// narrower OpenTunnel grant.
//
// Operators tighten as their access model matures. Common next steps:
//   - Restrict by Cognito group:
//       permit (
//         principal in Postern::Group::"engineers",
//         action in [Postern::Action::"MintOperatorCert", Postern::Action::"MintTimefixCert"],
//         resource
//       );
//       permit (
//         principal in Postern::Group::"remote-access",
//         action == Postern::Action::"OpenTunnel",
//         resource
//       );
//   - Restrict by device tag:
//       permit (
//         principal,
//         action == Postern::Action::"MintOperatorCert",
//         resource
//       ) when {
//         resource.fleet == "production"
//       };
//   - Cap tunnel TTL per fleet via the context attribute the broker
//     emits on every OpenTunnel request:
//       permit (
//         principal,
//         action == Postern::Action::"OpenTunnel",
//         resource
//       ) when {
//         context.requested_max_lifetime_minutes <= 30
//       };
//   - Time-of-day windows, source-IP allowlists, etc., via the context attrs
//     source_ip, user_agent, request_id, timestamp.
permit (
  principal,
  action in [
    Postern::Action::"MintOperatorCert",
    Postern::Action::"MintTimefixCert",
    Postern::Action::"OpenTunnel"
  ],
  resource
);
