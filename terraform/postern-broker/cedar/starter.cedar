// Starter Postern Cedar policy. It demonstrates principal-class gating on top
// of Cedar's implicit default-deny: human users may perform any device action
// from any source IP, while automated (machine) callers are denied unless a
// permit names them explicitly. AVP authenticates the principal via the
// configured identity source; the broker stamps the principal class and (for
// automated callers) the issuing client_id into the request context.
//
// The class strings below ("user", "machine") must match the class names the
// operator configures in the broker's idp.principal_classes block. That
// coupling is the operator-facing contract; it lives in the broker config + the
// policy store, never in code. With no principal_classes block configured every
// caller is "user", so policy (1) alone reproduces the prior permissive
// default.
//
// **OpenTunnel is the meaningful escalation** to gate separately: plain
// `postern ssh` requires LAN access to reach the device, while
// `postern ssh --tunnel` / `postern scp --tunnel` / `postern tunnel` open
// an AWS IoT secure tunnel that reaches the device from anywhere. Operators
// who want to limit remote access to a subset of engineers split the human
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
//   - Cap operator cert TTL via the context attribute the broker emits on
//     every MintOperatorCert request (the resolved, ceiling-clamped minutes):
//       permit (
//         principal,
//         action == Postern::Action::"MintOperatorCert",
//         resource
//       ) when {
//         context.requested_cert_ttl_minutes <= 60
//       };
//   - Time-of-day windows, source-IP allowlists, etc., via the context attrs
//     source_ip, user_agent, request_id, timestamp, principal_class, client_id.

// (1) Human users: any source IP, all device actions.
permit (
  principal,
  action in [
    Postern::Action::"MintOperatorCert",
    Postern::Action::"MintTimefixCert",
    Postern::Action::"OpenTunnel"
  ],
  resource
) when {
  context.principal_class == "user"
};

// (2) One specific service account: operator certs only, and only from its
// pinned source IP. Exact string match is sufficient for a single IP. Replace
// the client_id and source_ip with the operator's own values, or remove this
// policy if no automated callers should mint certificates.
permit (
  principal,
  action == Postern::Action::"MintOperatorCert",
  resource
) when {
  context.principal_class == "machine" &&
  context has client_id &&
  context.client_id == "EXAMPLEm2mclientid" &&
  context.source_ip == "203.0.113.7"
};

// No permit covers any other machine caller, nor this client from any other
// IP — those requests fall through to the implicit default-deny.
