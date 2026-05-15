# Security audit — pass #2 (post-sweep)

## Summary

Postern's security posture continues to be strong. The just-landed sweep (commit `8eb0efd`) closed the two MEDIUMs it explicitly targeted (F-SEC-M1 on the broker side; F-SEC-M2 by rewording LD-65); F-SEC-M3 and F-SEC-M4 were **not** addressed and remain open as carried forward in this pass. One **new HIGH** finding emerged: the CLI's ID-token verifier in `internal/oauthlogin/login.go` does not pin `SupportedSigningAlgs`, which is the exact gap the M1 broker-side fix closed — the original M1 finding explicitly named both verifier call sites, but only one was patched. The CLI ID-token branch is on the `postern login` hot path, so an IdP serving an HS256 advertisement could coerce the CLI into trusting an attacker-forged ID token for display + keychain metadata (broker still rejects the same token, so cert-mint is bounded — hence HIGH, not CRITICAL).

The rest of the codebase is in good shape: AVP fail-closed semantics hold, the new go-jose `accessTokenExpiry` parse uses `UnsafeClaimsWithoutVerification` correctly (CLI-side expiry pre-check only), `broker.TruncateRunes` is the shared rune-cap helper, `uuid.NewV7` replaces the prior hand-rolled UUIDv7, `internal/atomicfile` is the shared atomic-write seam, and the two `signer_failure` audit paths now align with the LD-65 restatement.

Severity counts (this pass): **HIGH 1, MEDIUM 3, LOW 6, INFO 3** (total 13 findings — 12-finding budget honored).

Delta vs pass #1: F-SEC-M1 split into CLOSED (broker) + new HIGH (CLI side, regression-by-omission); F-SEC-M2 CLOSED; F-SEC-M3 **OPEN**; F-SEC-M4 **OPEN**. Several pass-1 LOW/INFO items remain unchanged (F-SEC-L1 tempfile, F-SEC-L2 openBrowser, F-SEC-L5 iatMaxAge, F-SEC-L6 refresh-no-verify, F-SEC-L7 unbounded ReadString, F-SEC-I4 JWKs trust store, F-SEC-I5 YAML KnownFields) — not re-numbered, only the open ones are referenced.

## Prior-pass closure status

| Prior ID | Status | Evidence |
|---|---|---|
| F-SEC-M1 (OIDC SupportedSigningAlgs) | **PARTIAL** | `internal/idp/oidc.go:91-94` now sets `SupportedSigningAlgs: []string{"RS256",...,"EdDSA"}` (broker side fixed). `internal/oauthlogin/login.go:190` still constructs `provider.Verifier(&oidc.Config{ClientID: options.ClientID})` with no alg pin — see F-SEC2-H1. |
| F-SEC-M2 (LD-65 wording) | **CLOSED** | `docs/architect-log.md:21` LD-65 now reads "one audit outcome" (was "one audit row") and adds an explicit signer-failure clause: "the signer-failure path emits `*_authorized` + `*_denied/signer_failure` joined on `jti`". The two `signer_failure` emit sites (`internal/broker/sshcert.go:269-273`, `internal/broker/issuetimepayload.go:222-241`) match the restated invariant. |
| F-SEC-M3 (`--ip` flag validation) | **OPEN** | `pkg/cliapp/timefix.go:194-195` still uses only `strings.TrimSpace(ip)`; no whitespace/newline rejection on the value that flows into `"-o HostName="+ip`. Same shape unchanged. |
| F-SEC-M4 (sshconf newline-validate User/HostName/Patterns) | **OPEN** | `internal/sshconf/writer.go:347-355` `validateDevice` still rejects `\n\r` on Device only; the renderStanza path at `:178-205` interpolates `Stanza.HostName`, `Stanza.User`, and each `Stanza.Patterns` element via `fmt.Fprintf` with no validation. |

## High-severity findings

### F-SEC2-H1: CLI ID-token verifier does not pin `SupportedSigningAlgs` (regression-by-omission from F-SEC-M1 sweep)
**Location**: `/Users/ttarhan/Code/postern/internal/oauthlogin/login.go:190`
**Threat**: The broker-side fix to F-SEC-M1 (commit `8eb0efd`) pinned `SupportedSigningAlgs` to the asymmetric-alg set in `internal/idp/oidc.go`, closing alg-confusion at the broker. The CLI's ID-token verifier in `Login()` constructs an independent `provider.Verifier(&oidc.Config{ClientID: options.ClientID})` without the same pin, so go-oidc falls back to whatever algs the IdP's discovery document advertises (intersected with go-oidc's internal allowlist, which does NOT block HS256). The original F-SEC-M1 finding explicitly named **both** locations as needing the pin; the sweep missed the second. Impact: an IdP compromise (or operator misconfiguration) that begins advertising HS256 in `id_token_signing_alg_values_supported` lets any party with JWKs read access forge ID tokens that the CLI accepts as valid. The CLI uses the verified ID token's claims for the "Logged in as ..." display line and persists `sub`/`email`/`iat` into the keychain `tokenstore.State`. Subsequent broker calls re-verify the access token at the broker (which IS now pinned), so cert-mint is still safe — but the engineer sees a forged identity at the CLI, the keychain stores attacker-chosen subject/email metadata, and the local audit-of-self trail (which subject the engineer "logged in as") is now untrustworthy. Severity: HIGH because (a) the fix is one line, (b) the pass-1 finding explicitly called the location out, (c) the gap silently survived the sweep, and (d) the symptom is identity confusion at the trust boundary closest to the engineer. Not CRITICAL because the broker re-verification still keeps cert-mint locked down.
**Recommendation**: Apply the same pin: `provider.Verifier(&oidc.Config{ClientID: options.ClientID, SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}})`. Consider extracting the alg list into an exported constant in `internal/idp` so a future third call site can't drift again.

## Medium-severity findings

### F-SEC2-M1: `runTimefix` CLI `--ip` flag still has no whitespace/newline validation (F-SEC-M3 still open)
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/timefix.go:194-195`
**Threat**: Same shape as pass-1 F-SEC-M3. `buildTimefixSSHArgv` appends `"-o", "HostName="+ip` after only `strings.TrimSpace(ip)`. An engineer pasting `--ip "10.0.0.1\nProxyCommand=/bin/sh -c 'rm -rf ~'"` from a malicious onboarding doc or chat message gets the second line interpreted as an additional ssh option — local code execution under the engineer's UID. Pass-1 recommendation (a `^[A-Za-z0-9._:\[\]-]+$` regex) was not applied in the sweep; D13's lock note in `docs/phases/timefix/spec.md` line 47 says "Flag value validation is delegated to ssh (anything OpenSSH accepts as `HostName` value works); the CLI does no IP-vs-hostname parsing of its own" — but OpenSSH's `HostName` value parsing is line-oriented, so a newline IS smuggled-option terrain. The design decision is at odds with the threat model here.
**Recommendation**: Reject newlines, control characters, and embedded spaces on `--ip` value (one line of validation). The architectural lock in D13 covers the *positive* case (any IP/hostname OpenSSH accepts is fine); rejecting newline/control characters is below that bar and doesn't conflict with D13's intent. If the team prefers to keep the literal D13 wording, document the residual self-foot-gun risk in the CLI help text for `--ip`.

### F-SEC2-M2: `internal/sshconf` writer still trusts `Stanza.HostName`, `Stanza.User`, `Stanza.Patterns` without newline rejection (F-SEC-M4 still open)
**Location**: `/Users/ttarhan/Code/postern/internal/sshconf/writer.go:178-205, 347-355`
**Threat**: Same shape as pass-1 F-SEC-M4. `validateDevice` rejects newlines on `Device` only; `renderStanza`'s `fmt.Fprintf` interpolates HostName/User/each Patterns element verbatim. A newline in any of these injects arbitrary ssh-config directives (`ProxyCommand`, `LocalCommand`, `IdentityFile`, etc.) that every subsequent `ssh` invocation on the same Host stanza obeys. Today's only caller (`pkg/cliapp/addhost.go`) sources these from engineer-typed `--user`/`--ip` flags, so the threat is self-foot-gun — but the `sshconf` package contract should treat every rendered string as untrusted, especially since `pkg/cliapp` is part of the wrapping surface and a wrapper-side caller may not apply the same trim/validate discipline.
**Recommendation**: Extend `validateDevice`'s `strings.ContainsAny(s, "\n\r")` check to a generalized `validateStanzaField(name, value)` helper that runs over each of `Stanza.HostName`, `Stanza.User`, every `Stanza.Patterns` entry. Reject newlines, carriage returns, and the NUL byte. Reject empty patterns after trim (already done; keep). The `Device` validation can call into the same helper for symmetry.

### F-SEC2-M3: `internal/oauthlogin.AccessToken` refresh path writes new access tokens to keychain without re-verifying signature (pass-1 F-SEC-L6, severity-bumped here because of the new H1 context)
**Location**: `/Users/ttarhan/Code/postern/internal/oauthlogin/token.go:100-117`
**Threat**: The refresh flow calls `cfg.TokenSource(...).Token()`, then only checks that `exp` is parseable via the unsafe `UnsafeClaimsWithoutVerification` in `accessTokenExpiry` (which is correct for the expiry pre-check) — but it does NOT verify the refreshed access token's signature against the IdP's JWKs before persisting it. The broker re-verifies on every request (with the asymmetric-alg pin per the M1 broker-side fix), so cert-mint stays safe. But in combination with F-SEC2-H1 (where the CLI accepts unpinned ID-token algs at login), an in-path TLS-MITM with a tampered trust store gets two unverified-token write paths into the engineer's keychain. Was LOW in pass 1 (broker-as-authority argument); bumped to MEDIUM here because the CLI no longer has a clean "broker is the only verifier" story while H1 is open. Once H1 lands, this drops back to LOW.
**Recommendation**: Either (a) verify the refreshed access token via `provider.Verifier(...).Verify(ctx, accessToken)` (with the same asymmetric-alg pin from F-SEC2-H1) before persisting; or (b) accept that CLI-side access tokens are broker-verified-only and document that the trust boundary is the broker. Option (a) is one extra round-trip but turns the keychain entry into a verified artifact at write time.

## Low-severity findings

### F-SEC2-L1: F-SEC-L1 (tempfile in OS tempdir) carried forward unchanged
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/timefix.go:206-230`
**Threat**: As pass 1. `os.CreateTemp("", "postern-timefix-*.cert")` writes the timefix cert to the OS tempdir with mode 0600 applied AFTER `WriteString`. On multi-user Linux servers with a shared `/tmp`, a co-resident attacker can race the chmod window. The cert is short-lived and device-bound, so abuse is bounded.
**Recommendation**: Either write under the per-profile cache dir (where `internal/certcache` enforces 0700 on the parent), or `tempFile.Chmod(0o600)` BEFORE `tempFile.WriteString`. The latter is one swapped-line fix.

### F-SEC2-L2: F-SEC-L2 (`openBrowser` exec'ing user-influenced URL) unchanged
**Location**: `/Users/ttarhan/Code/postern/internal/oauthlogin/login.go:425-440`
**Threat**: As pass 1. The `authorizeURL` is built from operator YAML (`issuer`, `audience`, `scopes`) via `oauth2.Config.AuthCodeURL` and passed to `open`/`xdg-open`/`rundll32`. argv-form `exec.CommandContext` rules out shell injection; the residual surface is whatever the platform's URL handler honors. Config validator rejects non-https/loopback issuers; URL is `oauth2`-builder-produced, not free-form.
**Recommendation**: Validate the assembled `authorizeURL` parses as `https://` or `http://localhost:*` before exec. Defensive belt-and-suspenders.

### F-SEC2-L3: F-SEC-L5 (`iatMaxAge = 24 * time.Hour` ceiling) unchanged
**Location**: `/Users/ttarhan/Code/postern/internal/idp/oidc.go:35`
**Threat**: As pass 1. A 24-hour ceiling on access-token age combined with operator-cert TTL (typically minutes-to-an-hour) means a stolen access token has up to 24h of mint-replay window even if the IdP issues longer-lived tokens.
**Recommendation**: Consider aligning `iatMaxAge` with `cert_ttl.operator` from broker config, or hardcode to 1 hour. Out of audit scope; flag for architecture discussion.

### F-SEC2-L4: F-SEC-L7 (`defaultExecSSHTimefix` `ReadString('\n')` with no length cap) unchanged
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/runtime.go:195-216`
**Threat**: As pass 1. `bufio.NewReader.ReadString('\n')` on stdout from the device's ssh channel has no length bound. A compromised-device principal could emit gigabytes before newline. Requires already-compromised device authentication (force-command + timefix cert pinning), so a separate seam from the CLI's threat model — but the package-level should still cap.
**Recommendation**: Wrap with `io.LimitReader(stdoutPipe, 4096)` before constructing the `bufio.Reader`. Nonce + device-clock line together are ~80 bytes; 4KB is generous.

### F-SEC2-L5: `Stanza.Port` value not range-checked (new)
**Location**: `/Users/ttarhan/Code/postern/internal/sshconf/writer.go:194-196`, `/Users/ttarhan/Code/postern/pkg/cliapp/addhost.go:46-47`
**Threat**: `runAddHost` accepts `--port int` from `cobra.Flags().IntVar` (so the value is at least typed) and writes it via `fmt.Fprintf(&builder, "%sPort %d\n", stanzaIndent, s.Port)`. The writer's only gate is `s.Port > 0`. Negative ports are silently dropped (good); ports above 65535 are written verbatim (bad — ssh rejects, but the stanza is malformed for other tools that read it). This is a quality-of-implementation issue, not a security one.
**Recommendation**: Range-check 1..65535 in `Stanza` validation or at `addHostOptions.Port` ingest.

### F-SEC2-L6: CloudWatch audit `Record` has no per-event size cap (new)
**Location**: `/Users/ttarhan/Code/postern/internal/audit/cloudwatch.go:71-95`
**Threat**: `json.Marshal(event)` produces a `Message` that may exceed CloudWatch's 256KB per-event limit if a misconfigured IdP issues pathologically long claims. The broker-side `TruncateRunes` caps (`maxSubjectRunes=256`, `maxEmailRunes=320`, `maxGroupEntries=64`, `maxGroupRunes=64`) bound the rendered size to under ~32KB worst-case, so the cap is rarely hit. Hitting it surfaces as a CloudWatch SDK error → 500 from the broker, propagating up through `recordAuthorized`'s fail-closed contract: the request is correctly denied. No security gap; the worst case fails closed. Mentioned as future-hardening: add an explicit pre-emit `len(encoded) <= 256*1024` check that, on overflow, drops the `EngineerGroups`/`Raw` fields and re-marshals, so audit emission never silently fails the request.
**Recommendation**: Pre-emit size check + graceful field-shedding fallback. Optional; the existing TruncateRunes layer is adequate for IdPs that respect their own claim-size norms.

## Informational

### F-SEC2-I1: F-SEC-I4 (go-oidc JWKs fetch via `http.DefaultClient`) unchanged
**Location**: `/Users/ttarhan/Code/postern/internal/idp/oidc.go:74`, `/Users/ttarhan/Code/postern/internal/oauthlogin/login.go:136`
**Threat**: As pass 1. `oidc.NewProvider` uses the default HTTP client / system trust store. Standard TLS trust model; not Postern's concern to harden. The broker-side fix in M1 (asymmetric-alg pin) raises the bar — even with a MITM'd JWKs response, attacker-controlled symmetric keys are no longer accepted by the verifier. F-SEC2-H1 leaves the same MITM open at the CLI side until fixed.

### F-SEC2-I2: F-SEC-I5 (YAML `KnownFields(true)` not set) unchanged
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/config.go:63`, `/Users/ttarhan/Code/postern/pkg/brokerhandlers/config.go:227`
**Threat**: As pass 1. Typo'd YAML keys silently no-op. Usability concern, not security — but an `audience_param: resourse` typo on the CLI side could leave audience-param binding effectively unset (the default `resource` then kicks in via `WithDefaults`, which masks the typo entirely). The broker-side typo case is more dangerous: `idp.audiance: ...` would leave `idp.audience` unset, the constructor would reject for missing audience-or-scope at startup — so the broker fails-fast, good. The CLI fails-silent, less good.
**Recommendation**: Call `decoder.KnownFields(true)` on the CLI's `yaml.NewDecoder` (broker side is fail-fast already). One line.

### F-SEC2-I3: Dependency security — direct deps look current; one mid-severity risk in `go-oidc v3.11.0`
**Location**: `/Users/ttarhan/Code/postern/go.mod`
**Threat**: Direct deps `github.com/coreos/go-oidc/v3 v3.11.0` (May 2024 release), `github.com/go-jose/go-jose/v4 v4.1.4`, `github.com/google/uuid v1.6.0` (recently promoted from indirect), `golang.org/x/crypto v0.40.0`, `golang.org/x/sys v0.34.0`, `golang.org/x/oauth2 v0.35.0`, `gopkg.in/yaml.v3 v3.0.1`. Older versions of go-oidc (≤ v3.10.0) had a known issuer-URL canonicalization issue (GHSA-pj2j-w7vp-prfj, June 2024) that v3.11.0 fixed. `golang.org/x/crypto v0.40.0` is past the CVE-2024-45337 fix (`v0.31.0`+). `gopkg.in/yaml.v3 v3.0.1` is the latest tagged release; no known CVE. No direct govulncheck run from this audit (the auditor lacks the network permission to install the tool), so I'm working from version-vs-known-disclosures comparison alone — recommend wiring `govulncheck` into CI if not already present (`.github/workflows/test.yml` is the natural seam).
**Recommendation**: Add `golang.org/x/vuln/cmd/govulncheck@latest` to CI's test workflow. No immediate action needed on any specific dep; the version floors are current.

## Methodology

Files reviewed in full or extensively (this pass):
- `AGENTS.md`, `DESIGN.md` (relevant sections), `docs/phases/timefix/spec.md` (LD-90 / LD-91 / invariant R / D13 verbatim), `docs/audit-post-timefix/security.md` (prior-pass cross-check)
- `internal/idp/oidc.go` (M1 closure verification)
- `internal/oauthlogin/login.go` + `internal/oauthlogin/token.go` (the new go-jose `accessTokenExpiry` path; the CLI ID-token verifier branch)
- `internal/broker/preamble.go`, `internal/broker/sshcert.go`, `internal/broker/issuetimepayload.go`, `internal/broker/types.go`, `internal/broker/runes.go`, `internal/broker/id.go` (verifying M2 + the shared TruncateRunes / uuid.NewV7 sweep)
- `internal/signer/kms.go` (KMS Sign for SignTimePayload; structural domain separation)
- `internal/policy/avp.go` (Cedar action mapping for MintTimefixCert)
- `internal/registry/http.go`, `internal/sshconf/writer.go`, `internal/audit/cloudwatch.go`, `internal/ratelimit/dynamodb.go`, `internal/brokerclient/client.go`
- `pkg/brokerhandlers/handlers.go`, `pkg/brokerhandlers/config.go`
- `pkg/cliapp/timefix.go`, `pkg/cliapp/addhost.go`, `pkg/cliapp/runtime.go`, `pkg/cliapp/config.go`, `pkg/cliapp/profile.go`
- `cmd/timefix-apply/main.go` + `verify.go`, `cmd/timefix-apply/capubpath_prod.go` + `capubpath_testbuild.go`, `cmd/timefix-set-clock/main.go`
- `terraform/postern-broker/cedar/starter.cedar` + `cedar/schema.json` (verifying MintTimefixCert action lives in both schema + permissive starter policy)
- `go.mod` (dep audit)
- `docs/architect-log.md` LD-65 wording (M2 closure)
- `git show 8eb0efd` (the sweep commit) to confirm what was/wasn't touched

Searches across the repo (rg/grep):
- `SupportedSigningAlgs` (M1 coverage)
- `validateDevice|ContainsAny|newline` in `internal/sshconf` (M4 coverage)
- `TruncateRunes`, `uuid.NewV7`, `atomicfile.WriteFile` (sweep coverage)
- `slog.` on the broker pipeline for accidental token-in-log leakage (clean)
- `InsecureSkipVerify`, `http.DefaultClient` (TLS hardening)
- `LD-65|LD-84` wording (M2)
- `KnownFields|yaml.NewDecoder` (typo defense)

Not re-audited from pass 1 (no material change since):
- KMS signer MessageType=Raw path (F-SEC-I2 — still correct)
- KeyId interpolation `url.PathEscape` (F-SEC-I3 — still correct)
- Exit-code-5 lumping for nonce/aud/serial (F-SEC-L3 — wire contract; out of audit scope to renegotiate)
- MaxJWSBytes+1 cap shape (F-SEC-L4 — bounded; still fine)
- on-device verifier unknown-header tolerance (F-SEC-I1 — confirmed-correct per LD-90/91)

Depth: function-by-function read of every file touching crypto, token validation, audit-emit, rate-limit, privilege-boundary, request-parsing, or the four prior-pass MEDIUM-OR-WORSE call sites. ~45 minutes. govulncheck not run (tooling install was denied by environment; ran version-vs-known-CVE comparison from training cutoff knowledge instead — see F-SEC2-I3 recommendation).
