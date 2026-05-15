# Security audit — post-timefix

## Summary

Postern's security posture is strong. The code consistently implements its threat-model commitments: access-token verification at the broker uses go-oidc with audience/scope enforcement, alg pinning closes alg-confusion, JWS construction and parse share `go-jose/v4` on both sides, the on-device privilege split has zero policy-controlled inputs to the setter, and the env-var override on the verifier's CA-pubkey path is build-tag gated out of production binaries. No HIGH-severity findings. Severity breakdown: HIGH 0, MEDIUM 4, LOW 7, INFO 5.

## High-severity findings

(None.)

## Medium-severity findings

### F-SEC-M1: Broker OIDCVerifier does not pin `SupportedSigningAlgs`; trust delegated to provider discovery
**Location**: `/Users/ttarhan/Code/postern/internal/idp/oidc.go:84-86`
**Threat**: `provider.Verifier(&oidc.Config{SkipClientIDCheck: true})` does not explicitly set `SupportedSigningAlgs`, so go-oidc falls back to the algs advertised by the IdP's `.well-known/openid-configuration` discovery document, intersected with go-oidc's internal allowlist. `alg=none` is filtered out by go-oidc's allowlist (good), but the broker still accepts whatever algs the discovery doc names — e.g. HS256 if an IdP advertises it. An IdP compromise (or an operator who misconfigures their IdP) that begins advertising symmetric signing (HS256) would let any party with read access to the JWKs URL forge tokens. Pinning `SupportedSigningAlgs` to the asymmetric set the broker accepts (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `EdDSA`) closes that channel by construction, mirroring the positive `EdDSA` pin the timefix verifier already enforces (LD-90 / LD-91 / invariant R).
**Recommendation**: Set `SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA}` on the `oidc.Config`. (Or the narrower subset the broker actually expects to encounter, e.g. RS256/ES256/EdDSA.) Apply the same pin in `internal/oauthlogin/login.go:190` where the CLI's ID-token verifier is constructed.

### F-SEC-M2: `signer_failure` emits both `*_authorized` and `*_denied` for the same JTI, contradicting invariant LD-65
**Location**: `/Users/ttarhan/Code/postern/internal/broker/sshcert.go:269-274`, `/Users/ttarhan/Code/postern/internal/broker/issuetimepayload.go:222-241`
**Threat**: LD-65 specifies "every request produces exactly one audit outcome — either a deny (with denied_reason) OR the authorized+issued pair joined on jti." Both pipelines violate this on Sign failure: they emit `*_authorized` first (fail-closed) and then `*_denied` with `signer_failure`. An operator's CloudWatch Insights query that filters on `denied_reason` will count Sign-failure requests, but the same JTI also appears in the authorized stream — a join on JTI produces both an "authorized" row and a "denied" row for the same request, which the LD-65 wording does not anticipate. This is a deliberate design choice (per the inline rationale, "we authorized but couldn't sign" is what operators want to see), but it is at odds with the documented invariant. The risk is alert-fatigue / metric-skew, not a forged audit row, hence MEDIUM not HIGH.
**Recommendation**: Either rewrite LD-65 to allow the three-outcome shape ("denied alone, authorized+issued, or authorized+denied-signer_failure") and update the test row that asserts the invariant; or change the Sign-failure path to NOT emit the `*_authorized` row when Sign fails (move `recordAuthorized` to after Sign — but then a post-Sign audit failure means the broker can't unwind the mint, which is what LD-64/65 was designed to avoid). The cleanest fix is documenting the three-outcome shape and renaming the invariant; the current code is the better-of-two-evils choice.

### F-SEC-M3: `runTimefix` CLI does not validate `--ip` flag value; newline/space characters flow into the `-o HostName=` ssh argv element
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/timefix.go:194-195`
**Threat**: `buildTimefixSSHArgv` appends `"-o", "HostName="+ip` after only `strings.TrimSpace(ip)`. ssh's `-o` flag parses the value as a config-file line; OpenSSH's option-parser splits on whitespace within the value in some versions, and definitely treats newlines as line separators when the value is reused. An engineer typing or pasting `--ip "10.0.0.1\nProxyCommand=/bin/sh -c 'rm -rf ~'"` would have the second line interpreted as an additional ssh option. This is self-foot-gun rather than third-party attack (engineer controls their own CLI), but a malformed copy-paste from a chat client or a malicious operator publishing an onboarding doc with smuggled newlines could escalate to local-machine command execution under the engineer's own UID. Same shape applies in `pkg/cliapp/addhost.go:98-100` which writes IP/Patterns into `sshconf.Stanza` (newline-validation is on `Device` only — see F-SEC-L1).
**Recommendation**: Validate `--ip` as a hostname/IP/IPv6 literal: reject newlines, spaces, control characters, `=`, and SSH option-name characters. A simple `^[A-Za-z0-9._:\[\]-]+$` regex captures all valid IPv4/IPv6/hostname forms.

### F-SEC-M4: `internal/sshconf` writer trusts `Stanza.HostName`, `Stanza.User`, `Stanza.Patterns` without newline-rejection
**Location**: `/Users/ttarhan/Code/postern/internal/sshconf/writer.go:178-205, 347-355`
**Threat**: `validateDevice` rejects newlines on the `Device` field only. `Stanza.HostName`, `Stanza.User`, and each entry of `Stanza.Patterns` are interpolated into the rendered config with `fmt.Fprintf`; a newline in any of these fields injects arbitrary ssh-config directives that future `ssh` invocations on the same host stanza will obey (`ProxyCommand`, `LocalCommand`, `IdentityFile`, etc.). Today's callers (`pkg/cliapp/addhost.go`) get these values from the engineer-typed `--user` / `--ip` flags, so this is again self-foot-gun. But the package contract should treat all stanza fields as untrusted strings.
**Recommendation**: Extend `validateDevice`-style newline+control-character rejection to every string field rendered into the file: `HostName`, `User`, each `Patterns` element.

## Low-severity findings

### F-SEC-L1: `runTimefix` writes mint response to tempfile in OS tempdir without TOCTOU defense
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/timefix.go:206-230`
**Threat**: `os.CreateTemp("", "postern-timefix-*.cert")` uses the OS temp directory (typically `/tmp` on macOS/Linux). On systems with `/tmp` shared between local users (multi-user Linux servers), another local user could observe filename creation, link-race the tempfile, or read its mode-0600 contents after the engineer's `WriteString` but before the `Chmod`. The cert is short-lived and tied to a specific device, so abuse is bounded; still, writing to `os.TempDir()` rather than the engineer's `~/.postern/` keeps the cert off shared filesystems entirely.
**Recommendation**: Write the tempfile under the per-profile cache dir (where `internal/certcache` already enforces mode 0700 on the parent directory), or chmod 0600 BEFORE the write rather than after.

### F-SEC-L2: `internal/oauthlogin` openBrowser shells out to `open` / `xdg-open` / `rundll32` with user-influenced URL
**Location**: `/Users/ttarhan/Code/postern/internal/oauthlogin/login.go:425-440`
**Threat**: The `loginURL` passed to `open <url>` (macOS) / `xdg-open <url>` (Linux) / `rundll32 url.dll,FileProtocolHandler <url>` (Windows) is built from `oauth2.Config.AuthCodeURL` and includes the engineer's local YAML config values (issuer URL, audience, scopes). `exec.CommandContext(command, args...)` is safe against shell injection (argv form, no shell). The URL handlers interpret the URL — if the issuer is `javascript:` or `file:///etc/passwd` the platform URL handler might honor it. Postern's config validator (`isHTTPSOrLoopback`) catches issuer schemes other than https/loopback, but the assembled authorize URL goes through `oauth2`'s URL builder which prepends the issuer's authorize endpoint, not a free-form URL — so the attack surface is mostly the operator's own machine. Low severity, but worth noting.
**Recommendation**: Validate `authorizeURL` parses as `https://` or `http://localhost:*` before exec'ing the platform URL opener.

### F-SEC-L3: Verifier exit code 5 (claim failure) does not distinguish nonce mismatch from `aud`/`device_serial`/`now` failures
**Location**: `/Users/ttarhan/Code/postern/cmd/timefix-apply/verify.go:165-186`, invariant P in `docs/phases/timefix/spec.md`
**Threat**: Per invariant P, the verifier's stable exit-code wire contract bundles every claim-validation failure into exit code 5. An attacker replaying a stale JWS to a device with a different serial / nonce / now-bound gets the same exit code as legitimate-but-typo'd cases. On-device log analysis can't distinguish a replay attempt from a misconfigured engineer in operational logs without parsing stderr. This is by design (single-pass; the exit code names the failure class, not the field), but operationally it makes attacker activity look like noise.
**Recommendation**: Either split exit code 5 into separate codes for nonce-mismatch (replay signal) and other claim failures, or document explicitly that operators should pattern-match on stderr text for replay detection.

### F-SEC-L4: `MaxJWSBytes` cap is enforced AFTER `io.ReadAll` reads `MaxJWSBytes+1` bytes
**Location**: `/Users/ttarhan/Code/postern/cmd/timefix-apply/main.go:177-187`
**Threat**: `io.LimitReader(r, MaxJWSBytes+1)` caps the read at 4097 bytes total; the verifier then rejects anything over 4096. An attacker flooding stdin can drive at most 4097 bytes, which is fine, but the code path allocates the buffer before the cap check — well-bounded but worth a note for future expansion (if `MaxJWSBytes` grows).
**Recommendation**: Cap directly with a smaller buffer; alternatively, keep as-is since the absolute bound is tiny.

### F-SEC-L5: `OIDCVerifier.iatMaxAge = 24 * time.Hour` is a long ceiling
**Location**: `/Users/ttarhan/Code/postern/internal/idp/oidc.go:36`
**Threat**: A token whose `exp` claim is set far in the future (some IdPs issue tokens with `exp = iat + 7d`) is still rejected after 24h. But an IdP that issues `exp = iat + 365d` and the engineer's laptop never refreshes would still let an old token mint certs for up to 24h. The combination of `exp` enforcement and the 24h max-age cap is layered correctly; reducing the cap further (e.g. to 1h or matching the broker's operator cert TTL) tightens the window for stolen tokens replayed against the broker.
**Recommendation**: Consider tightening `iatMaxAge` to 1 hour or to the configured `cert_ttl.operator` value. Out of scope for this audit pass — flag for design discussion.

### F-SEC-L6: `internal/oauthlogin.AccessToken` writes refreshed access tokens to keychain even when not freshly verified against the IdP's JWKs
**Location**: `/Users/ttarhan/Code/postern/internal/oauthlogin/token.go:101-117`
**Threat**: The refresh flow trusts the IdP token endpoint's returned `access_token` and only checks that `exp` is parseable (`accessTokenExpiry`). It does NOT verify the token's signature against the IdP's JWKs. The ID-token signature is verified during the original login (`login.go:190-194`), but refreshed access tokens flow into the keychain unverified. Risk: a compromised IdP token endpoint (or in-path proxy with TLS-MITM if the engineer's trust store is tampered with) could substitute an attacker-controlled access token. Since the broker re-verifies the access token via its OIDC verifier on every request, downstream impact is bounded — the broker rejects unsigned/forged tokens at /ssh/cert. Still, freshly verifying on refresh would catch the issue at the CLI rather than the broker.
**Recommendation**: After refresh, verify the new access token via `provider.Verifier(...).Verify(ctx, accessToken)` before persisting. Or document that access-token verification is the broker's job exclusively.

### F-SEC-L7: `pkg/cliapp/timefix.go` `defaultExecSSHTimefix` reads device-emitted stdout line-by-line with `bufio.NewReader` — no input cap
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/runtime.go:185-216`
**Threat**: `stdoutReader.ReadString('\n')` reads until newline or EOF, with no length bound. A malicious device (or a man-in-the-middle on the SSH stream after compromise of the device's `timefix` principal authorization) could emit gigabytes before a newline, forcing the CLI to allocate unbounded memory. The cert verification path bounds device authorization (force-command + timefix-only cert), so this requires already-having-compromised the on-device authentication seam. Low severity, but the seam should still cap reads.
**Recommendation**: Replace `bufio.NewReader.ReadString('\n')` with `bufio.Scanner` or a `io.LimitReader`-wrapped `ReadString` capped at ~4KB (the nonce is 43 bytes; clock line is ~30 bytes; 4KB is generous).

## Informational

### F-SEC-I1: Verifier accepts arbitrary unknown JWS header fields
**Location**: `/Users/ttarhan/Code/postern/cmd/timefix-apply/verify.go:144-148`
**Threat**: Per the LD-90/LD-91 simplification of invariant R, the verifier tolerates unknown header fields (including `kid`, `jwk`, `x5c`, `crit`). The rationale is correct (with `alg=EdDSA` positively pinned via go-jose's accepted-algs list, extra header fields cannot widen attacker capability — there's no key-resolution step that could be tricked into using `jwk` or `x5c`). No exploit path. Mentioned only because v1 of the invariant (pre-LD-90) explicitly required header-field-set strictness; the looser invariant survives review.

### F-SEC-I2: KMS `Sign` calls use `MessageType=Raw` rather than `Digest`
**Location**: `/Users/ttarhan/Code/postern/internal/signer/kms.go:106-117, 137-148`
**Threat**: Both SignCert and SignTimePayload pass the full message bytes to KMS with `MessageType=Raw`; KMS hashes server-side under `SigningAlgorithmSpecEd25519Sha512`. Ed25519 specifies SHA-512 hashing as part of the signature algorithm (RFC 8032), and KMS's `ED25519` algorithm spec performs the hash internally as documented. The `Raw` choice is correct here — `Digest` would imply pre-hashed input which Ed25519 does not use externally. Mentioned for paper trail since it's an easy thing to second-guess.

### F-SEC-I3: `KeyId` field in SSH cert is engineer-influenced via `engineer.Subject` and `engineer.Email`
**Location**: `/Users/ttarhan/Code/postern/internal/broker/sshcert.go:438-442`
**Threat**: `keyID` uses `url.PathEscape` on both subject and email to defend against `;` / `\n` smuggling through structured log queries that parse the KeyId string. The defense looks correct — `url.PathEscape` escapes `;`, newline, and other special chars. The output `engineer_sub:%s;engineer_email:%s;jti:%s` is parseable. No issue; flagged for context since "engineer-influenced field is interpolated into a structured log identifier" is a typical injection vector.

### F-SEC-I4: Broker config validates `idp.issuer` must be https or loopback, but `internal/idp.OIDCVerifier` re-fetches discovery via go-oidc which uses `http.DefaultClient`
**Location**: `/Users/ttarhan/Code/postern/pkg/brokerhandlers/config.go:373-377`, `/Users/ttarhan/Code/postern/internal/idp/oidc.go:75`
**Threat**: `oidc.NewProvider` uses `http.DefaultClient` (or an injected one — none is injected here). The default client follows redirects and respects the system trust store. A network-level MITM with an attacker-issued cert in the trust store could intercept JWKs fetches and substitute attacker-controlled keys. This is the standard TLS trust model and not Postern's to harden; mentioned because the broker runs in environments (Lambda, ECS) where system trust store hygiene is reasonable but worth flagging.
**Recommendation**: No action; document in operator-runbook style.

### F-SEC-I5: `pkg/cliapp/config.go` `LoadConfig` decodes YAML without `KnownFields(true)`
**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/config.go:61-72`
**Threat**: `yaml.NewDecoder` accepts unknown YAML fields silently. An engineer typing `audience_param: resource` instead of the documented field name gets no error; the typo just becomes a no-op. This is a usability concern, not a security one — but typo'd config can leave audience binding effectively unset.
**Recommendation**: Call `decoder.KnownFields(true)`. (Note: the broker-side config loader at `pkg/brokerhandlers/config.go:227-232` has the same behavior; same recommendation applies symmetrically.)

## Methodology

Files reviewed (read in full or extensively):
- `AGENTS.md`, `docs/phases/timefix/spec.md`, `go.mod`
- `internal/idp/oidc.go`, `internal/idp/oidc_test.go` (partial), and go-oidc v3.11.0 source at `~/go/pkg/mod/github.com/coreos/go-oidc/v3@v3.11.0/oidc/verify.go` + `oidc.go` for alg/exp/expiry behavior
- `internal/signer/kms.go`
- `internal/oauthlogin/login.go`, `internal/oauthlogin/token.go`
- `internal/broker/preamble.go`, `internal/broker/issuetimepayload.go`, `internal/broker/sshcert.go`, `internal/broker/types.go`, `internal/broker/id.go`, `internal/broker/errors.go`
- `internal/policy/avp.go`
- `internal/registry/dynamodb.go`, `internal/registry/http.go`, `internal/registry/serial.go`
- `internal/ratelimit/dynamodb.go`
- `internal/audit/cloudwatch.go`
- `internal/brokerclient/client.go`
- `internal/brokerwire/wire.go`
- `internal/tokenstore/store.go`, `internal/tokenstore/file.go`, `internal/tokenstore/keychain.go`
- `internal/certcache/cache.go`
- `internal/sshconf/writer.go`
- `internal/atomicfile/atomicfile.go`
- `pkg/brokerhandlers/handlers.go`, `pkg/brokerhandlers/config.go`
- `pkg/cliapp/timefix.go`, `pkg/cliapp/runtime.go`, `pkg/cliapp/ssh.go`, `pkg/cliapp/addhost.go`, `pkg/cliapp/mint.go`, `pkg/cliapp/profile.go`, `pkg/cliapp/config.go`, `pkg/cliapp/defaults.go`
- `cmd/broker/main.go`
- `cmd/timefix-apply/verify.go`, `cmd/timefix-apply/main.go`, `cmd/timefix-apply/capubpath_prod.go`, `cmd/timefix-apply/capubpath_testbuild.go`, `cmd/timefix-apply/verify_test.go` (partial), `cmd/timefix-apply/integration_test.go`
- `cmd/timefix-set-clock/main.go`, `cmd/timefix-set-clock/syscalls_linux.go`, `cmd/timefix-set-clock/syscalls_other.go`
- Searches across the repo for: TLS / InsecureSkipVerify, alg pinning, slog calls touching tokens, JSON DisallowUnknownFields, env-var override sites, AWS SDK auth flows, XFF / RemoteAddr handling.

Not audited in this pass (per scope budget):
- `examples/`, `terraform/postern-broker/` (IaC review is a separate pass)
- `cmd/broker-lambda/` source code (verified that it shares dep wiring with `cmd/broker/`)
- `pkg/cliapp/scp.go`, `pkg/cliapp/cache.go`, `pkg/cliapp/configure.go`, `pkg/cliapp/logout.go`, `pkg/cliapp/login.go` end-to-end (sampled for token-handling patterns; full subcommand-by-subcommand review deferred)
- The DESIGN.md threat-model section (the bulk of it is documented in `AGENTS.md` and `docs/phases/timefix/spec.md`, both read in full)
- Test files beyond verification of locked-in invariants (test-only code is not in the threat model)

Depth: function-by-function read of every file touching crypto, token validation, audit, rate-limit, or privilege boundary; spot-check of patterns elsewhere via grep. ~45 minutes.
