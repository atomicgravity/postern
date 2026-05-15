# Hand-rolled vs library audit — 2026-05-15

## Scope, methodology, and how prior closures factored in

Walked every production `.go` file under `internal/`, `pkg/`, and `cmd/`
(48 files, excluding `_test.go` and the protoc-generated
`internal/securetunnel/proto/v3.pb.go`). For each file, scanned
`import`s, `crypto/*` / `encoding/*` / `net/*` stdlib reach, manual byte
parsing patterns (`strings.Split`, `binary.Big/LittleEndian`, length-
prefix framing), AWS SDK call shapes (DynamoDB `AttributeValue`
construction/extraction; KMS `Sign` body building; SigV4 helper use),
HTTP client construction, and file-IO patterns. Cross-checked
`docs/audit-post-sweep/hand-rolled.md` and
`docs/audit-post-timefix/hand-rolled.md` to avoid re-flagging closed
findings. The two prior closures that materially shape this pass are:

- **JWS pipeline → `go-jose/v4`** (LD-90 / LD-91): both broker
  (`internal/broker/issuetimepayload.go`) and on-device verifier
  (`cmd/timefix-apply/verify.go`) construct/parse JWS Compact via
  the library, with an `OpaqueSigner` adapter bridging KMS. The
  CLI access-token expiry-read in `internal/oauthlogin/token.go`
  also went through `jwt.ParseSigned`. None of these resurface as
  new findings.
- **`atomicfile.WriteFile{,Exclusive}`** as the in-repo helper for
  rename-or-link atomic writes: `tokenstore/file.go`,
  `pkg/cliapp/config.go` (`SaveConfigFile`), `internal/certcache/
  cache.go` (`writeProfileKeyExclusive`), `internal/sshconf/writer.
  go` all consume it now. The post-sweep audit's F-HR2-L1
  (`pkg/cliapp/timefix.go` tempfile pattern) remains open and is
  preserved verbatim below as L-9 because it still applies and is
  the only remaining cliapp temp-file open-code that isn't
  bench-tested against `os.WriteFile`.

This pass surfaces NEW findings only. The most notable new area is
`internal/securetunnel/` (the V3 secure-tunneling source proxy +
protobuf wire framing landed since the prior audit), which uses
`coder/websocket` + `google.golang.org/protobuf` correctly with
stdlib `encoding/binary` for the 2-byte length prefix — clean. Two
hand-roll candidates remain at the periphery (state-machine choice
and a stdlib helper).

Cap budget: 12 findings landed below.

## High

(none)

The big crypto-adjacent and wire-shape hand-rolls are closed. JWS
construction/parse, JWT exp-read, UUIDv7, SSH cert build + sign, SSH
authorized-key parse/marshal, SSH config write, atomic-file write,
HTTP body-cap, JSON disallow-unknown-fields, OAuth2 PKCE, OIDC
verifier — all library-driven.

## Medium

### L-1: DynamoDB Registry hand-decodes `AttributeValue` map with type switches

**Location**: `/Users/ttarhan/Code/postern/internal/registry/dynamodb.go:82-145`
**Priority**: Medium
**Current**: `ResolveDevice` reads each field by writing a type
assertion against the AWS SDK's `*types.AttributeValueMember{S,N,BOOL}`
discriminator. `stringAttribute` / `stringAttributeValue` /
`normalizeDynamoDBAttribute` each open-code an `AttributeValue ->
Go-value` projection. The S/N/BOOL case set is hardcoded; L (list), M
(map), SS / NS / BS (sets), NULL, and B (binary) drop silently.
**Library option**: `github.com/aws/aws-sdk-go-v2/feature/dynamodb/
attributevalue` (sibling subpackage of the v2 SDK, same release
cadence — adding it does not introduce a new ecosystem dep). It
provides `attributevalue.UnmarshalMap(item, &dest)` for struct-tagged
shapes and `attributevalue.Unmarshal(av, &v)` for per-attribute
projection. The struct-tag form would let `DeviceRecord` carry
`dynamodbav:"serial"` tags and the entire decode collapses to one
`UnmarshalMap` call.
**Trade-off**: The current code's positive-allowlist behavior (only S
/ N-integer / BOOL flow into `Attributes`; everything else drops) is
load-bearing for the Cedar-type-map contract that
`internal/policy/avp.go:cedarAttributeValue` enforces on the
downstream side. A blind `UnmarshalMap` into `map[string]any` would
admit L/M/SS/etc., which Cedar would then drop a second time. Worth
the swap only if the new decode preserves the same drop set; the
simplest shape is `UnmarshalMap` into a typed struct for the named
fields (`Serial`, `FriendlyID`) and keep the explicit type-switch for
`Attributes` (or use `UnmarshalListOfMaps`-style with a custom
decoder option that filters non-scalar types).
**Recommendation**: Use `attributevalue.UnmarshalMap` for the named
fields (`serial`, `friendly_id`) — that's the part where the
type-switch buys nothing. Keep the explicit `normalizeDynamoDBAttribute`
switch for the open-ended attributes map because the
drop-non-scalar policy is itself the value.

### L-2: `securetunnel.containsString` reimplements `slices.Contains`

**Location**: `/Users/ttarhan/Code/postern/internal/securetunnel/loops.go:314-321`
(call site `loops.go:110`)
**Priority**: Medium (Cleaner-with-stdlib — single-call swap)
**Current**:
```go
func containsString(list []string, target string) bool {
    for _, item := range list {
        if item == target {
            return true
        }
    }
    return false
}
```
Used inside `dispatchMessage` for the mid-session SERVICE_IDS
re-validation against the published service-id list.
**Library option**: `slices.Contains` (stdlib since Go 1.21).
`internal/idp/oidc.go` already uses it (`slices.Contains(token.Audience, v.audience)` and `slices.Contains(scp, required)`), and `pkg/cliapp/removehost.go:46` does too — `securetunnel` is the only package re-implementing it.
**Trade-off**: None.
**Recommendation**: Replace the helper with `slices.Contains` at the
one call site and delete the function. Roughly a 9-line negative diff.

### L-3: `cmd/timefix-apply/main.go` open-codes line iteration with `strings.Split` + manual skip

**Location**: `/Users/ttarhan/Code/postern/cmd/timefix-apply/main.go:225-249`
(`readPrincipalSerial`)
**Priority**: Medium
**Current**: `strings.Split(string(contents), "\n")` then loops
trimming, skipping blanks/comments, and unpacking the first match.
Allocates one large slice for the whole file just to read the first
non-skip line.
**Library option**: `bufio.Scanner` over `bytes.NewReader(contents)`
(both stdlib) — the same shape `internal/sshconf/ephemeral.go`
already uses for similar file-line walks. For a tiny
`/etc/ssh/authorized_principals/timefix` file the allocation cost
difference is negligible; the value is style consistency with
`sshconf` (which scans inside marker blocks line-by-line with
`bufio.Scanner`). Alternative: `bytes.Cut` in a `for` loop avoids
the slice allocation.
**Trade-off**: Either stdlib path works; the current code is
correct and readable. This is style-consistency, not
correctness-driven.
**Recommendation**: When someone is next in this file, switch to
`bufio.Scanner` for parity with `sshconf`. Not standalone-urgent.

### L-4: Hand-rolled `findHostPositional` SSH argv parser

**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/tunnel.go:238-269`
(plus the `sshFlagConsumesArg` flag-skip-list)
**Priority**: Medium
**Current**: A bespoke argv walker that classifies tokens as
flag/positional and applies a hand-curated skip-list of ssh flags
that take a separate-slot argument (`-L`, `-R`, `-D`, `-p`, `-o`,
`-i`, `-F`, `-l`, `-J`, `-W`, `-e`, `-c`, `-b`, `-m`, `-O`, `-Q`,
`-S`, `-w`). Used to find the engineer's destination positional
inside `--`-less ssh passthrough so tunnel-mode can rewrite the
host segment to the device-id.
**Library option**: There is no clean library swap here. `flag` /
`pflag` / `spf13/cobra` don't model ssh's argv (ssh's flag set is
inherited from OpenBSD's getopt(3), not POSIX); a "real" parser
would need ssh's flag table in full. The community ssh-argv parsers
(`flynn/u-root`-style helpers, etc.) are not maintained as
standalone libraries.
**Trade-off**: The skip-list is fragile (OpenSSH 9.x added flags
not in the list — `-G`, `-Y`, `-V`, etc. — but those are
positional-less, so they're harmless if missing) and grows with
each ssh release. Re-derive from `ssh -h`? That'd be a runtime
fork; not in scope.
**Recommendation**: Keep the hand-roll. Add a unit test that
exercises every ssh release's new flag-with-arg shape when it
matters; the skip-list is the right tradeoff for this niche
problem.

## Low

### L-5: `realclientip-go v1.0.0` pinned at the .0.0 with no update since project start

**Location**: `/Users/ttarhan/Code/postern/go.mod:19`
**Priority**: Low
**Current**: `github.com/realclientip/realclientip-go v1.0.0`. Used
in `internal/brokerwire/wire.go:buildClientIPStrategy` for
trusted-proxy XFF parsing and `pkg/brokerhandlers/handlers.go` for
the `ClientIPStrategy` interface.
**Library option**: Same library — but `v1.0.0` is from the
project's earliest tag and hasn't been bumped. The library is
maintained by the author of the IETF RFC-7239 Forwarded-spec
post-rationalization writeup; the library is small (one file of
strategies) and the API is stable, but a v1.x update may have
landed since.
**Trade-off**: The library's surface is tiny (`Strategy` interface,
`RemoteAddrStrategy`, `NewRightmostTrustedRangeStrategy`,
`NewChainStrategy` — that's it). A stale v1.0.0 is not a
correctness risk; it's a "track upstream" hygiene observation.
**Recommendation**: Run `go list -m -u github.com/realclientip/realclientip-go`
once per release cycle. Not a swap candidate; the library choice
is well-suited.

### L-6: HTTP retry/backoff absent (intentional — flagging for future-proofing)

**Location**: Search over `internal/brokerclient/client.go`,
`internal/registry/http.go`, `internal/oauthlogin/{login,token}.go`
**Priority**: Low
**Current**: Zero retry logic anywhere in the CLI's HTTP calls. A
broker 5xx, an IdP discovery timeout, an HTTP-registry transient
failure all surface unwrapped to the engineer. The AWS SDK calls
get the SDK's built-in retry (good). The CLI's broker calls and
OAuth refresh do not retry on `connection refused` / `tcp
read: i/o timeout`.
**Library option**: `github.com/hashicorp/go-retryablehttp` or
`github.com/cenkalti/backoff/v4`. Both well-maintained. The
former is `*http.Client`-shaped; the latter is generic.
**Trade-off**: The current "fail fast, engineer retries the
command" is consistent with the CLI's UX (every subcommand is
idempotent; rerunning `postern ssh foo` after a broker hiccup is
free). Adding retry would smooth over transient failures the
engineer's terminal already smooths over by re-typing the
command. For long-running unattended flows (`postern tunnel`
sessions that should survive a broker blip), retry would matter
— but those flows are out of scope today.
**Recommendation**: Leave alone for v1. Document the no-retry
choice in `docs/team-handoff.md` so the next reviewer doesn't
treat its absence as an oversight. If `postern tunnel` evolves
toward auto-reconnect, revisit then.

### L-7: `aws-lambda-go-api-proxy` v0.x version pinning

**Location**: `/Users/ttarhan/Code/postern/go.mod:14`
**Priority**: Low
**Current**: `github.com/awslabs/aws-lambda-go-api-proxy v0.16.2`.
The only consumer is `cmd/broker-lambda/main.go` for the
`httpadapter.HandlerAdapterV2` API-Gateway-HTTP-v2 → `http.Handler`
adapter.
**Library option**: Same library. AWS Labs has not stabilized this
at v1; v0.16.2 (Sep 2024) is the latest tag. It's the canonical
adapter for the use case — no alternative library to swap to.
**Trade-off**: `v0.x` semver implies API instability, but in
practice the v2 adapter has been stable for ~2 years. Stay pinned;
bump when AWS Labs cuts a new release.
**Recommendation**: Pin acknowledged; no action.

### L-8: Hand-rolled SSH-cert `KeyId` composition with manual `;` separators

**Location**: `/Users/ttarhan/Code/postern/internal/broker/sshcert.go:431-435`
(`keyID`)
**Priority**: Low
**Current**:
```go
return "engineer_sub:" + url.PathEscape(engineer.Subject) +
    ";engineer_email:" + url.PathEscape(engineer.Email) +
    ";jti:" + jti
```
**Library option**: `net/url` Query encoder via `url.Values`:
```go
values := url.Values{
    "engineer_sub":   {engineer.Subject},
    "engineer_email": {engineer.Email},
    "jti":            {jti},
}
return values.Encode() // returns canonical &-separated form
```
**Trade-off**: The current ASCII shape is **not** standard
URL-encoded query; it uses `;` as separator (URL-spec valid but
unusual today), and field order is fixed by code order (operator
log queries depend on field order). Switching to `url.Values.Encode()`
would change the separator to `&` (break operator log queries),
re-sort keys alphabetically (also breaks order-sensitive parsers),
and switch escape mode from `PathEscape` to `QueryEscape` (different
escape set for some chars). All breaking.
**Recommendation**: Leave alone — the current code is correct and
the wire format is stable for downstream consumers. Flagging because
it's a hand-rolled wire shape the audit lens picks up; the rationale
not to swap is the wire-stability rationale.

### L-9 [carried from prior pass]: `pkg/cliapp/timefix.go` `writeTimefixCertTempfile` open-codes temp+chmod+write

**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/timefix.go:206-230`
**Priority**: Low
**Current**: Same shape as the post-sweep F-HR2-L1 finding;
`os.CreateTemp("", timefixCertTempPrefix)` → `tempFile.Chmod(0o600)`
→ `tempFile.WriteString(sshCert)` → `tempFile.Close()` + per-step
cleanup. Still open — no fix landed since the prior pass.
**Library option**: `os.WriteFile` after `os.CreateTemp` (drop the
file handle, keep the path):
```go
file, err := os.CreateTemp("", timefixCertTempPrefix)
if err != nil {
    return "", nil, fmt.Errorf("create timefix cert tempfile: %w", err)
}
tempPath := file.Name()
file.Close()
if err := os.WriteFile(tempPath, []byte(sshCert), 0o600); err != nil {
    os.Remove(tempPath)
    return "", nil, fmt.Errorf("write timefix cert tempfile: %w", err)
}
```
**Trade-off**: None beyond the prior pass's note — code clarity,
not safety. The destination is a tempfile (not a stable named
path), so `atomicfile` doesn't directly apply.
**Recommendation**: Tighten when next in this file. Not
standalone-urgent.

## Cleaner-with-stdlib

### L-10: `time.RFC3339` parse + format pairs accumulate; consider a typed `RFC3339Time` wrapper

**Location**: `internal/sshconf/ephemeral.go:312-323`, `cmd/timefix-apply/verify.go:180-185`,
`pkg/cliapp/cache.go:88`, `internal/broker/issuetimepayload.go:211`, `internal/policy/avp.go:112`
**Priority**: Cleaner-with-stdlib (informational)
**Current**: Every time-payload, audit, AVP-context, and cache
listing path independently calls
`time.Parse(time.RFC3339, x)` / `time.Format(time.RFC3339)`. The
verifier's `now` field is RFC3339; the broker's audit timestamp is
RFC3339; AVP's `timestamp` context attribute is RFC3339;
`cliapp/cache.go` formats `ValidBefore` as RFC3339. Five sites,
identical idiom, no library involvement.
**Library option**: None — these are stdlib calls, used correctly.
The only adjacent library option would be `go-jose/v4/jwt.NumericDate`
for JWT-encoded times (already used in `oauthlogin/token.go`'s
expiry-read), but the wire-format pinning is RFC3339 by design (the
on-device verifier rebuilds the string for re-emission to ssh; a
JWT-style numeric date would diverge from DESIGN.md).
**Trade-off**: A `RFC3339Time` typed wrapper with `Marshal/Unmarshal`
methods would shrink the repetition, but at the cost of an extra
layer between domain types and JSON tags. The current shape is
duplicate-yet-clear; the duplication does not hide a bug.
**Recommendation**: No action. Flagging so a future "DRY this" pass
sees the rationale not to consolidate.

### L-11: `pkg/cliapp/cache.go:writeCacheList` uses `text/tabwriter` — clean stdlib choice worth noting

**Location**: `/Users/ttarhan/Code/postern/pkg/cliapp/cache.go:83-99`
**Priority**: Cleaner-with-stdlib (informational, positive example)
**Current**: `text/tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)` for
the `postern cache ls` human-readable column layout.
**Library option**: Already stdlib. Some Go CLIs reach for
`github.com/olekukonko/tablewriter` or `github.com/jedib0t/go-pretty`
when `tabwriter` would do.
**Trade-off**: None — stdlib choice is the right one for this use
case (no Unicode rune-width awareness needed; engineer-facing
ASCII-only fields).
**Recommendation**: Keep; flagging as a positive marker that the
project consistently picks stdlib when it suffices.

### L-12: `internal/audit/cloudwatch.go` uses `aws.String` / `aws.Int64` pointer-builder helpers — idiomatic SDK use

**Location**: `/Users/ttarhan/Code/postern/internal/audit/cloudwatch.go:81-86`
(and similar in `internal/policy/avp.go`, `internal/registry/dynamodb.go`,
`internal/ratelimit/dynamodb.go`, `internal/signer/kms.go`, `internal/tunneling/awsiot.go`)
**Priority**: Cleaner-with-stdlib (informational, positive example)
**Current**: Every AWS SDK call uses `aws.String(s)` / `aws.Int32(n)` /
`aws.Bool(b)` to build the pointer-typed SDK request fields. That's
the SDK's documented helper pattern.
**Library option**: Already library-driven; no swap.
**Trade-off**: None — this is exactly the "use the SDK as intended"
behavior the audit lens looks for, and it's followed consistently
across every AWS-touching package.
**Recommendation**: Keep. Flagging as a positive marker.

## Well-considered areas

The library choices in this repo are deliberate and consistent. The
JWS path is fully `go-jose/v4` on both sides (broker
`OpaqueSigner` adapter + verifier `ParseSigned` with EdDSA-only
accepted-algs list). The IdP path is single-dep `coreos/go-oidc/v3`
for verifier + `golang.org/x/oauth2` for PKCE — the OIDC verifier
runs on the broker side with a hardcoded list of asymmetric signing
algs (RS/ES/PS + EdDSA), explicitly excluding HS\* and `none`. The
OAuth2 callback is built on the stdlib `net/http` + a loopback
listener walk (no third-party server lib). Atomic file writes
centralize in `internal/atomicfile` with both rename-based and
link-based variants exported — the post-sweep finding that wanted
this split got it. SSH cert + key parse/marshal is exclusively
`golang.org/x/crypto/ssh` — no DIY OpenSSH wire formats anywhere.
The V3 secure-tunneling protobuf wire schema is vendored as a
`.proto` and the generated code is checked in; the runtime uses
`google.golang.org/protobuf` for `Marshal`/`Unmarshal` and stdlib
`encoding/binary.BigEndian` for the 2-byte length-prefix envelope —
clean separation of "the protocol's protobuf framing" from "the
WebSocket framing." The WebSocket client is `coder/websocket`
(actively maintained successor to the deprecated nhooyr/websocket).
The CLI's keychain backend (`zalando/go-keyring v0.2.8`) covers the
three OS-keychain APIs (macOS Security, Win wincred, Linux libsecret)
without a stdlib alternative. AWS calls use the SDK's `aws.String`
helpers and the `feature/dynamodb/attributevalue` package gap noted
in L-1 is the single SDK-helper miss against an otherwise idiomatic
SDK consumption pattern. Config is single-dep `gopkg.in/yaml.v3`
on both the broker and CLI sides, with no INI/TOML/JSON
reintroductions, and the `Duration` type's `Marshal/UnmarshalYAML`
is the right place to hide `time.ParseDuration`. The realclientip
choice for XFF parsing under trusted-proxy CIDRs is precisely the
library you'd pick (RFC-7239-aware, tiny surface). The "no DI
framework" rule holds — every constructor is hand-wired in `main.go`
or `brokerwire.BuildDeps`, with the `PipelineDeps` struct as a thin
shared bag the three issuers (SSHCert / TimePayload / Tunnel) embed.
HTTP body caps via `http.MaxBytesReader` + JSON decoder with
`DisallowUnknownFields` is the idiomatic stdlib defense. UUIDv7
generation is `google/uuid` (the canonical library, version `1.6.0`
which is when UUIDv7 shipped). Tabular human output is stdlib
`text/tabwriter`. Logging is stdlib `log/slog` with a JSON handler
— the one configuration point the project allows itself.
