# Hand-rolled-vs-library audit — post-TF-E (2026-05-13)

Single-question audit: **are we hand-rolling things a battle-tested library
does better?** Triggered by user policy: "never hand-roll things we don't have
to including the broker side. it is never more safe to hand roll your own
crypto adjacent code." The TF-E JWS swap (LD-90/LD-91) removed the canonical
example; this audit walks the rest of the production tree to see where else
the same shape lives.

## Summary

Scope: `internal/`, `pkg/`, `cmd/` excluding `_test.go`. Read every
production file under those trees.

Total findings: 7

- HIGH: 1 (crypto-adjacent JWT parsing in `oauthlogin/token.go`)
- MEDIUM: 2 (UUIDv7 in `broker/id.go`; atomic-write duplication in
  `tokenstore/file.go`)
- LOW: 1 (hex-formatted UUID via `fmt.Sprintf`)
- INFO: 3 (sshconf hybrid writer, hardcoded empty-payload SHA-256,
  base64url-decode of nonces — all justified)

The codebase is already in good shape on this dimension. The post-LD-90/LD-91
JWS construction/verification is cleanly library-driven via `go-jose/v4`. The
remaining HIGH is a single hand-roll the LD-90/LD-91 reasoning applies to
directly: parsing a JWT to read its `exp` claim in the CLI's access-token
refresh path.

## High

### F-HR-H1 — `internal/oauthlogin/token.go` hand-rolls JWT parsing to read `exp`

**Location:** `internal/oauthlogin/token.go`, `accessTokenExpiry` function
(~lines 165-199).

**What's hand-rolled:** The function reads the access token's `exp` claim by
manually splitting on `.`, base64url-decoding the middle segment, and
JSON-unmarshaling into a single-field struct:

```go
parts := strings.Split(token, ".")
if len(parts) < 2 {
    return time.Time{}, errors.New("access token is malformed")
}
payload, err := base64.RawURLEncoding.DecodeString(parts[1])
// ... json.Decoder.UseNumber() into {ExpiresAt json.Number `json:"exp"`} ...
```

This is structurally identical to the verifier-side hand-roll LD-91 just
removed from `cmd/timefix-apply/verify.go`. The function is called on
**every CLI access-token fetch** (cert mint, ssh, scp, timefix) via
`AccessToken` → `accessTokenFresh` → `accessTokenExpiry`, and once more
inside `Login` after the token exchange — i.e., it sits on every authenticated
CLI hot path.

**Library that replaces it:** `github.com/go-jose/go-jose/v4` (already a
direct dep, v4.1.4 per LD-62).

```go
import (
    jose "github.com/go-jose/go-jose/v4"
    "github.com/go-jose/go-jose/v4/jwt"
)

func accessTokenExpiry(token string) (time.Time, error) {
    parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
        jose.RS256, jose.ES256, jose.EdDSA, /* whatever IdPs we accept */
    })
    if err != nil {
        return time.Time{}, err
    }
    var claims jwt.Claims
    if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
        return time.Time{}, err
    }
    if claims.Expiry == nil {
        return time.Time{}, errors.New("access token missing exp")
    }
    return claims.Expiry.Time(), nil
}
```

`UnsafeClaimsWithoutVerification` is appropriate here: this is a CLI-side
expiry-pre-check on a token the CLI already obtained from the IdP and is
about to forward to the broker. The broker is the one verifying signatures
on the same token; the CLI is just deciding whether to refresh proactively.
The library still does the parse-shape and base64url validation correctly,
so a malformed token can't trip the hand-rolled `strings.Split` path.

**Why the swap is justified (LD-90/LD-91 argument, verbatim):** the same
parser/serializer differential surface argument applies — the IdP and the
broker use `go-oidc`/`go-jose` to construct and verify access tokens;
hand-rolling the parse on the CLI side puts a different code path between
issuer and consumer. The shape is small enough today that nothing is broken,
but the moment a future IdP emits an `exp` as a float (some non-RFC IdPs
do — note the existing `strconv.ParseFloat` fallback) or a fractional
second, the hand-roll's behavior diverges from what the library would
accept. The library's been hardened against the entire space of malformed
JWTs; we're hand-rolling on the smallest possible slice of that space.

Note: the `id_token` in `oauthlogin/login.go` is correctly verified via
`provider.Verifier(...).Verify()` — only the `access_token` expiry-read
path is hand-rolled, because the access token's signature is the broker's
problem and the CLI just needs the expiry.

**Severity rationale:** HIGH because (a) it's on the CLI's authenticated
hot path, (b) it's the textbook recurrence of the LD-90/LD-91 anti-pattern,
(c) the library is already imported, and (d) the user's policy on this is
explicit.

## Medium

### F-HR-M1 — `internal/broker/id.go` hand-rolls UUIDv7

**Location:** `internal/broker/id.go`, `UUIDv7Generator.NewID` (entire
function, ~lines 30-65).

**What's hand-rolled:** Manual UUIDv7 construction — read 10 bytes of
randomness, splice the millisecond timestamp into bytes 0-5, set the
version nibble (`uuid[6] = (uuid[6] & 0x0f) | 0x70`), set the variant
nibble (`uuid[8] = (uuid[8] & 0x3f) | 0x80`), and render via
`fmt.Sprintf("%x-%x-%x-%x-%x", ...)`.

**Library that replaces it:** `github.com/google/uuid` (canonical Go UUID
library; would be a new direct dep). UUIDv7 has shipped in `google/uuid`
since `v1.6.0` via `uuid.NewV7()`.

```go
func (g UUIDv7Generator) NewID(now time.Time) (ID, error) {
    id, err := uuid.NewV7()
    if err != nil {
        return ID{}, err
    }
    // ... independent 64-bit Serial via crypto/rand still applies ...
    return ID{UUID: id.String(), Serial: ...}, nil
}
```

**Why the swap is justified:** UUID generation is a small but real
crypto-adjacent surface — the bit-twiddling for the version/variant
nibbles is exactly the kind of detail that's been wrong in third-party
UUID implementations before (`uuid[6] & 0x0f | 0x70` reads correctly
here, but a copy-paste of this pattern with `0xf0` instead of `0x0f` would
produce malformed UUIDs that silently pass type checks). `google/uuid` is
the same library AWS SDK and most of the Go ecosystem use; pulling it in
adds nothing to the binary size that we don't already get transitively
through other deps.

**Severity rationale:** MEDIUM rather than HIGH because (a) the current
implementation is correct on inspection, (b) a malformed UUID here doesn't
break security (only affects JTI display and DB key correlation), and
(c) adding a new direct dep is friction even when it's a battle-tested
one. But the UUIDv7 bit-twiddling is exactly the kind of thing the
"never hand-roll crypto-adjacent" rule covers.

**Note:** the LD log doesn't surface a prior decision to hand-roll this;
the function is small enough that the architect-layer reasoning may have
been "it's just bit-twiddling" — which is the same kind of reasoning
LD-79 used for the JWS hand-roll and LD-90 corrected.

### F-HR-M2 — `internal/tokenstore/file.go` re-implements atomic file write

**Location:** `internal/tokenstore/file.go`, `Save` method (~lines 52-96).

**What's hand-rolled:** Manual write-temp → chmod → close → rename
sequence with cleanup-on-error. This is **byte-for-byte the same shape**
as `internal/atomicfile.WriteFile`, which exists in this repo for this
exact purpose and is consumed by `internal/certcache` and
`internal/sshconf`.

**Library that replaces it:** `internal/atomicfile` (already in this repo).

```go
// Save (simplified):
if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
    return err
}
if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
    return err
}
data, err := encodeState(state)
if err != nil {
    return err
}
return atomicfile.WriteFile(path, data, 0o600)
```

**Why the swap is justified:** Code duplication of an in-repo helper that
already has the documented atomic-write contract (per its package comment:
"A partial-write or panic before the rename leaves the temp behind but
never touches the destination path."). The hand-roll here predates the
extraction of `internal/atomicfile`, and the two implementations have
already drifted slightly (the file.go version doesn't have the
documented panic-safety story, just the error-path cleanup).

**Severity rationale:** MEDIUM — not a crypto-adjacent issue, but the
same "library exists, use it" principle applies. Worth fixing on the
next time someone is in this file; not standalone-urgent.

## Low

### F-HR-L1 — `internal/broker/id.go` hex-formats UUID via `fmt.Sprintf`

**Location:** `internal/broker/id.go` line 62:

```go
UUID: fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
```

**What's hand-rolled:** UUID canonical-string rendering via
`fmt.Sprintf`. Subsumed by F-HR-M1 if that swap happens (`google/uuid`
provides `.String()`). If F-HR-M1 is deferred, this still works correctly
because `%x` of an even-length byte slice produces fixed-width
lowercase hex.

**Library that replaces it:** Same as F-HR-M1, or
`encoding/hex.EncodeToString` with `+ "-" +` joins if hand-roll-with-
stdlib is preferred.

**Why the swap is justified:** Subsumed by F-HR-M1.

**Severity rationale:** LOW because the current code is correct; only
flagged because it pairs with M1.

## Info

### F-HR-I1 — `internal/sshconf/writer.go` is a hybrid begin/end-marker writer, not a generic ssh_config writer

**Location:** `internal/sshconf/writer.go` (entire file).

**What's done:** ~360 LoC of begin-marker / end-marker stanza upsert
machinery — `Upsert`, `Remove`, `List`, `replaceOrAppendStanza`,
`dropStanza`, line-anchored substring search via `indexLineStart`,
blank-line trim helpers.

**Why NOT a hand-roll concern:** `golang.org/x/crypto/ssh` provides
**only** the `ssh.ParseAuthorizedKey` / `ssh.MarshalAuthorizedKey` /
`ssh.ParseKnownHosts` surface — it does **not** ship an `ssh_config`
parser or writer. The community `github.com/kevinburke/ssh_config`
exists, but its data model is "parse a full ssh_config and modify the
AST in memory" which doesn't match this package's contract ("preserve
user-owned content outside marker brackets verbatim, idempotently
upsert stanzas inside brackets"). Adopting it would mean re-rendering
the engineer's entire `~/.ssh/config` from a parsed AST, which is
exactly the trust-boundary the marker-bracket design exists to avoid.

The package comment already names this: `sshconf` is not part of the
wrapping contract; the hybrid-file shape is the documented design
constraint. Leave as-is.

### F-HR-I2 — `internal/registry/http.go` hardcodes SHA-256 of empty string for SigV4 payload hash

**Location:** `internal/registry/http.go` line 22:

```go
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

**What's done:** Hardcoded hex of `SHA-256("")`. Used as the
`payloadHash` arg to `v4.Signer.SignHTTP` for GET requests with no
body.

**Why NOT a hand-roll concern:** AWS SigV4's `SignHTTP` requires the
caller to pass the pre-computed payload hash; the empty string's
SHA-256 is a single constant operators document and `aws-sdk-go-v2`
itself uses the same literal. Computing it every call via `sha256.Sum256(nil)`
would be marginally less efficient and exactly as opaque. The hardcoded
value is the idiom AWS SDK examples use. Leave as-is.

### F-HR-I3 — Multiple call sites do `base64.RawURLEncoding.DecodeString` on the timefix nonce

**Location:** `cmd/timefix-apply/main.go:113` (encode),
`internal/broker/issuetimepayload.go:143` (decode),
`pkg/cliapp/timefix.go:241` (decode).

**What's done:** `encoding/base64` from stdlib. This is the stdlib
function — not a hand-roll.

**Why NOT a hand-roll concern:** `base64.RawURLEncoding` is the right
stdlib idiom; there's no library that does this "better." The
three-site duplication of the 32-byte-decoded-length check is a code
hygiene observation (DRY), not a hand-roll. Out of scope for this
audit. Leave as-is.

## Methodology

Walked every production `.go` file under `internal/`, `pkg/`, `cmd/`
(excluding `_test.go`) — 35 files. For each file, inspected:

- All `import` blocks for the libraries listed in `go.mod`.
- All `crypto/*`, `encoding/*`, `net/*` stdlib imports for hand-roll
  candidates.
- All `*_test.go`-free uses of `strings.Split`, `strings.SplitN`,
  `bytes.Split`, manual byte parsing.
- All `sync.Mutex` / `sync.RWMutex` / `sync.Once` / `sync/atomic`
  usage (only one found — `certcache.Store.keyMu` — used correctly).
- All `os.CreateTemp` + `os.Rename` patterns (atomic-write
  candidates for `internal/atomicfile`).
- All `fmt.Sprintf` calls that build wire-format strings (hex, UUID,
  JWT, base64).
- All `crypto/rand`, `math/rand`, `math/rand/v2` usage (only
  `crypto/rand` found — correct for the use sites).
- All `time.Time` manipulation patterns (no string-based time math,
  all use `time.Time` directly — clean).

Cross-checked LD-90/LD-91 to confirm the JWS construction/verification
swap is already in place and that the audit isn't catching a finding the
architect has already addressed.

Out-of-scope per the task statement: `*_test.go`, the Terraform module,
the `examples/` directory.
