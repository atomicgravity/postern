# Hand-rolled-vs-library audit — post-sweep (pass 2, 2026-05-14)

Single-question audit, second pass: **are we hand-rolling things a battle-tested
library does better?** First pass at `docs/audit-post-timefix/hand-rolled.md`
identified F-HR-H1 / F-HR-M1 / F-HR-M2 (plus three INFO observations). The
sweep then closed all three. This pass:

1. Verifies the three closures are clean (library choice, idiomatic usage,
   no regressions introduced).
2. Re-walks production code for any additional hand-rolls the first pass
   missed, with focus on the orchestrator's named-attention areas
   (`internal/sshconf/`, `internal/atomicfile/`, `internal/broker/id.go`
   post-sweep, `pkg/brokerhandlers/` bearer/body-cap/JSON, `internal/brokerclient/`,
   `cmd/timefix-set-clock/`, `cmd/timefix-apply/`).

## Summary

Scope: `internal/`, `pkg/`, `cmd/` excluding `_test.go`. Read every
production file under those trees (39 files).

Prior-pass closures verified: **all three clean**. No regressions found.

New findings: 5

- HIGH: 0
- MEDIUM: 2 (configure-time YAML write bypasses atomicfile; certcache key
  writer duplicates atomicfile temp/link)
- LOW: 1 (timefix tempfile in `pkg/cliapp/timefix.go` does not use
  `os.WriteFile` / atomicfile)
- INFO: 2 (broker JTI generated even on handler-denial paths; `bearerToken`
  hand-roll is intentional)

The codebase remains in good shape on this dimension. The biggest crypto-
adjacent concerns (JWS construction/verification, JWT-exp read, UUIDv7
generation) are now library-driven on every code path. Remaining findings
are write-path durability hygiene rather than crypto exposure.

## Prior-pass closure status

### F-HR-H1 (CLI access-token JWT-exp parse) — CLOSED, clean

`internal/oauthlogin/token.go:180-199` (`accessTokenExpiry`) now uses
`github.com/go-jose/go-jose/v4` `jwt.ParseSigned` +
`UnsafeClaimsWithoutVerification`. The accepted-algorithm list is broad
(HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512, EdDSA) — the
in-code rationale (lines 172-179) makes the call out explicitly: this is a
CLI-side expiry-read on a token the broker is the authoritative verifier
for, so the broker's asymmetric-only pin (F-SEC-M1) is what closes the
algorithm-confusion attack at decision time. Including symmetric algs here
does not weaken the broker's posture; it only widens the set of tokens the
CLI can decide to refresh-or-reuse without forcing a re-login on tokens
the broker would reject anyway.

The library's parse-shape and base64url validation now sits in front of
every previously hand-rolled `strings.Split` / `base64.RawURLEncoding.DecodeString`
/ `json.Decoder` call site, eliminating the parser/serializer differential
surface the original finding flagged. **Closure clean.**

### F-HR-M1 (UUIDv7 hand-roll) — CLOSED, clean

`internal/broker/id.go` now uses `github.com/google/uuid` (`v1.6.0` per
go.mod, the version that ships UUIDv7). The hand-rolled bit-twiddling
(version nibble, variant nibble, timestamp splice, `fmt.Sprintf` rendering)
is gone — replaced by a single `uuid.NewV7()` call followed by `.String()`
for the canonical-form output. Independent 64-bit Serial generation via
`crypto/rand` is preserved (the documented reason — UUIDv7's first 48 bits
are the timestamp, leaving too few random bits for KRL-collision-safety —
remains correct).

The package-doc comment now names `google/uuid` as the source of truth and
documents why the `now` parameter on `NewID` is preserved despite
`uuid.NewV7()` reading time internally (interface alignment with the
broker pipeline's single-`now` capture). **Closure clean.** The
subsumed F-HR-L1 (hex-format via `fmt.Sprintf`) is naturally closed too —
`.String()` does it now.

### F-HR-M2 (tokenstore atomic-write duplication) — CLOSED, clean

`internal/tokenstore/file.go:54-73` (`Save`) now delegates to
`atomicfile.WriteFile`. The hand-rolled temp/chmod/close/rename sequence
plus cleanup-on-error is gone. The remaining code in `Save` is just the
parent-directory `MkdirAll` + `Chmod`, the `encodeState` call, and the
single `atomicfile.WriteFile(path, data, 0o600)` invocation. The package
doc comment (lines 50-53) names the swap explicitly:

> The on-disk write goes through internal/atomicfile (temp-file + os.Rename)
> so a process killed mid-write never leaves a zero-length or partially
> written file behind.

**Closure clean.**

## High

(none)

## Medium

### F-HR2-M1 — `pkg/cliapp/config.go` SaveConfigFile bypasses atomicfile

**Location:** `pkg/cliapp/config.go:41-56` (`SaveConfigFile`).

**What's hand-rolled:** Direct `os.OpenFile(path, O_WRONLY|O_CREATE|O_TRUNC, 0o600)`
then YAML encoder writes to it, then `file.Chmod(0o600)` at the end. No
write-temp + rename pattern; a process killed between `O_TRUNC` and the
final YAML encoder flush leaves the config file truncated or partial. This
is the engineer-facing config file for the `postern configure` subcommand
— a partial write here means the engineer's next `postern` invocation
fails to parse and they have to re-author the file from scratch.

**Library that replaces it:** `internal/atomicfile.WriteFile` — exactly
the same shape as the F-HR-M2 closure on `tokenstore.File.Save`.

```go
// SaveConfigFile (rewrite shape):
if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
    return err
}
var buf bytes.Buffer
if err := SaveConfig(&buf, config); err != nil {
    return err
}
return atomicfile.WriteFile(path, buf.Bytes(), 0o600)
```

**Why the swap is justified:** F-HR-M2's reasoning applies verbatim. The
atomicfile helper exists in this repo with the documented
crash-safety contract; bypassing it on a config-write path that an
engineer-facing subcommand depends on is the same duplication shape that
F-HR-M2 closed for `tokenstore.File.Save`. The fact that this duplication
slipped through after F-HR-M2's swap is the textbook reason to make the
helper the obvious-default path.

**Severity rationale:** MEDIUM — not crypto-adjacent, but the
"library exists, use it" principle the user named applies, and the user-
visible failure mode (engineer has to re-author their config) is bad
enough that this isn't INFO. Same severity as F-HR-M2 by direct analogy.

### F-HR2-M2 — `internal/certcache/cache.go` writeProfileKeyExclusive re-implements temp/link

**Location:** `internal/certcache/cache.go:335-371` (`writeProfileKeyExclusive`).

**What's hand-rolled:** `os.CreateTemp` → `tempFile.Write` → `tempFile.Chmod` →
`tempFile.Close` → `os.Link(tempPath, path)` + cleanup-on-error. This is
structurally `atomicfile.WriteFile` but with `os.Link` instead of
`os.Rename` so the EEXIST race-loser path can be detected via
`errors.Is(err, os.ErrExist)`. The package-doc on `atomicfile`
(lines 6-7) even names this variant:

> the standard write-temp-then-rename POSIX pattern… (or os.Link, for
> the exclusive variant) used to publish the final path.

But the package only exports `WriteFile` (rename-based); the link-based
exclusive variant is documented in the package doc but not exported —
so certcache hand-rolls the whole sequence to get exclusivity.

**Library that replaces it:** Extend `internal/atomicfile` with a second
exported function (e.g. `WriteFileExclusive(path, data, mode)`) that
performs the same temp-write but publishes via `os.Link`, returning the
underlying error so callers can `errors.Is(err, os.ErrExist)` to detect
the race-loser path. The two production callers (`certcache` here, and
any future first-write-wins use case) get the same crash-safety + perm-
setting contract as the rename-based helper without re-implementing the
temp-cleanup machinery each time.

```go
// In internal/atomicfile:
func WriteFileExclusive(path string, data []byte, mode os.FileMode) error {
    // ... same temp-write + chmod + close ...
    if err := os.Link(tempPath, path); err != nil {
        cleanup()
        return err // caller errors.Is(err, os.ErrExist) for race-loser
    }
    cleanup()
    return nil
}

// In certcache:
if err := atomicfile.WriteFileExclusive(keyPath, pemBytes, 0o600); err != nil {
    if errors.Is(err, os.ErrExist) {
        return loadProfileKey(keyPath)
    }
    return nil, nil, err
}
```

**Why the swap is justified:** The package doc on `atomicfile` already
calls out that the package owns both variants ("rename or link"); the
fact that the link variant isn't exported is the reason this hand-roll
exists. Extending atomicfile to ship both variants closes the duplication
and gives the package-doc claim a public function to point at.

**Severity rationale:** MEDIUM — same shape and severity as F-HR-M2.
Not crypto-adjacent in the alg-confusion sense, but the crash-safety
contract is exactly what the package was written to centralize, and
certcache's hand-roll is now the only remaining open-coded temp/link
in the tree post-F-HR-M2.

## Low

### F-HR2-L1 — `pkg/cliapp/timefix.go` writeTimefixCertTempfile open-codes temp+chmod+write

**Location:** `pkg/cliapp/timefix.go:206-230` (`writeTimefixCertTempfile`).

**What's hand-rolled:** `os.CreateTemp("", timefixCertTempPrefix)` →
`tempFile.Chmod(0o600)` → `tempFile.WriteString(sshCert)` →
`tempFile.Close()` + per-step cleanup. The destination is a tempfile
(not a stable named path), so atomicfile's write-temp-rename-into-place
pattern doesn't directly apply: the tempfile IS the final path, consumed
once by the per-invocation `ssh -o CertificateFile=...` call.

**Library that replaces it:** Not directly substituted by atomicfile.
The stdlib alternative is `os.WriteFile` after `os.CreateTemp` (drop
the file handle, just keep the path):

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

— shorter, single error path, and the 0o600 mode is set by `WriteFile`
directly on the open call. The current pattern is correct but verbose
relative to what the stdlib offers.

**Why the swap is justified:** Code clarity, not safety. The hand-roll
isn't structurally wrong (every error path cleans up the temp; the file
mode is set before content lands), it's just three calls and three
error-handler branches where one call would do. Worth tightening when
someone is next in this file; not standalone-urgent.

**Severity rationale:** LOW — verbosity vs. correctness. No
crash-safety or crypto-adjacent concern; the existing code's only
real cost is the extra branches.

## Info

### F-HR2-I1 — `bearerToken` hand-roll in `pkg/brokerhandlers/handlers.go` is intentional

**Location:** `pkg/brokerhandlers/handlers.go:293-303` (`bearerToken`).

**What's done:** Manual RFC 6750 "Bearer " prefix check via
`strings.EqualFold(header[:len(scheme)], scheme)` + `strings.TrimSpace`
on the remainder, with a stable error message.

**Why NOT a hand-roll concern:** The package's existing comment
(lines 287-292) names the design choice explicitly:

> Strict: requires the literal "Bearer " prefix (case-insensitive on the
> scheme name, one ASCII space, non-empty token after it). strings.Fields
> would accept arbitrary Unicode whitespace and folded headers — that's a
> header-smuggling primitive against any downstream filter that doesn't
> agree with Go on what counts as whitespace.

There is no stdlib helper for "RFC 6750 Bearer parser, strict on whitespace";
`net/http`'s `Request.BasicAuth` is the only sibling but it's Basic-auth
specific. Pulling in a third-party RFC-6750-strict parser would be more
risk than the dozen-line stdlib call site it replaces. Leave as-is.

### F-HR2-I2 — `RecordHandlerDenial` / `RecordTimePayloadHandlerDenial` mint a JTI via the IDGenerator

**Location:** `internal/broker/sshcert.go:344-365` and
`internal/broker/issuetimepayload.go:298-320`.

**What's done:** Both handler-denial recorders call
`i.deps.IDs.NewID(now)` to get a JTI for the audit row. Now that the
generator is `google/uuid`-backed, this trivially gets a fresh
UUIDv7 for every pre-pipeline denial.

**Why NOT a hand-roll concern:** Both functions discard the error
silently (`if id, err := i.deps.IDs.NewID(now); err == nil { jti = id.UUID }`)
and continue with `jti = ""` on failure. This was reasonable when the JTI
generator was an in-process crypto/rand reader — even with crypto/rand
exhausted, the audit emit was still worth attempting. Under
`uuid.NewV7()` the failure mode is `rand.Reader` exhaustion which is
effectively never going to happen in production; the silent-discard
remains correct. Not a hand-roll, but worth noting as a follow-up
hygiene observation: the silent-discard could log-and-continue rather
than just continue. Out of scope for this audit; flag for a future
quality pass.

## Methodology

Walked every production `.go` file under `internal/`, `pkg/`, `cmd/`
(excluding `_test.go`) — 39 files. For each file, inspected:

- All `import` blocks for the libraries listed in `go.mod` to look for
  hand-roll candidates a known dep would cover.
- All `crypto/*`, `encoding/*`, `net/*` stdlib imports.
- All `strings.Split`, `strings.SplitN`, `bytes.Split`, manual byte
  parsing (only one production hit — splitting comma-separated env in
  `pkg/brokerhandlers/config.go`, which is correct stdlib usage).
- All `sync.Mutex` / `sync.RWMutex` / `sync.Once` / `sync/atomic` (only
  one — `certcache.Store.keyMu`, used correctly).
- All `os.CreateTemp` + `os.Rename` / `os.Link` patterns (atomicfile
  candidates).
- All `fmt.Sprintf` calls that build wire-format strings (hex, UUID,
  JWT, base64) — all current uses are user-facing diagnostic strings
  or trivial address rendering, no wire-format hand-rolls remain.
- All `crypto/rand`, `math/rand`, `math/rand/v2` usage (only
  `crypto/rand` found — correct for the use sites).
- All `time.Time` manipulation patterns — every use is `time.Time`,
  `time.Unix`, `time.Parse(time.RFC3339, ...)`, or
  `time.ParseDuration`. No string-based time math, no DIY duration
  parsing.

Specifically re-verified for this pass:

- `internal/oauthlogin/token.go` — F-HR-H1 closure confirmed.
- `internal/broker/id.go` — F-HR-M1 closure confirmed.
- `internal/tokenstore/file.go` — F-HR-M2 closure confirmed.
- `cmd/timefix-apply/verify.go` — post-LD-90/LD-91, the JWS parse +
  verify path is all go-jose. No regressions; the per-line comments
  walk the alg-pin + typ-check + library-driven verify sequence cleanly.
- `cmd/timefix-set-clock/syscalls_linux.go` — RTC ioctl uses
  `unix.IoctlSetRTCTime` (`golang.org/x/sys/unix`) and
  `unix.ClockSettime`. No raw syscall numbers, no manual ioctl encoding;
  the `unix.RTCTime` field population (Mon = month-1, Year = year-1900,
  Yday = year-day-1) matches `linux/rtc.h`'s `struct rtc_time` contract
  exactly. Clean.
- `internal/sshconf/writer.go` — hybrid begin/end-marker writer reaffirmed
  as the right shape; `kevinburke/ssh_config` is not the right library
  here (its AST-rewrite model doesn't match the hybrid-file contract this
  package owns).
- `pkg/brokerhandlers/handlers.go` — bearer parse rationale is documented
  and the strictness is load-bearing; body cap (`http.MaxBytesReader`,
  64KB) is stdlib-correct; JSON decoder uses `DisallowUnknownFields`.
- `internal/brokerclient/client.go` — HTTP client is stdlib `net/http`;
  no hand-rolled retry, no hand-rolled SigV4; URL composition via
  `net/url`.

Out-of-scope per the task statement: `*_test.go`, the Terraform module,
the `examples/` directory.
