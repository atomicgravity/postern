# Tester baselines — Postern

> Last gate's exact counts + flake registry. Tester updates at end of each
> dispatch, reads on every spawn for cross-check vs reviewer's independent re-run.
> Flake registry classifies flakes — never used to mask them by retry.

## Last gate

**Sub-phase:** broker-aud-scope (staged `internal/idp/oidc.go` +
`internal/idp/oidc_test.go`; `git diff --cached`, 2 files)
**Date:** 2026-06-09
**Test command:** `go clean -testcache && make check` (then `make check` again, cached)
**Result:** GREEN, reproducible. Both vet passes clean; `-race ./...` all pass;
tagged timefix-apply pass green. 2nd run identically green, fully cached — no
flakes, no goleak failures, no order-dependence.
**Packages passing (21, count stable — only internal/idp touched for Go):**
cmd/timefix-{set-clock,apply(tagged)}, 17× internal/*, pkg/{brokerhandlers,
cliapp}.
**Net test delta (authoritative, via `git diff --cached`): +3 funcs.** Added:
TestVerifyAccessToken{AudienceScopeOR (20 named sub-cases: aud-only/scope-only/
both/cross-app/aud-multi/or-no-bypass tables), ExactScopePrecision (4 sub-cases:
prefix+suffix collide, multi-scope-string, scp-array match), FailsClosedWhen
NeitherConfigured}. 24 table `name:` cases + 2 top-level `t.Run` groups. Tables
use `wantAccept bool`/`wantSub`; REJECT cases (wrong-aud, cross-app, none-match,
all or-no-bypass, prefix/suffix-collide, fail-closed) verified as real
`t.Fatal`-on-nil-error assertions under `-v -race`, not skips.

**Warnings triaged:** none.

**Prior gates:** setup-ssh (2026-06-09) GREEN, +5/-2 funcs; client-auth/G
(2026-06-09) GREEN, +1 func/+3 cases; F (2026-06-08) GREEN, 2 funcs; E 8; D 8;
C 0; B 7; A 13.

## Integration / target counts

N/A — no on-device / hardware suite. timefix verifier runs in-process under
the `timefix_test_path` tag.

## Flake registry

None observed.

| date | test | failure mode | sibling tests affected |
|------|------|--------------|------------------------|
| — | — | — | — |
