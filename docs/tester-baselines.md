# Tester baselines — Postern

> Last gate's exact counts + flake registry. Tester updates at end of each
> dispatch, reads on every spawn for cross-check vs reviewer's independent re-run.
> Flake registry classifies flakes — never used to mask them by retry.

## Last gate

**Sub-phase:** setup-ssh (new staged `setup-ssh` command + tests, `add-host
--check` removal, docs; `git diff --cached`, 8 files)
**Date:** 2026-06-09
**Test command:** `go clean -testcache && make check` (then `make check` again, cached)
**Result:** GREEN, reproducible. Both vet passes clean; `-race ./...` all pass;
tagged timefix-apply pass green. 2nd run identically green, fully cached — no
flakes, no goleak failures, no order-dependence.
**Packages passing (21, count stable — setup-ssh touched only pkg/cliapp for
Go):** cmd/timefix-{set-clock,apply(tagged)}, 17× internal/*,
pkg/{brokerhandlers, cliapp}.
**Net test delta (authoritative, via `git diff --cached`): +5 funcs / -2
funcs.** Added: setup_ssh_test.go +5 (TestSetupSSH{PrependsInclude,Idempotent,
CreatesDirAndFile,CheckPresent,CheckAbsent}). Removed: addhost_test.go -2
(TestAddHostCheckFlag{Present,Absent}, the `add-host --check` path) + 1
assertion retargeted (Include-line hint → `setup-ssh` hint).

**Warnings triaged:** none.

**Prior gates:** client-auth/G (2026-06-09) GREEN, +1 func/+3 cases (strict env
decode); F (2026-06-08) GREEN, 2 new funcs; E 8; D 8; C 0; B 7; A 13.

## Integration / target counts

N/A — no on-device / hardware suite. timefix verifier runs in-process under
the `timefix_test_path` tag.

## Flake registry

None observed.

| date | test | failure mode | sibling tests affected |
|------|------|--------------|------------------------|
| — | — | — | — |
