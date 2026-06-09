# Tester baselines — Postern

> Last gate's exact counts + flake registry. Tester updates at end of each
> dispatch, reads on every spawn for cross-check vs reviewer's independent re-run.
> Flake registry classifies flakes — never used to mask them by retry.

## Last gate

**Sub-phase:** client-auth/G (strict env decode + predicate edge tests;
uncommitted working-tree diff on feat/client-auth)
**Date:** 2026-06-09
**Test command:** `go clean -testcache && make check` (then `make check` again, cached)
**Result:** GREEN, reproducible. Both vet passes clean; `-race ./...` all pass;
tagged timefix-apply pass green. 2nd run identically green, fully cached (19/19
ok cached) — no flakes, no goleak failures, no order-dependence.
**Packages passing (19, count stable — G touched only pkg/brokerhandlers +
internal/idp, both existing):** cmd/timefix-{set-clock,apply(tagged)}, 15×
internal/*, pkg/{brokerhandlers, cliapp}.
**New G tests — 1 top-level func + 3 table cases** (authoritative, via
`git diff`): config_test.go +1 func
TestLoadResolvedConfigRejectsUnknownKeyPrincipalClassesEnv (strict
KnownFields(true) rejects typo'd `default` key); oidc_test.go +3 cases in the
existing TestClassifyEvaluatesPredicateForms table (empty-string/empty-array
treated absent; present does not match empty-string). config.go = strict
yaml.NewDecoder + KnownFields(true) for POSTERN_IDP_PRINCIPAL_CLASSES.

**Warnings triaged:** none.

**Prior gates:** F (2026-06-08) GREEN/reproducible, 19 pkgs, 2 new funcs
(pkg/brokerhandlers env principal-classes); E 8 funcs; D 8; C 0; B 7; A 13.

## Integration / target counts

N/A — no on-device / hardware suite. timefix verifier runs in-process under
the `timefix_test_path` tag.

## Flake registry

None observed.

| date | test | failure mode | sibling tests affected |
|------|------|--------------|------------------------|
| — | — | — | — |
