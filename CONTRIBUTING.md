# Contributing

Postern is an Apache-2.0 open-source project. Contributions of any size — bug reports, design discussion, code, doc edits — are welcome.

## Before you open a PR

- Read [`DESIGN.md`](DESIGN.md) end-to-end. It captures the why behind every load-bearing decision. New design proposals belong as PRs against `DESIGN.md` before they land as code.
- For non-trivial changes, open an issue first to discuss the shape. Postern is intentionally narrow in scope (DESIGN.md §"What goes here vs elsewhere"); features that don't fit the embedded-device-fleet-SSH frame are usually better as a downstream wrapper.
- Run `make check` locally. The CI matrix runs the same command on Ubuntu and macOS; passing locally first catches almost all CI failures.

## Running tests

`make check` is the canonical command. It runs `go test -race ./...` plus a second pass of `cmd/timefix-apply/` with the `timefix_test_path` build tag set.

The verifier in `cmd/timefix-apply/` has its entire test suite gated behind that tag because the env-var CA-pubkey override seam (`POSTERN_TIMEFIX_CA_PUB`) is compiled in only under the tag — production binaries don't carry the override path, so a hostile sshd misconfiguration can't redirect verification to an attacker-controlled CA pubkey. See `cmd/timefix-apply/capubpath_testbuild.go` for the rationale.

**If you run raw `go test ./...`** (e.g. from an IDE):

- `cmd/timefix-apply/` appears as `[no test files]` because every test file in the package is tagged.
- A `TestMain` in an untagged file prints a one-line reminder when the tag isn't set.
- Add `-tags timefix_test_path` to the run to exercise the verifier suite: `go test -tags timefix_test_path ./cmd/timefix-apply/...`.
- IDE users (VS Code, GoLand): set the build tag in your Go-test config so the verifier tests appear in the test explorer.

## Commit message format — Conventional Commits

Postern uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) so [`release-please`](https://github.com/googleapis/release-please) can auto-generate the changelog and pick the next version on merge to `main`. The shape is:

```
<type>(<optional scope>): <short summary>

<optional body>

<optional footer>
```

**Types that matter for releases:**

| Type | Triggers | Examples |
|---|---|---|
| `feat:` | Minor bump (or patch pre-1.0 per config) | `feat(cli): add postern cache prune subcommand` |
| `fix:` | Patch bump | `fix(certcache): handle EEXIST race on first-mint key creation` |
| `perf:` | Patch bump | `perf(broker): cache KMS GetPublicKey response across requests` |
| `deps:` | Patch bump | `deps: bump aws-sdk-go-v2 from 1.41.7 to 1.42.0` |
| `feat!:` or `BREAKING CHANGE:` footer | Major bump | `feat!: rename --tunnel to --via-tunnel` |

**Types that are merged but don't bump the version:**

| Type | Use for |
|---|---|
| `docs:` | README / DESIGN.md / inline-doc-only edits |
| `refactor:` | Code reorganization with no behavior change |
| `test:` | Test additions / fixes that don't change production behavior |
| `build:` | Makefile / go.mod / build system changes |
| `ci:` | GitHub Actions / release tooling changes |
| `chore:` | Anything else not user-facing |

**Squash-merge convention:** if the PR is squash-merged, the squash subject line is the one release-please reads. Make sure that subject follows the Conventional Commits format even if individual commits in the PR don't. Maintainers will normalize the squash subject at merge time when needed.

## How releases happen

1. PRs land on `main` with Conventional Commit subjects.
2. The `release-please` GitHub Action keeps an open PR titled `chore(main): release <next-version>` that summarizes the pending changelog and version bump.
3. When you're ready to ship, merge that PR. Release-please creates the `vX.Y.Z` tag.
4. The tag push fires the `release` workflow, which runs GoReleaser to build the platform matrix and publish a GitHub Release with binaries attached.

The first release of this project (`v0.1.0`) is bootstrapped manually with `git tag v0.1.0 && git push --tags`. From `v0.1.1` onward, release-please drives the cadence.

## Things that are out of scope

- Adding a second concrete implementation of any abstraction (IdP, Signer, Tunneling, Audit, Registry, Policy, RateLimit) without a real downstream user requesting it. v1 ships one impl per abstraction by design; speculative second impls bake the first impl's assumptions into the interface. See `AGENTS.md` §"One concrete impl per abstraction in v1".
- Organization-specific or vendor-specific code. Postern is intentionally generic; brand or org-specific bits belong in downstream wrappers, not in this repo.
- Features beyond what `DESIGN.md` describes. Design proposals are welcome as PRs against `DESIGN.md`; they should not arrive bundled with code that implements them.

## Reporting security issues

Don't file security issues as public GitHub issues. Use GitHub's private vulnerability reporting on this repo until a dedicated `SECURITY.md` lands.
