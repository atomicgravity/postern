# Postern

SSH access framework for embedded Linux device fleets.

## What this is

If you ship connected hardware (medical devices, robots, industrial IoT, lab instruments, kiosks) and your engineers need diagnostic SSH to those devices in the field, you have a recurring problem: short-lived SSO-gated SSH access for devices that may be offline, behind customer firewalls, with broken clocks. Off-the-shelf SSH access platforms (Teleport, HashiCorp Boundary) are designed for server fleets and don't fit. Most companies build a one-off internal tool.

Postern is that tool, factored as a reusable framework:

- A **cloud broker** that mints short-lived SSH certificates scoped to specific devices, gated by corporate SSO. Ships as both a long-running HTTP server (`cmd/broker`) and an API-Gateway-fronted Lambda (`cmd/broker-lambda`); the v1 Terraform reference uses the Lambda path.
- An **engineer CLI** (`postern`) that handles SSO login, certificate caching, secure-tunnel orchestration, and `ssh` / `scp` invocation.
- Two **on-device binaries** for fixing broken device clocks via a privilege-split forced-command path.
- **Pluggable abstractions** for the parts that vary by deployment (IdP, signing key storage, secure tunneling, audit log sink, device-identity registry) — with focused concrete implementations shipped in v1. The Registry includes a DynamoDB-backed default and an HTTP-backed option for existing inventory services.

The full design rationale is in [`DESIGN.md`](DESIGN.md). Read that first.

## Goals

- Embedded-device-fleet-first (not server-fleet)
- Short-lived certs, SSO-gated, auditable end-to-end
- Works for devices that may be offline, firewalled, or have broken clocks
- Single static binaries on every side, minimal runtime dependencies
- Designed to be wrapped by downstream operators with their own tooling on top, without forcing them to fork

## Non-goals

- Not a replacement for full SSH access platforms like Teleport. Postern is lighter and embedded-specific.
- Not centralized device management or fleet operations beyond SSH access.
- Not session-content recording (designed-in path for adding it, but log-only audit is the default).

## Using Postern (engineer quick start)

Assumes your operator has already stood up the broker, your laptop's `~/.postern/config.yaml` has the broker / IdP details (see [Setting it up](#setting-it-up) below if not), and the device side is wired (Postern CA pubkey in `authorized_keys`, the `engineer` and `timefix` users, the timefix binaries — also covered below).

Download the latest `postern` binary for your platform from the [Releases page](https://github.com/atomicgravity/postern/releases) and put it on your `PATH`.

### Daily

```sh
postern login   # once per ~8h SSO session
```

### Two flows — pick whichever fits the moment

**Ad-hoc** — for one-off access to a device you haven't registered:

```sh
postern ssh widget-042 root@192.168.120.119
postern scp widget-042 ./payload.tar.gz root@192.168.120.119:/tmp/
```

The device id (`widget-042`) tells the broker which device to mint a cert for; the `root@192.168.120.119` part is the actual ssh destination. You type the IP and user each time. Postern handles cert mint + reuse transparently.

**Registered** — for devices you'll touch more than once (recommended):

```sh
postern add-host widget-042 --ip 192.168.120.119 --user root      # once per device
postern ssh widget-042                                            # cert auto-minted + reused
```

After `add-host`, you don't need to remember the IP or the username — both live in the Postern-managed `~/.postern/ssh.conf` stanza. The first `postern ssh widget-042` mints on demand; subsequent calls reuse the cached cert until it expires.

The bigger payoff: **vanilla ssh-aware tools now work too**, as long as the cert is fresh. After running `postern mint widget-042` once (or after any `postern ssh` that already minted), every ssh-aware tool finds the device natively:

```sh
ssh widget-042                          # no IP, no user@, no `postern` prefix
scp ./payload.tar.gz widget-042:/tmp/
rsync ./data/ widget-042:/srv/data/
git push widget-042:/srv/repo.git main
sftp widget-042
```

VSCode Remote-SSH "Connect to Host..." → `widget-042` → just works. Same goes for Cursor, JetBrains Gateway, and any other tool that reads `~/.ssh/config`. (Run `postern setup-ssh` once to wire the Include into your `~/.ssh/config`; `postern setup-ssh --check` reports whether it's wired.)

You can `add-host` as many devices as you like — they each get their own cert and stanza. Pick the right one with the device id; `postern ssh` (and the cached certs vanilla ssh uses) routes correctly.

### Renewing certs

Postern certs are short-lived (a few hours). `postern login` keeps your SSO session alive (~8h); `postern ssh` / `postern scp` / `postern add-host` mint certs on demand whenever the cached one is missing or near expiry, so if those are your daily drivers you don't have to think about it.

If your daily driver is **vanilla ssh / scp / rsync / VSCode-Remote-SSH** (the registered-flow payoff), you do need to refresh the cert yourself once it expires — vanilla tools don't know to call postern. The daily move:

```sh
postern login                                       # once per SSO session
postern mint widget-042                               # once per device per day; refreshes the cached cert
ssh widget-042                                        # then use vanilla tooling all day
```

You can `postern mint` several devices in a row; each goes into the per-device cache. As long as the cert is fresh, every ssh-aware tool finds the device.

### Headless / remote hosts

Running Postern on a remote server, container, or jumphost — somewhere without a local browser or a usable OS keychain — needs two adjustments:

**No local browser.** Pass `--no-browser` to `postern login`. The CLI skips launching a browser and instead prints the authorization URL plus the exact `ssh -L` line to forward the loopback callback port back to the machine where your browser lives:

```sh
ssh -L 50001:localhost:50001 remote-host   # forward the callback port
postern login --no-browser                 # on remote-host; open the printed URL on your laptop
```

The OAuth flow is otherwise identical (Authorization Code + PKCE, loopback callback). If the printed port isn't the one you forwarded, pin it up front with `--callback-port <n>` (must be one of the registered `50001-50010`).

**No keychain.** By default Postern stores tokens in the OS keychain (macOS Keychain / Linux Secret Service). On hosts where that's unreachable — D-Bus / Secret Service missing or blocked by AppArmor — switch to a per-profile JSON file under `~/.postern/tokens/` (mode `0600`). Either set it for the session:

```sh
export POSTERN_TOKEN_STORE=file
postern login --no-browser
```

…or pin it in `~/.postern/config.yaml` so you don't re-export it each session:

```yaml
default:
  broker: https://postern.example.com
  idp: { ... }
  token_store: file
```

Precedence is `POSTERN_TOKEN_STORE` env > `token_store` in config > keychain default — the env var wins so you can flip a config-pinned machine back to the keychain for one command. It's opt-in (not an automatic fallback) because the file backend writes your refresh token to disk readable by your own user.

### Automated tools / service accounts

CI jobs, schedulers, and other non-human callers authenticate with an OAuth2 client-credentials (service-account) grant instead of the browser SSO flow. Set `grant: client_credentials` in the profile and point `client_id` at the IdP's service-account (M2M) app client:

```yaml
default:
  broker: https://postern.example.com
  idp:
    issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_XXXXXXXXX
    client_id: <m2m-app-client-id>
    audience: https://postern.example.com   # or scopes:
    grant: client_credentials
```

The client **secret is never read from the config file** — it comes only from the `POSTERN_IDP_CLIENT_SECRET` environment variable:

```sh
export POSTERN_IDP_CLIENT_SECRET=...        # service-account secret; keep it out of YAML
postern login                               # validates the creds, prints the client identity
postern mint widget-042                       # browserless; re-mints on demand
ssh widget-042
```

This path is browserless (no callback port, no keychain) and caches no token: each invocation re-mints a fresh access token from the client_id + secret, so there's no refresh token and nothing is written to the token store. `postern login` is a credential check that prints the client identity; it persists nothing.

On the broker side the operator authorizes and audits these automated callers distinctly from humans. The broker classifies each caller into a **principal class** purely from the verified token's claims (no identity database, no live IdP lookup), exposes the class and the issuing `client_id` to policy, and can bound their certificate TTL per class — so a policy might, for example, let one specific service account mint only from a fixed source IP while denying all other machine callers. See [`DESIGN.md`](DESIGN.md) ("Principal classes") and the broker config's `idp.principal_classes` block.

### Firewalled devices (tunneling)

For devices you can't reach on the LAN — behind a customer firewall, NAT, or mobile network — Postern tunnels through AWS IoT Secure Tunneling. Three entry points:

```sh
postern ssh --tunnel widget-042                # one-shot interactive ssh
postern scp --tunnel widget-042 src dst        # one-shot file copy
postern tunnel widget-042                      # hold-open; use ssh widget-042.tunnel / scp /
                                             # VSCode-remote / rsync / etc. in another terminal
```

`postern tunnel` writes an ephemeral `<device>.tunnel` stanza alongside the persistent `<device>` block in `~/.postern/ssh.conf`, so direct-LAN access via `ssh widget-042` keeps working in parallel during a tunnel session. The hold-open command blocks until you `^C` it; the ephemeral stanza is cleaned up automatically.

All three commands accept `--max-lifetime <duration>` (Go duration string; capped at 12h per the AWS IoT ceiling). `postern tunnel` also accepts `--port-only` (skip the ssh.conf integration; print the loopback port and hold open).

### Broken clocks

If a device's clock is too far off to validate a normal cert, repair it first:

```sh
postern timefix widget-042                          # device is registered via add-host
postern timefix widget-042 --ip 192.168.120.119     # ad-hoc, no add-host stanza
```

`postern timefix` opens an SSH session to the device's `timefix` principal (a forced-command path bound to the on-device verifier), reads the device's nonce and clock snapshot, asks the broker for a signed JWS time payload bound to that pair, pipes the JWS back to the device, and the privileged setter applies the corrected timestamp. Progress goes to stderr by default; pass `--quiet` to suppress.

### Command reference

| Command | Purpose |
|---|---|
| `postern configure [--broker ... --idp-issuer ... --idp-client-id ... --idp-audience ...]` | Write `~/.postern/config.yaml` (or run with no flags to read the current config) |
| `postern login [--no-browser] [--callback-port <n>]` | SSO + cache access / refresh tokens (`--no-browser` for headless / remote hosts) |
| `postern ssh [--user <name>] [--tunnel] [--cert-max-lifetime <dur>] <device> [user@]<host> [...]` | SSH with cert auto-mint + reuse |
| `postern scp [--user <name>] [--tunnel] [--cert-max-lifetime <dur>] <device> <src> <dst> [...]` | scp with cert auto-mint + reuse |
| `postern tunnel <device> [--user <name>] [--max-lifetime <dur>] [--port-only]` | Hold-open tunnel for VSCode-remote / rsync / git / multi-session workflows |
| `postern add-host <device> --ip <ip> [--user <name>] [--port <n>]` | Register a device in `~/.postern/ssh.conf` (and mint a fresh cert) |
| `postern remove-host <device>` | Drop a device's managed stanza |
| `postern setup-ssh [--check]` | Wire `Include ~/.postern/ssh.conf` into `~/.ssh/config` (`--check` reports without writing) |
| `postern mint <device> [--cert-max-lifetime <dur>]` | Force-mint a fresh cert (ad-hoc / scripted) |
| `postern timefix <device> [--ip <addr>] [--tunnel] [--quiet]` | Repair a device's clock |
| `postern cache ls` | List cached cert entries |
| `postern cache prune [--dry-run]` | Remove expired entries |
| `postern logout` | Forget cached tokens |
| `postern version` | Print version info |

The `--user` flag follows a single precedence rule across `add-host`, `tunnel`, `ssh`, and `scp`: explicit `--user` flag > persistent stanza's User (set via a prior `add-host --user`) > profile `default_ssh_user` from `~/.postern/config.yaml` > built-in `engineer` fallback. For `postern ssh` / `postern scp` specifically, you can also use the natural `user@host` form in passthrough args (or `-l <user>` for ssh, `-o User=<user>` for scp); postern detects engineer-supplied user-info and stays out of the way so OpenSSH's native parser handles it.

Two lifetime flags exist and control different things — don't confuse them. `--cert-max-lifetime <dur>` (on `mint` / `ssh` / `scp`) requests a shorter **certificate** TTL; the broker clamps it down to its own per-class ceiling (there is no client-side cap, and the broker never widens past the request). `--max-lifetime <dur>` (on `tunnel`, and on `ssh` / `scp` with `--tunnel`) bounds the **tunnel** lifetime instead, and is capped at 12h by the AWS IoT ceiling. On a single `ssh --tunnel` invocation the two are independent and map to separate requests. Omitting `--cert-max-lifetime` leaves the cert TTL at whatever the broker's per-class default resolves to (today's behavior).

## Setting it up

Three pieces stand up before engineers can use Postern: a **broker** (cloud-side, one per operator), the **device-side** sshd configuration (per device or per firmware build), and each **engineer's laptop** (one config file).

### 1. Broker (cloud-side)

The unwrapped path needs an OIDC IdP plus the AWS infrastructure provisioned by the `postern-broker` Terraform module. With `examples/terraform/cognito/` as the sample IdP:

```sh
# Stand up the broker infrastructure (KMS, DynamoDB, AVP, CloudWatch, Lambda,
# API Gateway, optionally Route 53 + ACM custom domain). The example consumes
# the in-repo module by relative path and builds the Lambda zip at apply time.
cd examples/terraform/deployment
cp terraform.tfvars.example terraform.tfvars   # edit IdP + domain values
terraform init
terraform apply
```

See [`terraform/postern-broker/README.md`](terraform/postern-broker/README.md) for the module reference (variables, outputs, composition with `examples/terraform/cognito/`, OIDC-vs-Cognito identity source, opt-in tunneling backend via `tunneling_enabled = true`).

To consume the module from your own infra repo, copy `examples/terraform/deployment/` and switch the module `source` line from a relative path to a git ref pinned to a Postern release tag — full instructions in the example's README.

### 2. Device side

Each device needs the Postern CA public key in `authorized_keys` for the SSO-authenticated principal(s), plus the matching sshd `Match User` stanzas. Reference sshd drop-in at [`examples/on-device/sshd/`](examples/on-device/sshd/) (a partial `sshd_config` and `authorized_keys` skeleton covering the `engineer` and `timefix` users).

Optional pieces, gated by which recovery paths you want:

- **Broken-clock recovery (`postern timefix`)**: install the on-device verifier + setter binaries (shipped in the `postern-timefix-on-device_<version>_linux_<arch>.tar.gz` release artifact). Reference packaging at [`examples/on-device/timefix/`](examples/on-device/timefix/), which covers install paths, the `setcap cap_sys_time+ep` line for the privileged setter, and the sshd `Match User timefix` ForceCommand stanza that ties the cert principal to the verifier binary.
- **Firewalled-device recovery (`postern ssh --tunnel` / `postern tunnel`)**: install the AWS IoT Greengrass `aws.greengrass.SecureTunneling` component on the device (subscribed to the `$aws/things/device-<serial>/tunnels/notify` MQTT topic). Reference at [`examples/on-device/secure-tunnel/`](examples/on-device/secure-tunnel/). Pair this with `tunneling_enabled = true` in the broker Terraform module.

The on-device pieces are reference recipes, not framework code — Postern's device side is "an sshd that trusts the Postern CA pubkey for the right principals." Adapt for your packaging (Yocto, Buildroot, Debian package, OTA bundle, whatever).

### 3. Engineer laptop

After downloading the `postern` binary, each engineer writes the broker / IdP details into `~/.postern/config.yaml` once. Either run `postern configure` with flags:

```sh
postern configure \
  --broker=https://postern.example.com \
  --idp-issuer=https://cognito-idp.us-west-2.amazonaws.com/us-west-2_XXXXXXXXX \
  --idp-client-id=abcdef0123456789 \
  --idp-audience=https://postern.example.com
```

…or paste a YAML snippet you publish into `~/.postern/config.yaml` directly. Either way, the result is the same. Operators typically pre-bake one of these forms into onboarding docs so engineers don't have to know the IdP details.

If engineers want vanilla `ssh` / `scp` / VSCode-Remote-SSH to find their devices (the registered-flow payoff covered above), they run `postern setup-ssh` once, which prepends `Include ~/.postern/ssh.conf` to `~/.ssh/config`. `postern setup-ssh --check` reports whether it's wired and exits non-zero if not.

## Releases

Pre-built binaries for the engineer CLI (`postern`), the broker (`broker`, long-running HTTP), the broker Lambda artifact (`broker-lambda_<version>_linux_arm64.zip`, ready for the Terraform module's `broker_lambda_zip_path` input), and the on-device timefix pair (`postern-timefix-on-device_<version>_linux_<arch>.tar.gz`, containing `timefix-apply` + `timefix-set-clock`) are published on the [Releases page](https://github.com/atomicgravity/postern/releases) for every tagged version.

The `checksums.txt` file is signed via cosign keyless using GitHub Actions OIDC → Sigstore Fulcio. The signature, cert, and Rekor transparency-log entry are packaged into a single `checksums.txt.sigstore` bundle alongside the checksums on the release page. Verifiers run:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore \
  --certificate-identity-regexp='https://github\.com/atomicgravity/postern/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt
```

…then verify each binary against its line in `checksums.txt`.

## Layout

```
postern/
├── cmd/                 # broker (long-running + Lambda), engineer CLI, on-device verifier + setter
├── internal/            # shared internals; abstractions and their default impls
├── pkg/                 # publicly importable handlers + CLI builder for downstream wrappers
├── terraform/           # Terraform module (postern-broker/) for the AWS reference deployment
├── examples/            # End-to-end examples and packaging references
│   └── terraform/       # Module consumers: deployment/ (directly deployable), cognito/ (sample IdP)
├── DESIGN.md            # design rationale and architecture (read this first)
├── README.md            # this file
└── CLAUDE.md            # operating constraints for AI agents working in this repo
```

## License

Apache 2.0.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for commit-message conventions, the release flow, and the test-running rules (notably: `cmd/timefix-apply/` tests are gated behind the `timefix_test_path` build tag; use `make check` rather than raw `go test ./...`). A `SECURITY.md` disclosure process will land before v1; until then, please use GitHub's private vulnerability reporting for security issues.

Design discussion is welcome via issues and PRs against `DESIGN.md`.
