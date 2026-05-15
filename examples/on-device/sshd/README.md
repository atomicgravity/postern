# On-device sshd integration

A **partial** `sshd_config` drop-in that wires the on-device OpenSSH server to authenticate engineers via Postern-issued certificates and exposes the timefix recovery path. Bring your own base `sshd_config`; this file adds only the Postern-specific directives.

The full design rationale is in [`DESIGN.md`](../../../DESIGN.md) §"sshd config (sketch)" and §"Packaging onto devices."

## What's in the box

[`postern.conf`](postern.conf) is intended to land at `/etc/ssh/sshd_config.d/10-postern.conf` on distributions whose main `sshd_config` ends with `Include /etc/ssh/sshd_config.d/*.conf` — Debian, Ubuntu, modern Fedora, and most off-the-shelf Linux distros. On layouts without the `sshd_config.d` include (some Yocto / Buildroot builds), append the directives directly to your `sshd_config` — they are additive.

The drop-in covers two access modes:

- **`engineer` user — real shell.** Cert principal `device-{serial}-operator` admits the connection. Local port forwards allowed (so engineers can `-L` a debug HTTP/UI on the device back to their laptop); agent + X11 forwarding disabled.
- **`timefix` user — forced command.** Cert principal `device-{serial}-timefix` admits the connection, and the only thing reachable is `/usr/sbin/timefix-apply`. No TTY, no forwarding, no shell. This is the recovery path for devices whose clocks have drifted past the operator cert's validity window.

## Prereqs your provisioning must arrange

Postern itself doesn't write these — they're the operator's job (typically through Yocto recipes, Buildroot packages, OS image bakes, or first-boot setup scripts).

| Artifact | Where | What populates it |
|---|---|---|
| `/etc/ssh/postern_ca.pub` | Single line: `ssh-ed25519 AAAA…` | Operator extracts from the broker's KMS key (see [terraform/postern-broker/README.md](../../../terraform/postern-broker/README.md) §"Extracting the SSH CA public key for devices"); same file is shipped to every device in the fleet via OS update or first-boot |
| `engineer` system user | Real interactive shell, no sudo unless your access model needs it | OS image / Yocto recipe |
| `timefix` system user | Unprivileged; **shell `/bin/sh`** (NOT `/usr/sbin/nologin`). sshd runs the `ForceCommand` via the user's login shell (`shell -c '/usr/sbin/timefix-apply'`), so a `nologin` shell prints "This account is currently not available." and exits before the verifier ever runs. The forced command + the `AuthorizedPrincipalsFile` gate keep the surface tight — the timefix user only ever exec's the verifier. | OS image / Yocto recipe; see [`../timefix/README.md`](../timefix/README.md) install step 1 |
| `/etc/ssh/authorized_principals/engineer` | Single line: `device-{serial}-operator` | The principals-init service (boot-time helper described in DESIGN.md §"Device identity and on-device principals") |
| `/etc/ssh/authorized_principals/timefix` | Single line: `device-{serial}-timefix` | Same |
| `/usr/sbin/timefix-apply` + `/usr/sbin/timefix-set-clock` | The unprivileged verifier + privileged setter binaries (Go, ~no deps) | See [`../timefix/README.md`](../timefix/README.md) for the install / user-group / `setcap` recipe. Until both are installed the `Match User timefix` block is harmless: timefix sessions fail at exec time but operator-user shells continue to work normally. |

## Install

1. Drop `postern.conf` into `/etc/ssh/sshd_config.d/10-postern.conf` (or append to `/etc/ssh/sshd_config` if your sshd doesn't include the `.d` directory).
2. Validate with `sudo sshd -t` — fixes any path or syntax issues before they break the running service.
3. Reload: `sudo systemctl reload sshd` (or `kill -HUP <sshd-pid>`).

If `sshd -t` fails, leave the existing running config in place and fix the new file; sshd does not pick up changes until you reload.

## A note on user names

`engineer` and `timefix` are conventions, not mandates. If your image already provisions a different system user for diagnostic access, rename consistently:

- The `Match User <name>` block in this file
- The `AuthorizedPrincipalsFile` path implicitly through the `%u` substitution (no edit needed; sshd swaps `%u` to whichever user name connected)
- The `/etc/ssh/authorized_principals/<name>` file your principals-init writes

The cert principal (`device-{serial}-operator` / `device-{serial}-timefix`) is what the broker mints and is **not** user-configurable in v1 — change it on the device side by changing what your principals-init script writes into the file, not in the cert itself.

## Verifying end-to-end

After dropping in the config, with a Postern broker stood up and the engineer's CLI configured, you can sanity-check the device side without involving the broker at all:

```sh
# On the device:
cat /etc/ssh/authorized_principals/engineer                 # should print exactly: device-<your-serial>-operator
sudo sshd -t                                                # config valid
sudo journalctl -u sshd --since "5 minutes ago"             # watch sshd logs while an engineer attempts a cert auth from the broker side
```

If an engineer's `postern ssh <device>` reaches the device and sshd rejects the connection, the `LogLevel VERBOSE` setting will print which check failed (CA signature, principal mismatch, validity window, etc.) — read those before assuming a broker-side issue.
