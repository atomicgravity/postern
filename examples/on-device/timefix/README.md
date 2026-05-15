# On-device timefix integration

A **partial** install recipe for the on-device timefix recovery path. The recovery path lets an engineer fix a broken device clock over SSH using a signed JWS time payload from the Postern broker; the on-device side is two binaries with a deliberate privilege split. This sample documents what to install where, with which user/group, and with which Linux capabilities. Bring your own Yocto recipe / Buildroot package / Debian postinst — this sample is a documentation reference, not a runnable bake target.

The full design rationale is in [`DESIGN.md`](../../../DESIGN.md) §"The on-device timefix path (privilege-split)" and §"Why split into two binaries".

## What's in the box

Two Linux binaries built from this repo's `cmd/` tree:

- **`timefix-apply`** — the unprivileged verifier. Runs as the `timefix` system user under sshd's `ForceCommand` for that user, validates an incoming JWS Compact against the on-device CA pubkey + hardware serial + an in-memory nonce + a sanity time range, then exec's `timefix-set-clock` with the validated unix timestamp. Has zero Linux capabilities and no SUID bit. A bug here gives an attacker at most a `timefix`-user shell that can do nothing reachable.
- **`timefix-set-clock`** — the privileged setter. Runs as the same `timefix` user but carries `cap_sys_time+ep` via Linux file capabilities applied by this install recipe. Calls `clock_settime(CLOCK_REALTIME, ...)` on a single positional integer arg, then best-effort writes the RTC via `RTC_SET_TIME` ioctl on `/dev/rtc0`. No stdin read, no env-derived input, no file reads except the syscall/ioctl targets, no flags.

The two binaries ride upstream Postern releases. Download from this repo's GitHub releases for your device architecture (`linux/amd64` or `linux/arm64`) — they have no runtime dependencies beyond glibc / musl.

## Prereqs your provisioning must arrange

Postern itself doesn't write these — they're the operator's job (typically through Yocto recipes, Buildroot packages, OS image bakes, or first-boot setup scripts).

| Artifact | Where | What populates it |
|---|---|---|
| `/etc/ssh/postern_ca.pub` | Single line: `ssh-ed25519 AAAA…` | Operator extracts from the broker's KMS key (see [terraform/postern-broker/README.md](../../../terraform/postern-broker/README.md) §"Extracting the SSH CA public key for devices"); same file is shipped to every device in the fleet via OS update or first-boot |
| `timefix` system user + group | Unprivileged; **shell `/bin/sh`** (NOT `/usr/sbin/nologin`) | OS image / Yocto recipe — see install step 1 below. sshd's `ForceCommand` runs as `<user-shell> -c '/usr/sbin/timefix-apply'`; a nologin shell aborts before the verifier exec's |
| sshd `ForceCommand` block for the `timefix` user | Cert principal `device-{serial}-timefix` + `ForceCommand /usr/sbin/timefix-apply` | See [`../sshd/README.md`](../sshd/README.md) — the drop-in there wires both the engineer (real shell) and timefix (forced command) modes |
| `/etc/ssh/authorized_principals/timefix` | Single line: `device-{serial}-timefix` | The principals-init service (boot-time helper described in DESIGN.md §"Device identity and on-device principals"). **This file is the verifier's source of truth for the expected aud** — `cmd/timefix-apply` reads its `device-<serial>-timefix` principal here, no hardware-path dependency |

## Install

The order below matters: the `install -m 0750` step for `timefix-set-clock` MUST precede the `setcap` step. Linux file capabilities live on the inode; reinstalling the binary clears them. If you ever re-deploy the setter (OS update, A/B image switch, etc.), the `setcap` step needs to run again.

```sh
# 1. Create the timefix user + group. /bin/sh — NOT /usr/sbin/nologin —
#    is load-bearing: sshd's ForceCommand runs the verifier via the user's
#    login shell (`shell -c '/usr/sbin/timefix-apply'`). A nologin shell
#    prints "This account is currently not available." and exits before
#    the verifier runs. The forced command + the AuthorizedPrincipalsFile
#    gate keep this from widening the surface — the timefix user only
#    ever exec's the verifier, never gets an interactive shell.
useradd --system --user-group --no-create-home --shell /bin/sh timefix

# 2. Install the two binaries with the load-bearing perms.
#    0750 root:timefix means only `timefix` (the user the verifier runs as)
#    and root can exec the setter. Combined with cap_sys_time+ep, this gives
#    defense in depth: even on a hostile fork where some other unprivileged
#    user got the setter's path, they can't exec it.
install -o root -g timefix -m 0750 timefix-apply     /usr/sbin/
install -o root -g timefix -m 0750 timefix-set-clock /usr/sbin/

# 3. Apply cap_sys_time to the setter. ep = effective + permitted. Order
#    matters — this must come AFTER the install step above, because file
#    caps live on the inode and `install` replaces it.
setcap cap_sys_time+ep /usr/sbin/timefix-set-clock
```

Then drop in the sshd config from [`../sshd/README.md`](../sshd/README.md) so the timefix user is reachable via SSH cert auth with the binary as `ForceCommand`.

### Building without the RTC path

Rootfs images that don't expose `/dev/rtc0` to the `timefix` user (no RTC hardware, xattr-stripped rootfs, no `disk` group membership, etc.) can compile out the RTC ioctl entirely with `-tags no_rtc`:

```sh
go build -tags no_rtc -o timefix-set-clock ./cmd/timefix-set-clock
```

The kernel-clock side still runs (and still needs `cap_sys_time+ep`); only the hardware-persisted RTC ioctl becomes a silent no-op. Without the tag, an RTC failure logs a one-line warning to stderr and the setter still exits 0 (kernel clock is the load-bearing action); the tag exists for operators who'd rather not see the warning at all because they know the RTC path can never succeed on their image.

In Yocto, set on the recipe building the setter:

```bitbake
GO_BUILDFLAGS = "-tags no_rtc"
```

## A note on file permissions and capabilities

The on-device privilege model is two-layered.

**The first layer is the file-capability boundary.** `setcap cap_sys_time+ep` binds the `CAP_SYS_TIME` capability to the setter's binary inode. When the setter runs, the kernel grants it `CAP_SYS_TIME` regardless of the calling user's UID — that's the entire reason file capabilities exist as a modern alternative to SUID. The setter does one syscall + one ioctl with that capability and exits. The verifier never carries the capability; it has nothing that needs it.

**The second layer is `root:timefix 0750`.** `cap_sys_time` only matters if the binary actually runs. The 0750 + group-ownership pair restricts who can exec the setter at all: root (because root can always read+exec anything) and the `timefix` group (which currently has exactly one member, the `timefix` user that sshd switches to when handling a timefix cert). A different unprivileged user trying to invoke `/usr/sbin/timefix-set-clock` directly hits a permission-denied wall before the kernel even loads the binary's file caps.

The combination is what `DESIGN.md` §"Why split into two binaries" calls a trivially small attack surface: the only piece of code in the system with `CAP_SYS_TIME` is a binary whose only job is one syscall + one ioctl from a single integer arg, and the only way to invoke it is via the verifier (or root, which is already trusted).

## Verifying end-to-end

After the install above, with a Postern broker stood up and the engineer's CLI configured, you can sanity-check the device side without involving the broker at all:

```sh
# On the device:
getcap /usr/sbin/timefix-set-clock                 # should print: cap_sys_time=ep
ls -l /usr/sbin/timefix-set-clock                  # should print: -rwxr-x--- 1 root timefix ...
id timefix                                         # should print: uid=N(timefix) gid=N(timefix) groups=N(timefix)
sudo -u timefix /usr/sbin/timefix-set-clock 1747000000   # should print nothing on stdout/stderr if RTC works (or one warning line if no RTC); should NOT print "operation not permitted"
```

The last command actually advances the device's kernel clock to 2025-05-11T22:13:20Z — do this only on a device you don't mind perturbing.

If `setcap` is missing or the install step replaced the binary after the cap was set, the last command fails with `clock_settime: operation not permitted` to stderr and exits 3. Re-run the `setcap` step.

If the engineer's `postern timefix <device>` reaches the device, the verifier emits two stdout lines: the base64url-encoded nonce on line 1, then `device-clock: <RFC3339 timestamp>` on line 2 showing the device's current clock reading (engineer sees this in CLI verbose output for debugging clock skew). The verifier then reads the JWS from stdin, validates it, and exec's the setter. Verifier failures emit a single line to stderr naming the failure class with a stable exit code per `DESIGN.md` §"Device-side validation".
