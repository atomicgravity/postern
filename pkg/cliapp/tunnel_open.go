package cliapp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
)

// tunnelHostnameSuffix appends to the device id for the ephemeral stanza
// name. Pinned so engineers learn one rule (`ssh <device>.tunnel` while a
// tunnel is open) that carries across operators.
const tunnelHostnameSuffix = ".tunnel"

func tunnelCommand(rt runtime) *cobra.Command {
	var (
		maxLifetime time.Duration
		user        string
		portOnly    bool
		reap        bool
		verbose     bool
	)

	command := &cobra.Command{
		Use:   "tunnel <device-id>",
		Short: "Open an AWS IoT Secure Tunnel to a device and hold it open until ^C",
		Long: `Open a tunnel to a firewalled device and write a transient
Postern-managed ssh.conf Host block under <device>.tunnel pointing at
the loopback listener. Run ssh, scp, rsync, sftp, or any other
ssh-speaking tool against <device>.tunnel in another terminal while the
tunnel is open. The persistent <device> stanza (if any) is left alone,
so direct LAN access via ssh <device> still works concurrently. Press
^C in this terminal to close the tunnel; the transient ssh.conf stanza
is removed automatically.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reap {
				return runTunnelReap(cmd, rt)
			}
			if len(args) != 1 {
				return errors.New("device id is required")
			}
			return runTunnelOpen(cmd, rt, args[0], tunnelOpenOptions{
				MaxLifetime: maxLifetime,
				User:        user,
				PortOnly:    portOnly,
				Verbose:     verbose,
			})
		},
	}

	command.Flags().DurationVar(&maxLifetime, flagMaxLifetime, 0, "engineer-requested tunnel TTL (e.g. 30m, 4h; capped at 12h by AWS); zero means use the broker default")
	command.Flags().StringVar(&user, flagUser, "", "override the ssh user in the transient ssh.conf stanza (defaults to the persistent <device> stanza's User if registered, else the profile default)")
	command.Flags().BoolVar(&portOnly, flagPortOnly, false, "skip the transient ssh.conf stanza; print the loopback port and hold open")
	command.Flags().BoolVar(&reap, flagReap, false, "run the stale-ephemeral-stanza reaper and exit (manual escape hatch when a prior tunnel was SIGKILLed or the host is Windows)")
	command.Flags().BoolVarP(&verbose, flagVerbose, "v", false, "log mint + broker + proxy progress to stderr")

	return command
}

type tunnelOpenOptions struct {
	MaxLifetime time.Duration
	User        string
	PortOnly    bool
	Verbose     bool
}

// tunnelHostname returns the ephemeral stanza's Host name. The suffix
// keeps the persistent <device> stanza untouched, so direct LAN access
// works in parallel and a SIGKILLed tunnel can't half-restore it.
func tunnelHostname(deviceID string) string {
	return deviceID + tunnelHostnameSuffix
}

// runTunnelOpen runs the hold-open lifecycle: reap stale stanzas →
// tunnelDial → write the transient stanza (skipped under --port-only) →
// print usage → block on ctx → on cancel, remove the stanza then teardown.
//
// Ordering: RemoveEphemeral runs BEFORE proxy.Close()+Wait() so a stanza
// pointing at a kernel-released port can't mislead the next ssh attempt.
func runTunnelOpen(cmd *cobra.Command, rt runtime, deviceID string, options tunnelOpenOptions) error {
	deviceID = strings.TrimSpace(deviceID)
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}

	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	// Reap before write so the file the next `ssh <device>.tunnel` reads
	// can't reference dead tunnels.
	reaped, err := writer.ReapStaleEphemeral()
	if err != nil {
		return fmt.Errorf("reap stale ephemeral stanzas: %w", err)
	}
	if options.Verbose && len(reaped) > 0 {
		verbosef(cmd, options.Verbose, "reaped stale ephemeral stanzas: %s", strings.Join(reaped, ", "))
	}

	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	dial, err := tunnelDial(cmd, rt, deviceID, options.MaxLifetime, false, options.Verbose)
	if err != nil {
		return err
	}

	// Discard the explicit bool; the stanza always carries a concrete
	// User, mirroring add-host.
	user, _ := resolveUser(writer, deviceID, options.User, profile)

	tunnelHost := tunnelHostname(deviceID)
	if !options.PortOnly {
		stanza := sshconf.Stanza{
			Device:          tunnelHost,
			HostName:        "127.0.0.1",
			User:            user,
			Port:            dial.proxy.LocalPort(),
			IdentityFile:    dial.keyPath,
			CertificateFile: dial.certPath,
		}
		if err := writer.UpsertEphemeral(stanza, os.Getpid(), time.Now().UTC()); err != nil {
			// Tear the proxy down so a WebSocket goroutine doesn't
			// leak. The upsert error is the dominant signal.
			_ = teardownTunnel(cmd.Context(), dial)
			return err
		}

		// The stanza is only useful if ~/.ssh/config Includes the
		// Postern-managed file; warn loudly if it doesn't, so the
		// engineer doesn't chase "Could not resolve hostname".
		if !checkIncludePresence(writer.Path()) {
			warnMissingInclude(cmd.ErrOrStderr(), rt.binaryName, writer.Path(), tunnelHost)
		}
	}

	printTunnelOpenHint(cmd.OutOrStdout(), tunnelHost, dial.proxy.LocalPort(), options.PortOnly)

	// Block until ctx cancels — cmd/postern/main.go wires SIGINT/SIGTERM
	// into the root context.
	<-cmd.Context().Done()

	if !options.PortOnly {
		if err := writer.RemoveEphemeral(tunnelHost); err != nil {
			// Surface remove error but still tear down so a leaked
			// proxy doesn't compound the remove failure.
			downErr := teardownTunnel(cmd.Context(), dial)
			if downErr != nil {
				return fmt.Errorf("remove ephemeral stanza: %w (proxy teardown also failed: %v)", err, downErr)
			}
			return fmt.Errorf("remove ephemeral stanza: %w", err)
		}
	}

	if err := teardownTunnel(cmd.Context(), dial); err != nil {
		return fmt.Errorf("source proxy teardown: %w", err)
	}
	return nil
}

// runTunnelReap is the --reap escape hatch: runs the same reaper as a
// regular tunnel open, without opening one. For SIGKILLed parents or
// Windows hosts where pid-liveness is weaker.
func runTunnelReap(cmd *cobra.Command, rt runtime) error {
	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	reaped, err := writer.ReapStaleEphemeral()
	if err != nil {
		return fmt.Errorf("reap stale ephemeral stanzas: %w", err)
	}

	out := cmd.OutOrStdout()
	if len(reaped) == 0 {
		_, err := fmt.Fprintln(out, "No stale ephemeral tunnel stanzas found.")
		return err
	}

	_, err = fmt.Fprintf(out, "Reaped %d stale ephemeral tunnel stanzas: %s\n",
		len(reaped), strings.Join(reaped, ", "))
	return err
}

// printTunnelOpenHint emits the post-open instruction line.
func printTunnelOpenHint(out io.Writer, tunnelHost string, localPort int, portOnly bool) {
	if portOnly {
		fmt.Fprintf(out, "Tunnel open. Local port: %d. ^C to close.\n", localPort)
		return
	}
	fmt.Fprintf(out, "Tunnel open. Run `ssh %s` (or scp, rsync, sftp, etc.) in another terminal. ^C here to close.\n", tunnelHost)
}
