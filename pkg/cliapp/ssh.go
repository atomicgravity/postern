package cliapp

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// cacheHitSafetyMargin is the validity headroom required to reuse a cached
// cert without re-minting — below it ssh re-mints so an in-progress session
// doesn't die mid-stream.
const cacheHitSafetyMargin = 5 * time.Minute

func verbosef(cmd *cobra.Command, verbose bool, format string, a ...any) {
	if !verbose {
		return
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "postern: "+fmt.Sprintf(format, a...))
}

func sshCommand(rt runtime) *cobra.Command {
	var refresh bool
	var tunnel bool
	var maxLifetime time.Duration
	var certMaxLifetime time.Duration
	var user string
	var verbose bool

	command := &cobra.Command{
		Use:   "ssh [flags] <device-id> [ssh-args...]",
		Short: "Open an SSH session to a device, minting a fresh cert if needed",
		Long: "Open an SSH session to a device, minting a fresh cert if needed.\n" +
			"\n" +
			"The device-id is used as the SSH destination when no explicit host is\n" +
			"present in ssh-args. Pass a `user@host` or bare host in ssh-args to\n" +
			"override (e.g. when you want to use the device's cert to reach a different\n" +
			"host on the same LAN).",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSH(cmd, rt, args, sshOptions{
				Refresh:         refresh,
				Tunnel:          tunnel,
				MaxLifetime:     maxLifetime,
				CertMaxLifetime: certMaxLifetime,
				User:            user,
				Verbose:         verbose,
			})
		},
	}

	// Anything after the device-id passes straight through to ssh, so
	// postern flags must precede the device id. Engineers wanting to pass
	// -v to ssh put it after: `postern ssh <device> -v ...`.
	command.Flags().SetInterspersed(false)
	command.Flags().BoolVar(&refresh, flagRefresh, false, "force a fresh cert mint even if the cache has a valid one")
	command.Flags().BoolVar(&tunnel, flagTunnel, false, "route through the AWS IoT Secure Tunneling backend rather than direct LAN")
	command.Flags().DurationVar(&maxLifetime, flagMaxLifetime, 0, "engineer-requested tunnel TTL (e.g. 30m, 4h; capped at 12h by AWS); zero means use the broker default")
	command.Flags().DurationVar(&certMaxLifetime, flagCertMaxLifetime, 0, "engineer-requested certificate TTL (e.g. 30m, 4h); zero means use the broker default; the broker clamps it to its per-class ceiling")
	command.Flags().StringVar(&user, flagUser, "", "override the ssh user (defaults to the persistent <device> stanza's User if registered, else the profile default)")
	command.Flags().BoolVarP(&verbose, flagVerbose, "v", false, "log cert-mint progress and the ssh invocation argv to stderr")

	return command
}

type sshOptions struct {
	Refresh         bool
	Tunnel          bool
	MaxLifetime     time.Duration
	CertMaxLifetime time.Duration
	User            string
	Verbose         bool
}

func runSSH(cmd *cobra.Command, rt runtime, args []string, options sshOptions) error {
	deviceID := strings.TrimSpace(args[0])
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}
	passthrough := args[1:]

	certMaxLifetimeMinutes, err := certLifetimeMinutesFromDuration(options.CertMaxLifetime)
	if err != nil {
		return err
	}

	if options.Tunnel {
		return runTunneledSSH(cmd, rt, deviceID, passthrough, certMaxLifetimeMinutes, options)
	}

	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return err
	}

	if err := ensureFreshCert(cmd, rt, store, profile, deviceID, certMaxLifetimeMinutes, options.Refresh, options.Verbose); err != nil {
		return err
	}

	certPath, keyPath, err := store.CachePath(deviceID)
	if err != nil {
		return err
	}

	sshUser := resolveCommandUser(rt, deviceID, options.User, profile, passthrough, false)

	argv := buildSSHArgv(keyPath, certPath, deviceID, sshUser, passthrough)
	verbosef(cmd, options.Verbose, "exec: %s", strings.Join(argv, " "))

	return rt.execSSH(cmd.Context(), argv, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
}

// runTunneledSSH executes the --tunnel branch. Proxy lifetime is bounded by
// the ssh subprocess — ssh exit (clean or ctx cancel) closes and waits the
// proxy so no WebSocket goroutines outlive the session.
func runTunneledSSH(cmd *cobra.Command, rt runtime, deviceID string, passthrough []string, certMaxLifetimeMinutes int32, options sshOptions) error {
	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	dial, err := tunnelDial(cmd, rt, deviceID, options.MaxLifetime, certMaxLifetimeMinutes, options.Refresh, options.Verbose)
	if err != nil {
		return err
	}

	sshUser := resolveCommandUser(rt, deviceID, options.User, profile, passthrough, false)

	argv := buildTunneledSSHArgv(dial.keyPath, dial.certPath, deviceID, sshUser, dial.proxy.LocalPort(), passthrough)
	verbosef(cmd, options.Verbose, "exec: %s", strings.Join(argv, " "))

	execErr := rt.execSSH(cmd.Context(), argv, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
	_ = teardownTunnel(cmd.Context(), dial)
	return execErr
}

// buildSSHArgv assembles the ssh argv. The device id is appended as the
// destination when passthrough has no host-shaped positional; an explicit
// user@host in passthrough is left alone. Empty user skips -l so a
// `Host *` wildcard User in ~/.ssh/config keeps applying.
func buildSSHArgv(keyPath, certPath, deviceID, user string, passthrough []string) []string {
	argv := sshIdentityArgs("ssh", keyPath, certPath)
	if user != "" {
		argv = append(argv, "-l", user)
	}
	if findHostPositional(passthrough) < 0 {
		passthrough = append(passthrough, deviceID)
	}
	return append(argv, passthrough...)
}
