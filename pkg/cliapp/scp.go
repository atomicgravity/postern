package cliapp

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ErrSCPMissingPaths is returned when scp's positionals don't include both
// source and destination. scp's native "usage" message buries the postern
// context; this names the wrapper in the error.
var ErrSCPMissingPaths = errors.New("scp requires at least one source and one destination argument")

func scpCommand(rt runtime) *cobra.Command {
	var refresh bool
	var tunnel bool
	var maxLifetime time.Duration
	var certMaxLifetime time.Duration
	var user string
	var verbose bool

	command := &cobra.Command{
		Use:   "scp [flags] <device-id> [scp-args...]",
		Short: "Run scp against a device, minting a fresh cert if needed",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSCP(cmd, rt, args, scpOptions{
				Refresh:         refresh,
				Tunnel:          tunnel,
				MaxLifetime:     maxLifetime,
				CertMaxLifetime: certMaxLifetime,
				User:            user,
				Verbose:         verbose,
			})
		},
	}

	// Anything after the device-id passes straight to scp. Engineers
	// wanting to pass -v to scp put it after: `postern scp <device> -v src dst`.
	command.Flags().SetInterspersed(false)
	command.Flags().BoolVar(&refresh, flagRefresh, false, "force a fresh cert mint even if the cache has a valid one")
	command.Flags().BoolVar(&tunnel, flagTunnel, false, "route through the AWS IoT Secure Tunneling backend rather than direct LAN")
	command.Flags().DurationVar(&maxLifetime, flagMaxLifetime, 0, "engineer-requested tunnel TTL (e.g. 30m, 4h; capped at 12h by AWS); zero means use the broker default")
	command.Flags().DurationVar(&certMaxLifetime, flagCertMaxLifetime, 0, "engineer-requested certificate TTL (e.g. 30m, 4h); zero means use the broker default; the broker clamps it to its per-class ceiling")
	command.Flags().StringVar(&user, flagUser, "", "override the ssh user (defaults to the persistent <device> stanza's User if registered, else the profile default)")
	command.Flags().BoolVarP(&verbose, flagVerbose, "v", false, "log cert-mint progress and the scp invocation argv to stderr")

	return command
}

type scpOptions struct {
	Refresh         bool
	Tunnel          bool
	MaxLifetime     time.Duration
	CertMaxLifetime time.Duration
	User            string
	Verbose         bool
}

func runSCP(cmd *cobra.Command, rt runtime, args []string, options scpOptions) error {
	deviceID := strings.TrimSpace(args[0])
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}
	if len(args) < 3 {
		return ErrSCPMissingPaths
	}
	passthrough := args[1:]

	certMaxLifetimeMinutes, err := certLifetimeMinutesFromDuration(options.CertMaxLifetime)
	if err != nil {
		return err
	}

	if options.Tunnel {
		return runTunneledSCP(cmd, rt, deviceID, passthrough, certMaxLifetimeMinutes, options)
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

	scpUser := resolveCommandUser(rt, deviceID, options.User, profile, passthrough, true)

	argv := buildSCPArgv(keyPath, certPath, scpUser, passthrough)
	verbosef(cmd, options.Verbose, "exec: %s", strings.Join(argv, " "))

	return rt.execSCP(cmd.Context(), argv, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
}

// runTunneledSCP is scp's --tunnel branch. Mirrors runTunneledSSH; differs
// only in scp's argv shape (uppercase -P, two positional file specs that
// need device-id rewriting) and scp's flag set (-S program, -l limit,
// -P port vs ssh's -l login, -p port).
func runTunneledSCP(cmd *cobra.Command, rt runtime, deviceID string, passthrough []string, certMaxLifetimeMinutes int32, options scpOptions) error {
	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	dial, err := tunnelDial(cmd, rt, deviceID, options.MaxLifetime, certMaxLifetimeMinutes, options.Refresh, options.Verbose)
	if err != nil {
		return err
	}

	scpUser := resolveCommandUser(rt, deviceID, options.User, profile, passthrough, true)

	argv := buildTunneledSCPArgv(dial.keyPath, dial.certPath, deviceID, scpUser, dial.proxy.LocalPort(), passthrough)
	verbosef(cmd, options.Verbose, "exec: %s", strings.Join(argv, " "))

	execErr := rt.execSCP(cmd.Context(), argv, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
	_ = teardownTunnel(cmd.Context(), dial)
	return execErr
}

// buildSCPArgv assembles the scp argv. scp's `-l` is bandwidth-limit, so a
// non-empty user becomes `-o User=`. Empty user skips the option so a
// `Host *` wildcard User in ~/.ssh/config keeps applying.
func buildSCPArgv(keyPath, certPath, user string, passthrough []string) []string {
	argv := sshIdentityArgs("scp", keyPath, certPath)
	if user != "" {
		argv = append(argv, "-o", "User="+user)
	}
	return append(argv, passthrough...)
}

// buildTunneledSCPArgv assembles scp's tunneled argv. -P is uppercase (scp's
// port flag; lowercase -p is preserve-times). Positionals get their host
// segments rewritten to the device-id with HostName redirecting to loopback,
// so a `Host <device-id>` stanza in ~/.ssh/config still applies.
func buildTunneledSCPArgv(keyPath, certPath, deviceID, user string, localPort int, passthrough []string) []string {
	argv := sshIdentityArgs("scp", keyPath, certPath)
	argv = append(argv,
		"-P", strconv.Itoa(localPort),
		"-o", "HostName=127.0.0.1",
		"-o", "NoHostAuthenticationForLocalhost=yes",
	)
	if user != "" {
		argv = append(argv, "-o", "User="+user)
	}
	argv = append(argv, withSCPDeviceIDDestinations(deviceID, passthrough)...)
	return argv
}

// withSCPDeviceIDDestinations rewrites the host portion of every remote scp
// positional (user@host:path / host:path) to the device-id, preserving user
// and path. Both source and dest get rewritten so a `Host <device-id>`
// stanza covers both legs of a same-device copy. Local-only positionals
// (no colon, or colon-after-slash) are left alone. If no remote positional
// exists, the device-id is appended defensively to keep scp's "usage"
// diagnostic from burying the postern context.
func withSCPDeviceIDDestinations(deviceID string, passthrough []string) []string {
	out := make([]string, len(passthrough))
	copy(out, passthrough)

	rewrote := false
	for i := 0; i < len(out); i++ {
		token := out[i]
		if token == "" {
			continue
		}
		if token[0] == '-' {
			if scpFlagConsumesArg(token) && i+1 < len(out) {
				i++
			}
			continue
		}
		if !looksLikeRemoteSCPSpec(token) {
			continue
		}
		out[i] = rewriteSCPHost(token, deviceID)
		rewrote = true
	}

	if !rewrote {
		out = append(out, deviceID)
	}
	return out
}

// looksLikeRemoteSCPSpec reports whether a positional names a remote file
// (`host:path` / `user@host:path`). A `/` before the first colon means
// local path with literal colon in the filename.
func looksLikeRemoteSCPSpec(token string) bool {
	colon := strings.Index(token, ":")
	if colon < 0 {
		return false
	}
	prefix := token[:colon]
	if prefix == "" {
		return false
	}
	if strings.ContainsAny(prefix, "/\\") {
		return false
	}
	return true
}

// rewriteSCPHost swaps the host portion of an accepted remote spec for the
// device-id, preserving any `user@` prefix and the `:path` suffix.
func rewriteSCPHost(token, deviceID string) string {
	colon := strings.Index(token, ":")
	hostPart := token[:colon]
	pathPart := token[colon:] // includes the leading ':'
	at := strings.LastIndex(hostPart, "@")
	if at >= 0 {
		return hostPart[:at+1] + deviceID + pathPart
	}
	return deviceID + pathPart
}

// scpFlagConsumesArg reports scp flags that take a separate-slot argument.
// scp differs from ssh at load-bearing points: -P is port (ssh -p), -l is
// bandwidth-limit (ssh -l is login). Long-form `-oKey=Value` is self-
// contained and doesn't consume a slot.
func scpFlagConsumesArg(token string) bool {
	if len(token) > 2 && token[0] == '-' {
		return false
	}
	switch token {
	case "-c", "-F", "-i", "-J", "-l", "-o", "-P", "-S":
		return true
	}
	return false
}
