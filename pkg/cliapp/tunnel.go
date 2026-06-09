package cliapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/securetunnel"
	"github.com/spf13/cobra"
)

// ErrTunnelNegativeLifetime / ErrTunnelLifetimeExceedsCeiling are
// client-side rejections that surface a clean error before the broker
// round-trip; the broker re-enforces the same bounds authoritatively.
var (
	ErrTunnelNegativeLifetime       = errors.New("--max-lifetime must be a non-negative duration")
	ErrTunnelLifetimeExceedsCeiling = errors.New("--max-lifetime must be at most 12h (AWS IoT Secure Tunneling ceiling)")
)

const awsTunnelCeiling = 12 * time.Hour

// tunnelDialResult bundles the running proxy, cache paths, and resolved TTL
// every tunnel-mode subcommand consumes.
type tunnelDialResult struct {
	proxy              sourceProxy
	certPath           string
	keyPath            string
	maxLifetimeMinutes int32
}

// tunnelDial composes mint + /ssh/tunnel + source-proxy-start for ssh and
// scp's tunnel mode. Returns with the proxy running; the caller owns
// proxy.Close() + Wait() so exit-code propagation stays explicit.
func tunnelDial(cmd *cobra.Command, rt runtime, deviceID string, maxLifetime time.Duration, certMaxLifetimeMinutes int32, refresh bool, verbose bool) (*tunnelDialResult, error) {
	maxLifetimeMinutes, err := lifetimeMinutesFromDuration(maxLifetime)
	if err != nil {
		return nil, err
	}

	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return nil, err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return nil, err
	}

	if err := ensureFreshCert(cmd, rt, store, profile, deviceID, certMaxLifetimeMinutes, refresh, verbose); err != nil {
		return nil, err
	}

	certPath, keyPath, err := store.CachePath(deviceID)
	if err != nil {
		return nil, err
	}

	accessToken, err := rt.accessToken(cmd.Context(), profile)
	if err != nil {
		return nil, mintAuthError(rt.binaryName, profile.Name, err)
	}

	verbosef(cmd, verbose, "opening tunnel for %q via %s", deviceID, profile.Profile.Broker)

	tunnel, err := rt.tunnelOpener(cmd.Context(), profile, accessToken, deviceID, maxLifetimeMinutes)
	if err != nil {
		return nil, err
	}

	// The source access token is bearer-equivalent and must never be
	// logged, written to disk, or echoed. The diagnostic below names only
	// region + tunnel id.
	verbosef(cmd, verbose, "broker authorized tunnel %s in region %s (max lifetime %d minutes)", tunnel.TunnelID, tunnel.Region, tunnel.MaxLifetimeMinutes)

	var proxyLogger *slog.Logger
	if verbose {
		proxyLogger = slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	proxy, err := rt.sourceProxyStarter(cmd.Context(), securetunnel.SourceProxyOptions{
		Region:            tunnel.Region,
		SourceAccessToken: tunnel.SourceAccessToken,
		ServiceID:         securetunnel.DefaultServiceID,
		Logger:            proxyLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("start source proxy: %w", err)
	}

	verbosef(cmd, verbose, "source proxy listening on 127.0.0.1:%d", proxy.LocalPort())

	return &tunnelDialResult{
		proxy:              proxy,
		certPath:           certPath,
		keyPath:            keyPath,
		maxLifetimeMinutes: tunnel.MaxLifetimeMinutes,
	}, nil
}

// lifetimeMinutesFromDuration converts duration → broker's int32 minutes.
// Zero passes through so the broker substitutes its default; sub-minute
// positives round up to 1.
func lifetimeMinutesFromDuration(d time.Duration) (int32, error) {
	if d == 0 {
		return 0, nil
	}
	if d < 0 {
		return 0, ErrTunnelNegativeLifetime
	}
	if d > awsTunnelCeiling {
		return 0, ErrTunnelLifetimeExceedsCeiling
	}
	minutes := int64(d / time.Minute)
	if d%time.Minute != 0 {
		minutes++
	}
	if minutes < 1 {
		minutes = 1
	}
	return int32(minutes), nil
}

// buildTunneledSSHArgv assembles ssh's tunneled argv. HostName redirects
// to loopback while the engineer-typed destination keeps the device-id form
// so a `Host <device-id>` stanza still applies.
// NoHostAuthenticationForLocalhost keeps known_hosts pristine — host-key
// trust flows through the cert's principal pinning, not known_hosts.
func buildTunneledSSHArgv(keyPath, certPath, deviceID, user string, localPort int, passthrough []string) []string {
	argv := sshIdentityArgs("ssh", keyPath, certPath)
	argv = append(argv,
		"-p", strconv.Itoa(localPort),
		"-o", "HostName=127.0.0.1",
		"-o", "NoHostAuthenticationForLocalhost=yes",
	)
	if user != "" {
		argv = append(argv, "-l", user)
	}
	argv = append(argv, withDeviceIDDestination(deviceID, passthrough)...)
	return argv
}

// withDeviceIDDestination rewrites the host portion of the destination
// positional to the device-id so a `Host <device-id>` stanza applies in
// tunnel mode. user@host keeps the user; missing destination appends
// the device-id.
func withDeviceIDDestination(deviceID string, passthrough []string) []string {
	out := make([]string, len(passthrough))
	copy(out, passthrough)

	hostIndex := findHostPositional(out)
	if hostIndex < 0 {
		out = append(out, deviceID)
		return out
	}

	host := out[hostIndex]
	at := strings.LastIndex(host, "@")
	if at >= 0 {
		out[hostIndex] = host[:at+1] + deviceID
	} else {
		out[hostIndex] = deviceID
	}
	return out
}

// findHostPositional returns the index of the first non-flag positional
// (the ssh destination), -1 if absent. Conservative skip-list of flags
// that consume the next slot.
func findHostPositional(argv []string) int {
	for i := 0; i < len(argv); i++ {
		token := argv[i]
		if token == "" {
			continue
		}
		if token[0] != '-' {
			return i
		}
		if sshFlagConsumesArg(token) && i+1 < len(argv) {
			i++
		}
	}
	return -1
}

// sshFlagConsumesArg reports ssh / scp flags taking a separate-slot
// argument. Long-form `-oKey=Value` is self-contained.
func sshFlagConsumesArg(token string) bool {
	if len(token) > 2 && token[0] == '-' {
		return false
	}
	switch token {
	case "-L", "-R", "-D", "-p", "-o", "-i", "-F", "-l", "-J", "-W", "-e", "-c", "-b", "-m", "-O", "-Q", "-S", "-w":
		return true
	}
	return false
}

// teardownTunnel closes the proxy and waits its goroutines so no
// WebSockets outlive ssh exit. The Wait error is the proxy's termination
// cause; callers fold it into the ssh exit so ssh's status dominates.
func teardownTunnel(_ context.Context, result *tunnelDialResult) error {
	if result == nil || result.proxy == nil {
		return nil
	}
	_ = result.proxy.Close()
	return result.proxy.Wait()
}
