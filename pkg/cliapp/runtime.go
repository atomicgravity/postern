package cliapp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/brokerclient"
	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/atomicgravity/postern/internal/securetunnel"
	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
)

// profileResolverFunc resolves a cobra command to a populated profile.
type profileResolverFunc func(*cobra.Command) (ResolvedProfile, error)

// runtime holds the per-process dependencies and helpers wired by New.
// Func-typed deps form a single test-substitution seam style.
type runtime struct {
	binaryName         string
	configPath         string
	lookupEnv          func(string) (string, bool)
	profileResolver    profileResolverFunc
	loginRunner        loginRunnerFunc
	accessToken        accessTokenFunc
	sshCertRequester   sshCertRequesterFunc
	tunnelOpener       tunnelOpenerFunc
	sourceProxyStarter sourceProxyStarterFunc
	timePayloadFetch   timePayloadFetcherFunc
	deleteToken        deleteTokenFunc
	openCertStore      openCertStoreFunc
	execSSH            execSSHFunc
	execSSHTimefix     execSSHTimefixFunc
	execSCP            execSCPFunc
	openSSHConfWriter  openSSHConfWriterFunc
}

type loginRunnerFunc func(context.Context, ResolvedProfile, io.Writer, loginOptions) error

// loginOptions carries the login subcommand's flags through the runner
// seam. CallbackPort of 0 means "try the full registered port set in
// order"; a non-zero value pins a single port (validated against the
// registered set before it reaches here).
type loginOptions struct {
	NoBrowser    bool
	CallbackPort int
}

type accessTokenFunc func(context.Context, ResolvedProfile) (string, error)

type sshCertRequesterFunc func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error)

// tunnelOpenerFunc is the broker /ssh/tunnel call. maxLifetimeMinutes=0 means
// use the broker's configured default; the broker returns the resolved value.
type tunnelOpenerFunc func(ctx context.Context, profile ResolvedProfile, accessToken, deviceID string, maxLifetimeMinutes int32) (broker.TunnelOpenResponse, error)

// sourceProxy mirrors *securetunnel.SourceProxy's public surface so tests
// substitute a fake.
type sourceProxy interface {
	LocalPort() int
	Wait() error
	Close() error
}

// sourceProxyStarterFunc starts the source proxy. The starter must complete
// the SERVICE_IDS handshake before returning so the caller can spawn ssh
// immediately.
type sourceProxyStarterFunc func(ctx context.Context, options securetunnel.SourceProxyOptions) (sourceProxy, error)

type deleteTokenFunc func(profile string) error

// openCertStoreFunc returns a *certcache.Store for the given profile.
type openCertStoreFunc func(profile string) (*certcache.Store, error)

// execSSHFunc runs ssh; spawn-and-wait shape (not syscall.Exec) keeps the
// seam mockable.
type execSSHFunc func(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error

// execSCPFunc runs scp; distinct from execSSHFunc so tests can capture argv
// per subcommand.
type execSCPFunc func(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error

// timePayloadFetcherFunc requests a signed JWS time payload from the broker.
type timePayloadFetcherFunc func(ctx context.Context, profile ResolvedProfile, accessToken, deviceID, nonce string) (string, error)

// jwsSupplierFunc is the callback execSSHTimefixFunc invokes after reading
// nonce + device-clock from ssh's stdout. Errors abort before any further
// bytes go to the device.
type jwsSupplierFunc func(nonce, deviceClock string) (string, error)

// execSSHTimefixFunc runs ssh with interleaved stdin/stdout for the timefix
// verifier protocol: read nonce + device-clock from stdout, write JWS to
// stdin, propagate the device's exit code unchanged so verifier-side codes
// reach the engineer.
type execSSHTimefixFunc func(ctx context.Context, argv []string, supplier jwsSupplierFunc, stderr io.Writer) (exitCode int, err error)

// openSSHConfWriterFunc returns a *sshconf.Writer rooted at the engineer's
// Postern-managed ssh-config file.
type openSSHConfWriterFunc func() (*sshconf.Writer, error)

// newRuntime returns a fully-defaulted runtime. Empty binaryName falls back
// to DefaultBinaryName.
func newRuntime(binaryName string, options Options) runtime {
	binaryName = resolveBinaryName(binaryName)

	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	envPrefix := EnvPrefixForBinaryName(binaryName)

	return runtime{
		binaryName:         binaryName,
		configPath:         options.ConfigPath,
		lookupEnv:          lookupEnv,
		profileResolver:    defaultProfileResolver(binaryName, options.ConfigPath, envPrefix, lookupEnv),
		loginRunner:        defaultLoginRunner(binaryName),
		accessToken:        defaultAccessToken(binaryName),
		sshCertRequester:   defaultSSHCertRequester,
		tunnelOpener:       defaultTunnelOpener,
		sourceProxyStarter: defaultSourceProxyStarter,
		timePayloadFetch:   defaultTimePayloadFetcher,
		deleteToken:        defaultDeleteToken(binaryName),
		openCertStore:      defaultOpenCertStore(binaryName),
		execSSH:            defaultExecCommand("execSSH"),
		execSSHTimefix:     defaultExecSSHTimefix,
		execSCP:            defaultExecCommand("execSCP"),
		openSSHConfWriter:  defaultOpenSSHConfWriter(binaryName),
	}
}

func defaultTunnelOpener(ctx context.Context, profile ResolvedProfile, accessToken, deviceID string, maxLifetimeMinutes int32) (broker.TunnelOpenResponse, error) {
	return brokerclient.New(profile.Profile.Broker, nil).OpenTunnel(ctx, accessToken, deviceID, maxLifetimeMinutes)
}

func defaultSourceProxyStarter(ctx context.Context, options securetunnel.SourceProxyOptions) (sourceProxy, error) {
	return securetunnel.StartSourceProxy(ctx, options)
}

// defaultExecCommand spawns argv[0] via os/exec. argv[0] resolves via $PATH
// so ssh-wrapper conventions stay intact. label distinguishes the seam in
// error wraps ("execSSH" vs "execSCP").
func defaultExecCommand(label string) func(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
	return func(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
		if len(argv) == 0 {
			return fmt.Errorf("%s: empty argv", label)
		}
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdin = stdin
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		return cmd.Run()
	}
}

// defaultExecSSHTimefix runs ssh, reads nonce + device-clock from stdout,
// asks supplier for the JWS, writes it to stdin and waits for ssh to exit.
// A supplier or stdout-parse error aborts before stdin is touched so a
// partial JWS never reaches the device. A missing device-clock prefix or
// unparseable RFC3339 surfaces as ErrTimefixMalformedDeviceClock so the
// engineer sees a CLI-shaped diagnostic instead of chasing a broker reject.
func defaultExecSSHTimefix(ctx context.Context, argv []string, supplier jwsSupplierFunc, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("execSSHTimefix: empty argv")
	}
	if supplier == nil {
		return 0, errors.New("execSSHTimefix: supplier is required")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = stderr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("execSSHTimefix: stdout pipe: %w", err)
	}
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return 0, fmt.Errorf("execSSHTimefix: stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("execSSHTimefix: start ssh: %w", err)
	}

	// cleanup unblocks the child's read and waits for exit. Every early
	// return uses it; ignoring the close/wait errors is correct because
	// the caller already has a more informative error.
	cleanup := func() int {
		_ = stdinPipe.Close()
		return exitCodeFrom(cmd.Wait())
	}

	stdoutReader := bufio.NewReader(stdoutPipe)
	nonce, readErr := stdoutReader.ReadString('\n')
	nonce = strings.TrimRight(nonce, "\r\n")
	if readErr != nil && nonce == "" {
		// Surface the read error alongside the device's exit code so
		// ssh-side failure is distinguishable from device-side failure.
		return cleanup(), fmt.Errorf("execSSHTimefix: read nonce: %w", readErr)
	}

	// Validate nonce shape before reading further. Misconfigured devices
	// emit diagnostic strings here (e.g. nologin's "account is currently
	// not available") which would otherwise present as a confusing EOF
	// on the next line.
	if err := validateTimefixNonce(nonce); err != nil {
		cleanup()
		return 0, fmt.Errorf("%w: got %q", err, nonce)
	}

	clockLine, clockReadErr := stdoutReader.ReadString('\n')
	clockLine = strings.TrimRight(clockLine, "\r\n")
	if clockReadErr != nil && clockLine == "" {
		// Verifier crashed between nonce and clock emits. Surface as a
		// CLI-shaped error including the partial state.
		cleanup()
		return 0, fmt.Errorf("%w: %v (read nonce=%q before EOF)", ErrTimefixMalformedDeviceClock, clockReadErr, nonce)
	}
	deviceClock, ok := strings.CutPrefix(clockLine, "device-clock: ")
	if !ok {
		cleanup()
		return 0, fmt.Errorf("%w: missing prefix in %q", ErrTimefixMalformedDeviceClock, clockLine)
	}

	jws, supplyErr := supplier(nonce, deviceClock)
	if supplyErr != nil {
		cleanup()
		return 0, supplyErr
	}

	if _, err := io.WriteString(stdinPipe, jws+"\n"); err != nil {
		cleanup()
		return 0, fmt.Errorf("execSSHTimefix: write JWS: %w", err)
	}
	if err := stdinPipe.Close(); err != nil {
		// Close is normal-flow here (device reads EOF, exec's the
		// setter); surface the device's exit code via cleanup() so
		// the close failure doesn't mask the verifier outcome.
		return cleanup(), fmt.Errorf("execSSHTimefix: close stdin: %w", err)
	}

	waitErr := cmd.Wait()
	exitCode := exitCodeFrom(waitErr)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitCode, fmt.Errorf("execSSHTimefix: ssh exited with code %d", exitCode)
		}
		return exitCode, fmt.Errorf("execSSHTimefix: wait: %w", waitErr)
	}
	return exitCode, nil
}

// exitCodeFrom unwraps *exec.ExitError into the underlying exit code.
// nil → 0; unknown shapes → 1 so the caller always has a non-negative int.
func exitCodeFrom(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func resolveConfigPath(binaryName string, configPath string) (string, error) {
	if configPath != "" {
		return configPath, nil
	}

	path, err := DefaultConfigPath(binaryName)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return path, nil
}
