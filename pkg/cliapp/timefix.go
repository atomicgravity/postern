package cliapp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	timefixQuietFlag = "quiet"
	timefixIPFlag    = "ip"

	// timefixCertTempPrefix's "*.cert" suffix matches certcache's
	// extension so a stray tempfile is recognizable as a postern artifact.
	timefixCertTempPrefix = "postern-timefix-*.cert"

	// timefixNonceDecodedBytes mirrors the broker-side check.
	timefixNonceDecodedBytes = 32
)

// CLI-side validation errors that distinguish device-output faults from
// broker rejections. The device-clock line is engineer-facing diagnostic
// only — detecting locally avoids surfacing an unrelated broker error.
var (
	ErrTimefixEmptyNonce           = errors.New("device emitted empty nonce")
	ErrTimefixMalformedNonce       = errors.New("device emitted malformed nonce")
	ErrTimefixMalformedDeviceClock = errors.New("device emitted malformed device-clock line")
)

func timefixCommand(rt runtime) *cobra.Command {
	var (
		quiet bool
		ip    string
	)

	command := &cobra.Command{
		Use:   "timefix <device-id>",
		Short: "Repair a device's clock through the on-device timefix path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTimefix(cmd, rt, args[0], timefixOptions{Quiet: quiet, IP: ip})
		},
	}

	command.Flags().BoolVar(&quiet, timefixQuietFlag, false, "suppress progress output to stderr")
	command.Flags().StringVar(&ip, timefixIPFlag, "", "device IP or hostname to connect to (sets ssh -o HostName=); the connect target stays timefix@<device-id>")

	return command
}

type timefixOptions struct {
	Quiet bool
	IP    string
}

// runTimefix orchestrates the broken-clock recovery flow: mint timefix cert
// to a tempfile, ssh to the timefix principal, read the device-emitted
// nonce + clock, request the JWS, pipe it to stdin, propagate exit code.
// Cert tempfile is removed on every exit path. Verbose progress is on by
// default — recovery wants visibility.
func runTimefix(cmd *cobra.Command, rt runtime, deviceID string, options timefixOptions) error {
	deviceID = strings.TrimSpace(deviceID)
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}
	verbose := !options.Quiet

	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return err
	}

	_, profilePub, err := store.ProfileKey()
	if err != nil {
		return fmt.Errorf("load profile key: %w", err)
	}
	_, keyPath, err := store.CachePath(deviceID)
	if err != nil {
		return err
	}

	accessToken, err := rt.accessToken(cmd.Context(), profile)
	if err != nil {
		return mintAuthError(rt.binaryName, profile.Name, err)
	}

	verbosef(cmd, verbose, "minting timefix cert for %q via %s", deviceID, profile.Profile.Broker)

	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(profilePub)))
	response, err := rt.sshCertRequester(cmd.Context(), profile, accessToken, broker.SSHCertIssueRequest{
		DeviceID:      deviceID,
		PrincipalType: broker.PrincipalTypeTimefix,
		PublicKey:     publicKey,
	})
	if err != nil {
		return err
	}

	cert, err := parseIssuedCert(response.SSHCert)
	if err != nil {
		return err
	}

	certPath, removeCert, err := writeTimefixCertTempfile(response.SSHCert)
	if err != nil {
		return err
	}
	defer removeCert()

	verbosef(cmd, verbose, "minted timefix cert for %q (serial %d, principals %v); wrote to %s",
		deviceID, cert.Serial, cert.ValidPrincipals, certPath)

	argv := buildTimefixSSHArgv(keyPath, certPath, deviceID, options.IP)
	verbosef(cmd, verbose, "exec: %s", strings.Join(argv, " "))

	exitCode, err := rt.execSSHTimefix(cmd.Context(), argv, func(nonce, deviceClock string) (string, error) {
		if err := validateTimefixNonce(nonce); err != nil {
			return "", err
		}
		verbosef(cmd, verbose, "received nonce from device (device clock: %s); requesting time payload", deviceClock)
		jws, err := rt.timePayloadFetch(cmd.Context(), profile, accessToken, deviceID, nonce)
		if err != nil {
			return "", err
		}
		verbosef(cmd, verbose, "received signed time payload; piping to device")
		return jws, nil
	}, cmd.ErrOrStderr())
	if err != nil {
		if exitCode != 0 {
			return fmt.Errorf("timefix on %q failed (device exit %d): %w", deviceID, exitCode, err)
		}
		return fmt.Errorf("timefix on %q: %w", deviceID, err)
	}
	if exitCode != 0 {
		return fmt.Errorf("timefix on %q failed: device verifier exited with code %d", deviceID, exitCode)
	}
	verbosef(cmd, verbose, "timefix on %q complete: device verifier exited 0", deviceID)
	return nil
}

// buildTimefixSSHArgv assembles ssh's argv for the timefix principal. -T
// disables TTY allocation — a pty would interpose line discipline and
// corrupt the streaming JWS bytes.
func buildTimefixSSHArgv(keyPath, certPath, host, ip string) []string {
	argv := []string{
		"ssh",
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		argv = append(argv, "-o", "HostName="+ip)
	}
	argv = append(argv, "-T", "timefix@"+host)
	return argv
}

// writeTimefixCertTempfile writes sshCert to a 0600 tempfile and returns
// the path + idempotent removal closure.
func writeTimefixCertTempfile(sshCert string) (string, func(), error) {
	tempFile, err := os.CreateTemp("", timefixCertTempPrefix)
	if err != nil {
		return "", nil, fmt.Errorf("create timefix cert tempfile: %w", err)
	}
	tempPath := tempFile.Name()
	remove := func() { _ = os.Remove(tempPath) }

	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		remove()
		return "", nil, fmt.Errorf("chmod timefix cert tempfile: %w", err)
	}
	if _, err := tempFile.WriteString(sshCert); err != nil {
		tempFile.Close()
		remove()
		return "", nil, fmt.Errorf("write timefix cert tempfile: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		remove()
		return "", nil, fmt.Errorf("close timefix cert tempfile: %w", err)
	}

	return tempPath, remove, nil
}

// validateTimefixNonce mirrors the broker's nonce-shape check so device-
// output faults surface distinctly from broker rejections.
func validateTimefixNonce(nonce string) error {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return ErrTimefixEmptyNonce
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTimefixMalformedNonce, err)
	}
	if len(decoded) != timefixNonceDecodedBytes {
		return fmt.Errorf("%w: decoded length %d, want %d", ErrTimefixMalformedNonce, len(decoded), timefixNonceDecodedBytes)
	}
	return nil
}
