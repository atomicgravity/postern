package cliapp

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// ErrMintNoAuth wraps token-retrieval failures so callers can distinguish
// auth errors from broker/transport errors.
var ErrMintNoAuth = errors.New("no cached access token")

func mintCommand(rt runtime) *cobra.Command {
	var certMaxLifetime time.Duration

	command := &cobra.Command{
		Use:   "mint <device-id>",
		Short: "Mint an SSH certificate for a device and cache it on disk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMint(cmd, rt, args[0], certMaxLifetime)
		},
	}

	command.Flags().DurationVar(&certMaxLifetime, flagCertMaxLifetime, 0, "engineer-requested certificate TTL (e.g. 30m, 4h); zero means use the broker default; the broker clamps it to its per-class ceiling")

	return command
}

// runMint always calls the broker; cache reuse belongs to ssh/scp.
func runMint(cmd *cobra.Command, rt runtime, deviceID string, certMaxLifetime time.Duration) error {
	deviceID = strings.TrimSpace(deviceID)
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}

	certMaxLifetimeMinutes, err := certLifetimeMinutesFromDuration(certMaxLifetime)
	if err != nil {
		return err
	}

	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return err
	}

	cert, err := mintAndCache(cmd, rt, store, profile, deviceID, certMaxLifetimeMinutes, false)
	if err != nil {
		return err
	}

	certPath, keyPath, err := store.CachePath(deviceID)
	if err != nil {
		return err
	}

	// State-aware connect hint: when the device is registered in ssh.conf,
	// the summary collapses to "ssh <device>"; otherwise it suggests
	// add-host with the manual ssh -i ... fallback.
	registered := false
	if writer, werr := rt.openSSHConfWriter(); werr == nil {
		if got, herr := writer.Has(deviceID); herr == nil {
			registered = got
		}
		// "ssh <device>" only works when ~/.ssh/config has the Postern
		// Include line — warn loudly when registered devices would
		// confuse the engineer with "could not resolve hostname".
		if registered && !checkIncludePresence(writer.Path()) {
			warnMissingInclude(cmd.ErrOrStderr(), rt.binaryName, writer.Path(), deviceID)
		}
	}

	return writeMintSummary(cmd.OutOrStdout(), rt.binaryName, deviceID, cert, certPath, keyPath, registered, time.Now())
}

// validateMintDeviceID surfaces a CLI-shaped error before the cache layer's
// generic "invalid device id" can bubble up from a deeper frame.
func validateMintDeviceID(deviceID string) error {
	if deviceID == "" {
		return errors.New("device id is required")
	}
	if strings.ContainsAny(deviceID, "/\\") {
		return fmt.Errorf("invalid device id %q: path separators are not allowed", deviceID)
	}
	if strings.Contains(deviceID, "..") {
		return fmt.Errorf("invalid device id %q: '..' is not allowed", deviceID)
	}
	return nil
}

// mintAuthError wraps a token failure with a copy-paste login hint. The
// %q quoting keeps profile names containing shell metas safe.
func mintAuthError(binaryName, profileName string, cause error) error {
	return fmt.Errorf("%w: %w (run %q --profile %q login)", ErrMintNoAuth, cause, resolveBinaryName(binaryName), profileName)
}

func parseIssuedCert(sshCert string) (*ssh.Certificate, error) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshCert))
	if err != nil {
		return nil, fmt.Errorf("parse minted cert: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("broker returned non-certificate authorized_keys entry (got %T)", parsed)
	}
	return cert, nil
}

// writeMintSummary prints the human-readable result. State-aware: a
// registered device collapses to "ssh <device>"; otherwise the summary
// suggests add-host with a manual ssh -i ... fallback.
func writeMintSummary(out io.Writer, binaryName, deviceID string, cert *ssh.Certificate, certPath, keyPath string, registered bool, now time.Time) error {
	binaryName = resolveBinaryName(binaryName)

	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()
	remaining := validBefore.Sub(now).Round(time.Second)

	if _, err := fmt.Fprintf(out, "Cert minted for %s. Valid until %s (%s remaining).\n",
		deviceID, validBefore.Format(time.RFC3339), formatRemaining(remaining)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "  Cert: %s\n  Key:  %s\n\n", certPath, keyPath); err != nil {
		return err
	}

	if registered {
		_, err := fmt.Fprintf(out, "Connect with:\n  ssh %s\n", deviceID)
		return err
	}

	if _, err := fmt.Fprintf(out, "Register the device for vanilla ssh:\n  %s add-host %s --ip <device-ip>\n\n",
		binaryName, deviceID); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Or use directly:\n  ssh -i %s \\\n      -o CertificateFile=%s \\\n      engineer@<device-ip>\n",
		keyPath, certPath)
	return err
}

func formatRemaining(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	return d.String()
}

func defaultOpenCertStore(binaryName string) openCertStoreFunc {
	return func(profile string) (*certcache.Store, error) {
		baseDir, err := defaultCacheBaseDir(binaryName)
		if err != nil {
			return nil, err
		}
		return certcache.OpenStore(baseDir, strings.TrimSpace(profile))
	}
}

func defaultCacheBaseDir(binaryName string) (string, error) {
	return BinaryHomeSubdir(binaryName, "cache")
}
