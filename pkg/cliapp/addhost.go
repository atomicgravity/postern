package cliapp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	addHostIPFlag     = "ip"
	addHostPortFlag   = "port"
	addHostUserFlag   = "user"
	addHostNoMintFlag = "no-mint"
)

func addHostCommand(rt runtime) *cobra.Command {
	var (
		ip     string
		port   int
		user   string
		noMint bool
	)

	command := &cobra.Command{
		Use:   "add-host <device-id>",
		Short: "Register a device in the Postern-managed ssh-config (and mint a cert by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAddHost(cmd, rt, args[0], addHostOptions{IP: ip, Port: port, User: user, NoMint: noMint})
		},
	}

	command.Flags().StringVar(&ip, addHostIPFlag, "", "device IP or hostname to add as an additional Host match")
	command.Flags().IntVar(&port, addHostPortFlag, 0, "non-default ssh port (omitted when 0)")
	command.Flags().StringVar(&user, addHostUserFlag, "", "override the profile's default ssh user")
	command.Flags().BoolVar(&noMint, addHostNoMintFlag, false, "skip the cert mint (offline staging / pre-grant); register the stanza only")

	return command
}

type addHostOptions struct {
	IP     string
	Port   int
	User   string
	NoMint bool
}

func runAddHost(cmd *cobra.Command, rt runtime, deviceID string, options addHostOptions) error {
	deviceID = strings.TrimSpace(deviceID)
	if err := validateMintDeviceID(deviceID); err != nil {
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

	// Mint before writing the stanza: a stanza pointing at a missing cache
	// entry yields opaque ssh failures, worse than no stanza at all.
	var mintedCert *ssh.Certificate
	if !options.NoMint {
		cert, err := mintAndCache(cmd, rt, store, profile, deviceID, 0, false)
		if err != nil {
			return err
		}
		mintedCert = cert
	}

	certPath, keyPath, err := store.CachePath(deviceID)
	if err != nil {
		return err
	}

	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	// addhost discards the explicit bool; the stanza always carries a
	// concrete User. ssh / scp re-derive explicitness at read time.
	user, _ := resolveUser(writer, deviceID, options.User, profile)

	stanza := sshconf.Stanza{
		Device:          deviceID,
		User:            user,
		Port:            options.Port,
		IdentityFile:    keyPath,
		CertificateFile: certPath,
	}
	if ip := strings.TrimSpace(options.IP); ip != "" {
		stanza.HostName = ip
		stanza.Patterns = []string{ip}
	}

	if err := writer.Upsert(stanza); err != nil {
		return fmt.Errorf("update %s: %w", writer.Path(), err)
	}

	return writeAddHostSummary(cmd.OutOrStdout(), rt.binaryName, deviceID, writer.Path(), stanza, mintedCert, time.Now(), checkIncludePresence(writer.Path()))
}

// writeAddHostSummary prints the post-Upsert confirmation plus include-line
// guidance, naming the cert validity window when one was minted.
func writeAddHostSummary(out io.Writer, binaryName, deviceID, sshConfPath string, stanza sshconf.Stanza, mintedCert *ssh.Certificate, now time.Time, includePresent bool) error {
	binaryName = resolveBinaryName(binaryName)

	target := stanza.Device
	if len(stanza.Patterns) > 0 {
		target = stanza.Device + " (" + strings.Join(stanza.Patterns, ", ") + ")"
	}

	if _, err := fmt.Fprintf(out, "Registered %s in %s as user %s.\n",
		target, sshConfPath, stanza.User); err != nil {
		return err
	}

	if mintedCert != nil {
		validBefore := time.Unix(int64(mintedCert.ValidBefore), 0).UTC()
		remaining := validBefore.Sub(now).Round(time.Second)
		if _, err := fmt.Fprintf(out, "Cert minted, valid until %s (%s remaining).\n",
			validBefore.Format(time.RFC3339), formatRemaining(remaining)); err != nil {
			return err
		}
	}

	display := displayIncludePath(sshConfPath)
	if includePresent {
		if mintedCert != nil {
			_, err := fmt.Fprintf(out, "\nInclude line for %s is already in ~/.ssh/config.\n\n"+
				"Connect with:\n\n"+
				"  ssh %s\n",
				display, deviceID)
			return err
		}
		_, err := fmt.Fprintf(out, "\nInclude line for %s is already in ~/.ssh/config.\n\n"+
			"Then mint a cert and connect (--no-mint was used; cache is empty):\n\n"+
			"  %s mint %s              # mints; subsequent `ssh %s` works until cert expiry\n",
			display, binaryName, deviceID, deviceID)
		return err
	}

	if mintedCert != nil {
		_, err := fmt.Fprintf(out, "\nThe line `Include %s` was NOT found in ~/.ssh/config.\n"+
			"Wire it up (one-time setup):\n\n"+
			"  %s setup-ssh\n\n"+
			"Then connect with:\n\n"+
			"  ssh %s\n",
			display, binaryName, deviceID)
		return err
	}

	_, err := fmt.Fprintf(out, "\nThe line `Include %s` was NOT found in ~/.ssh/config.\n"+
		"Wire it up (one-time setup):\n\n"+
		"  %s setup-ssh\n\n"+
		"Then mint a cert and connect (--no-mint was used; cache is empty):\n\n"+
		"  %s mint %s              # mints; subsequent `ssh %s` works until cert expiry\n",
		display, binaryName, binaryName, deviceID, deviceID)
	return err
}

// warnMissingInclude writes the "Include line missing" warning shared by
// mint, tunnel_open, and add-host.
func warnMissingInclude(w io.Writer, binaryName, sshConfPath, hostHint string) {
	binaryName = resolveBinaryName(binaryName)
	fmt.Fprintf(w,
		"%s: warning — Include line for %s is NOT in ~/.ssh/config; `ssh %s` will fail\n"+
			"  Wire it up with:  %s setup-ssh\n",
		binaryName, displayIncludePath(sshConfPath), hostHint, binaryName)
}

// checkIncludePresence reports whether ~/.ssh/config has an Include
// directive (either absolute or ~-form) for sshConfPath. Missing
// ~/.ssh/config returns false, not an error.
func checkIncludePresence(sshConfPath string) bool {
	configPath, err := userSSHConfigPath()
	if err != nil {
		return false
	}
	file, err := os.Open(configPath)
	if err != nil {
		return false
	}
	defer file.Close()

	absForm := sshConfPath
	tildeForm := displayIncludePath(sshConfPath)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.EqualFold(fields[0], "Include") {
			continue
		}
		for _, arg := range fields[1:] {
			if arg == absForm || arg == tildeForm {
				return true
			}
		}
	}
	return false
}

// userSSHConfigPath returns ~/.ssh/config. Only setup-ssh writes here; every
// other path treats it read-only.
func userSSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// displayIncludePath converts absPath to the ~-form engineers see in
// summaries. Falls back to absPath when the home prefix doesn't apply.
func displayIncludePath(absPath string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return absPath
	}
	if rel, err := filepath.Rel(home, absPath); err == nil && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	return absPath
}

func defaultOpenSSHConfWriter(binaryName string) openSSHConfWriterFunc {
	return func() (*sshconf.Writer, error) {
		path, err := BinaryHomeFile(binaryName, "ssh.conf")
		if err != nil {
			return nil, err
		}
		return sshconf.NewWriter(path), nil
	}
}
