package cliapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/atomicgravity/postern/internal/atomicfile"
	"github.com/spf13/cobra"
)

const setupSSHCheckFlag = "check"

// setupSSHCommand wires the Postern-managed ssh.conf into the engineer's
// ~/.ssh/config via an Include directive. This is the single place Postern is
// allowed to write ~/.ssh/config; the implicit paths (add-host, mint, tunnel)
// stay read-only on that file.
func setupSSHCommand(rt runtime) *cobra.Command {
	var check bool

	command := &cobra.Command{
		Use:   "setup-ssh",
		Short: "Add the Include line for the Postern-managed ssh.conf to ~/.ssh/config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if check {
				return runSetupSSHCheck(cmd, rt)
			}
			return runSetupSSH(cmd, rt)
		},
	}

	command.Flags().BoolVar(&check, setupSSHCheckFlag, false, "report whether the Include line is present; exit non-zero if missing")

	return command
}

func runSetupSSHCheck(cmd *cobra.Command, rt runtime) error {
	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if checkIncludePresence(writer.Path()) {
		fmt.Fprintf(out, "Include line for %s is present in ~/.ssh/config.\n", displayIncludePath(writer.Path()))
		return nil
	}
	fmt.Fprintf(out, "Include line for %s is NOT present in ~/.ssh/config.\n", displayIncludePath(writer.Path()))
	fmt.Fprintf(out, "Add it with:  %s setup-ssh\n", resolveBinaryName(rt.binaryName))
	return errors.New("missing Include line in ~/.ssh/config")
}

func runSetupSSH(cmd *cobra.Command, rt runtime) error {
	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	display := displayIncludePath(writer.Path())
	out := cmd.OutOrStdout()

	if checkIncludePresence(writer.Path()) {
		fmt.Fprintf(out, "Include line for %s is already in ~/.ssh/config.\n", display)
		return nil
	}

	configPath, err := userSSHConfigPath()
	if err != nil {
		return err
	}

	if err := prependInclude(configPath, display); err != nil {
		return err
	}

	fmt.Fprintf(out, "Added Include line for %s to ~/.ssh/config.\n", display)
	return nil
}

// prependInclude writes "Include <display>" as the first line of ~/.ssh/config,
// preserving any existing content below it. The directive must precede every
// Host/Match block: ssh applies Include at the point it appears, so a directive
// inside a block's scope only applies to that pattern. The write is atomic — a
// concurrent reader never sees a truncated config. Creates ~/.ssh (0700) and
// ~/.ssh/config (0600) when missing.
func prependInclude(configPath, display string) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	existing, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	content := append([]byte("Include "+display+"\n"), existing...)
	if err := atomicfile.WriteFile(configPath, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	return nil
}
