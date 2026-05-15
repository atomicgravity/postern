// Package cliapp builds the Postern CLI as an importable cobra root.
// Wrappers reuse subcommand handlers, profile resolution, and OAuth /
// broker plumbing without forking. The unwrapped binary calls
// New(Options{}); wrappers override BinaryName, ConfigPath, or
// Stdout/Stderr to brand or test.
package cliapp

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/atomicgravity/postern/internal/version"
	"github.com/spf13/cobra"
)

// DefaultBinaryName is the cobra root's Use value when Options.BinaryName
// is empty.
const DefaultBinaryName = "postern"

// ErrNotImplemented is returned by subcommand placeholders.
var ErrNotImplemented = errors.New("command not implemented")

// VersionInfo is the version trio rendered by `version` and --version. An
// empty VersionInfo falls back to the build-injected internal/version values.
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

// Options is the constructor input for New. Every field is optional.
// Stdout / Stderr install on the cobra root; handlers reach them via
// cmd.OutOrStdout() / cmd.ErrOrStderr() automatically — pass a buffer here
// to capture all subcommand output in tests.
type Options struct {
	BinaryName string
	ConfigPath string
	LookupEnv  func(string) (string, bool)
	Stdout     io.Writer
	Stderr     io.Writer
	Version    VersionInfo
}

// New returns the assembled cobra root.
func New(options Options) *cobra.Command {
	stdout := options.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	stderr := options.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	versionInfo := options.Version
	if versionInfo == (VersionInfo{}) {
		versionInfo = currentVersionInfo()
	}
	rt := newRuntime(options.BinaryName, options)

	root := &cobra.Command{
		Use:           rt.binaryName,
		Short:         "SSH access framework for embedded Linux device fleets",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       formatVersion(versionInfo),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")

	root.AddCommand(
		loginCommand(rt),
		mintCommand(rt),
		sshCommand(rt),
		scpCommand(rt),
		tunnelCommand(rt),
		addHostCommand(rt),
		removeHostCommand(rt),
		cacheCommand(rt),
		timefixCommand(rt),
		placeholderCommand("upgrade", "Upgrade the CLI from the configured release channel"),
		logoutCommand(rt),
		configureCommand(rt),
		versionCommand(versionInfo),
	)

	return root
}

func placeholderCommand(use string, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("%s: %w", cmd.Name(), ErrNotImplemented)
		},
	}
}

func versionCommand(versionInfo VersionInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", cmd.Root().Name(), formatVersion(versionInfo))
			return err
		},
	}
}

func currentVersionInfo() VersionInfo {
	return VersionInfo{
		Version: version.Version,
		Commit:  version.Commit,
		Date:    version.Date,
	}
}

func normalizeVersionInfo(info VersionInfo) VersionInfo {
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
}

func formatVersion(info VersionInfo) string {
	info = normalizeVersionInfo(info)
	return fmt.Sprintf("%s (commit %s, built %s)", info.Version, info.Commit, info.Date)
}
