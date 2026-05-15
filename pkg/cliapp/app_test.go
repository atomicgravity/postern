package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewDefaultsBinaryName(t *testing.T) {
	root := New(Options{})

	if root.Name() != DefaultBinaryName {
		t.Fatalf("Name() = %q, want %q", root.Name(), DefaultBinaryName)
	}
}

func TestRunVersionUsesConfiguredBinaryName(t *testing.T) {
	var stdout bytes.Buffer
	root := New(Options{
		BinaryName: "acme-access",
		Stdout:     &stdout,
		Version: VersionInfo{
			Version: "1.2.3",
			Commit:  "abc123",
			Date:    "2026-05-02",
		},
	})

	if err := execute(context.Background(), root, "version"); err != nil {
		t.Fatalf("Run(version) returned error: %v", err)
	}

	if got, want := stdout.String(), "acme-access 1.2.3 (commit abc123, built 2026-05-02)\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRunHelpListsExpectedCommands(t *testing.T) {
	var stdout bytes.Buffer
	root := New(Options{Stdout: &stdout})

	if err := execute(context.Background(), root, "help"); err != nil {
		t.Fatalf("Run(help) returned error: %v", err)
	}

	output := stdout.String()
	for _, want := range []string{
		"Usage:",
		"Available Commands:",
		"login",
		"ssh",
		"scp",
		"tunnel",
		"timefix",
		"upgrade",
		"logout",
		"configure",
		"version",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("help output missing %q:\n%s", want, output)
		}
	}
}

// TestTimefixSubcommandReturnsConfigErrors keeps the boundary check that
// timefix surfaces a load-config error from the profile resolver before any
// broker work. The original placeholder pattern resolved the profile up
// front so a missing config file failed fast with a clear message; the real
// subcommand preserves that contract.
func TestTimefixSubcommandReturnsConfigErrors(t *testing.T) {
	missingConfigPath := filepath.Join(t.TempDir(), "missing.yaml")
	root := New(Options{ConfigPath: missingConfigPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root, "timefix", "device-1234")
	if err == nil {
		t.Fatal("Run(timefix) returned nil error")
	}
	if errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Run(timefix) error = %v, want config error", err)
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("Run(timefix) error = %v, want load config error", err)
	}
}

func TestCommandProfileNameReadsProfileFlag(t *testing.T) {
	var gotProfile string
	root := New(Options{})
	root.AddCommand(&cobra.Command{
		Use:  "capture-profile",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			gotProfile = CommandProfileName(cmd)
		},
	})

	if err := execute(context.Background(), root, "--profile", "staging", "capture-profile"); err != nil {
		t.Fatalf("Run(capture-profile) returned error: %v", err)
	}
	if got, want := gotProfile, "staging"; got != want {
		t.Fatalf("CommandProfileName() = %q, want %q", got, want)
	}
}

// TestCommandProfileNameDerivesEnvFromBinaryName covers the cobra-rooted half
// of env-prefix derivation: when no --profile flag is passed,
// CommandProfileName consults <BINARY>_PROFILE derived from the root command's
// name. Mirrors TestResolveProfileUsesCustomEnvPrefix on the Options-bound
// path — the two paths must derive the same env var name so a wrapper's
// <WRAPPER>_PROFILE works whether engineers use the flag or the env.
func TestCommandProfileNameDerivesEnvFromBinaryName(t *testing.T) {
	t.Setenv("ACME_ACCESS_PROFILE", "staging")

	var gotProfile string
	root := New(Options{BinaryName: "acme-access"})
	root.AddCommand(&cobra.Command{
		Use:  "capture-profile",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			gotProfile = CommandProfileName(cmd)
		},
	})

	if err := execute(context.Background(), root, "capture-profile"); err != nil {
		t.Fatalf("Run(capture-profile) returned error: %v", err)
	}
	if got, want := gotProfile, "staging"; got != want {
		t.Fatalf("CommandProfileName() = %q, want %q", got, want)
	}
}

func execute(ctx context.Context, command *cobra.Command, args ...string) error {
	command.SetArgs(args)
	return command.ExecuteContext(ctx)
}

func writeConfigFileForTest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// newRuntimeForTest builds a runtime via the production constructor so tests
// can overwrite individual func-typed fields to inject seams.
func newRuntimeForTest(options Options) runtime {
	return newRuntime(options.BinaryName, options)
}
