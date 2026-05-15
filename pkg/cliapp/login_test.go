package cliapp

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoginResolvesProfile(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
default:
  broker: https://postern.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://postern.example.com
`)
	var gotProfile ResolvedProfile
	rt := newRuntimeForTest(Options{ConfigPath: configPath, LookupEnv: emptyEnv})
	rt.loginRunner = func(ctx context.Context, profile ResolvedProfile, output io.Writer) error {
		gotProfile = profile
		return nil
	}
	root := rootWithLoginForTest(rt, nil)

	if err := execute(context.Background(), root, "login"); err != nil {
		t.Fatalf("Run(login) error = %v", err)
	}
	if got, want := gotProfile.Name, "default"; got != want {
		t.Fatalf("login profile name = %q, want %q", got, want)
	}
	if got, want := gotProfile.Profile.IDP.ClientID, "client-123"; got != want {
		t.Fatalf("login client id = %q, want %q", got, want)
	}
}

func TestLoginReturnsConfigErrors(t *testing.T) {
	missingConfigPath := filepath.Join(t.TempDir(), "missing.yaml")
	root := New(Options{ConfigPath: missingConfigPath, LookupEnv: emptyEnv})

	err := execute(context.Background(), root, "login")
	if err == nil {
		t.Fatal("Run(login) returned nil error")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("Run(login) error = %v, want load config error", err)
	}
}

func TestLoginUsesInjectedProfileResolver(t *testing.T) {
	resolverCalls := 0
	loginCalls := 0
	rt := newRuntimeForTest(Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
	})
	rt.profileResolver = func(cmd *cobra.Command) (ResolvedProfile, error) {
		resolverCalls++
		return ResolvedProfile{
			Name: "wrapped",
			Profile: Profile{
				Broker: "https://wrapped.example.com",
				IDP: IDPConfig{
					Issuer:   "https://idp-wrapped.example.com",
					ClientID: "wrapped-client",
					Scopes:   "postern/wrapped-access",
				},
			},
		}, nil
	}
	rt.loginRunner = func(ctx context.Context, profile ResolvedProfile, output io.Writer) error {
		loginCalls++
		if profile.Name != "wrapped" {
			t.Fatalf("login profile = %q, want wrapped", profile.Name)
		}
		return nil
	}
	root := rootWithLoginForTest(rt, nil)

	if err := execute(context.Background(), root, "login"); err != nil {
		t.Fatalf("Run(login) error = %v", err)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolverCalls)
	}
	if loginCalls != 1 {
		t.Fatalf("login calls = %d, want 1", loginCalls)
	}
}

func TestLoginUsesProfileFlag(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
staging:
  broker: https://staging.example.com
  idp:
    issuer: https://idp-staging.example.com
    client_id: client-456
    scopes: postern/cli-access
`)
	var gotProfile string
	rt := newRuntimeForTest(Options{ConfigPath: configPath, LookupEnv: emptyEnv})
	rt.loginRunner = func(ctx context.Context, profile ResolvedProfile, output io.Writer) error {
		gotProfile = profile.Name
		return nil
	}
	root := rootWithLoginForTest(rt, nil)

	if err := execute(context.Background(), root, "--profile", "staging", "login"); err != nil {
		t.Fatalf("Run(login) error = %v", err)
	}
	if got, want := gotProfile, "staging"; got != want {
		t.Fatalf("login profile = %q, want %q", got, want)
	}
}

func TestLoginWritesDisplayName(t *testing.T) {
	var stdout bytes.Buffer
	rt := newRuntimeForTest(Options{})
	rt.profileResolver = func(cmd *cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default"}, nil
	}
	rt.loginRunner = func(ctx context.Context, profile ResolvedProfile, output io.Writer) error {
		_, err := output.Write([]byte("Logged in as engineer@example.com\n"))
		return err
	}
	root := rootWithLoginForTest(rt, &stdout)

	if err := execute(context.Background(), root, "login"); err != nil {
		t.Fatalf("Run(login) error = %v", err)
	}
	if got, want := stdout.String(), "Logged in as engineer@example.com\n"; got != want {
		t.Fatalf("login output = %q, want %q", got, want)
	}
}

func rootWithLoginForTest(rt runtime, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(loginCommand(rt))
	return root
}
