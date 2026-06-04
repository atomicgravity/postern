package cliapp

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestLogoutDeletesSelectedProfile(t *testing.T) {
	tokenStore := &recordingTokenStore{}
	var stdout bytes.Buffer
	resolved := ResolvedProfile{Name: "staging", Profile: Profile{TokenStore: "file"}}
	root := rootWithLogoutForTest(tokenStore, &stdout, resolved, nil)

	if err := execute(context.Background(), root, "--profile", "staging", "logout"); err != nil {
		t.Fatalf("Run(logout) error = %v", err)
	}
	if got, want := tokenStore.deleted.Name, "staging"; got != want {
		t.Fatalf("deleted profile = %q, want %q", got, want)
	}
	if got, want := tokenStore.deleted.Profile.TokenStore, "file"; got != want {
		t.Fatalf("deleted profile token_store = %q, want %q (backend should flow through)", got, want)
	}
	if got, want := stdout.String(), "Logged out of profile \"staging\"\n"; got != want {
		t.Fatalf("logout output = %q, want %q", got, want)
	}
}

// TestLogoutFallsBackOnResolveError verifies that an unresolvable profile
// (missing / broken config, or an orphaned name) doesn't block logout: the
// command still clears the bare profile name via the default backend.
func TestLogoutFallsBackOnResolveError(t *testing.T) {
	tokenStore := &recordingTokenStore{}
	var stdout bytes.Buffer
	root := rootWithLogoutForTest(tokenStore, &stdout, ResolvedProfile{}, errors.New("profile not found"))

	if err := execute(context.Background(), root, "--profile", "ghost", "logout"); err != nil {
		t.Fatalf("Run(logout) error = %v", err)
	}
	if got, want := tokenStore.deleted.Name, "ghost"; got != want {
		t.Fatalf("deleted profile = %q, want %q (should fall back to bare name)", got, want)
	}
}

func TestLogoutReturnsDeleteError(t *testing.T) {
	tokenStore := &recordingTokenStore{deleteErr: errors.New("delete failed")}
	root := rootWithLogoutForTest(tokenStore, nil, ResolvedProfile{Name: "default"}, nil)

	err := execute(context.Background(), root, "logout")
	if err == nil {
		t.Fatal("Run(logout) returned nil error")
	}
	if !errors.Is(err, tokenStore.deleteErr) {
		t.Fatalf("Run(logout) error = %v, want delete error", err)
	}
}

type recordingTokenStore struct {
	deleted   ResolvedProfile
	deleteErr error
}

func (s *recordingTokenStore) Delete(profile ResolvedProfile) error {
	s.deleted = profile
	return s.deleteErr
}

func rootWithLogoutForTest(tokenStore *recordingTokenStore, stdout *bytes.Buffer, resolved ResolvedProfile, resolveErr error) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return resolved, resolveErr
	}
	rt.deleteToken = tokenStore.Delete
	root.AddCommand(logoutCommand(rt))
	return root
}
