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
	root := rootWithLogoutForTest(tokenStore, &stdout)

	if err := execute(context.Background(), root, "--profile", "staging", "logout"); err != nil {
		t.Fatalf("Run(logout) error = %v", err)
	}
	if got, want := tokenStore.deletedProfile, "staging"; got != want {
		t.Fatalf("deleted profile = %q, want %q", got, want)
	}
	if got, want := stdout.String(), "Logged out of profile \"staging\"\n"; got != want {
		t.Fatalf("logout output = %q, want %q", got, want)
	}
}

func TestLogoutReturnsDeleteError(t *testing.T) {
	tokenStore := &recordingTokenStore{deleteErr: errors.New("delete failed")}
	root := rootWithLogoutForTest(tokenStore, nil)

	err := execute(context.Background(), root, "logout")
	if err == nil {
		t.Fatal("Run(logout) returned nil error")
	}
	if !errors.Is(err, tokenStore.deleteErr) {
		t.Fatalf("Run(logout) error = %v, want delete error", err)
	}
}

type recordingTokenStore struct {
	deletedProfile string
	deleteErr      error
}

func (s *recordingTokenStore) Delete(profile string) error {
	s.deletedProfile = profile
	return s.deleteErr
}

func rootWithLogoutForTest(tokenStore *recordingTokenStore, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.deleteToken = tokenStore.Delete
	root.AddCommand(logoutCommand(rt))
	return root
}
