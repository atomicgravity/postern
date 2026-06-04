package cliapp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/atomicgravity/postern/internal/tokenstore"
)

func TestDefaultTokenStore(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		envVal  string
		envSet  bool
		want    any
		wantErr bool
	}{
		{name: "all-unset-defaults-to-keychain", want: tokenstore.Keychain{}},
		{name: "config-keychain", config: "keychain", want: tokenstore.Keychain{}},
		{name: "config-keyring-alias", config: "keyring", want: tokenstore.Keychain{}},
		{name: "config-file", config: "file", want: tokenstore.File{}},
		{name: "config-case-insensitive", config: "  FILE  ", want: tokenstore.File{}},
		{name: "config-unknown-errors", config: "vault", wantErr: true},

		{name: "env-file-no-config", envVal: "file", envSet: true, want: tokenstore.File{}},
		{name: "env-empty-falls-through-to-config", config: "file", envVal: "", envSet: true, want: tokenstore.File{}},
		{name: "env-overrides-config-keychain-wins", config: "file", envVal: "keychain", envSet: true, want: tokenstore.Keychain{}},
		{name: "env-overrides-config-file-wins", config: "keychain", envVal: "file", envSet: true, want: tokenstore.File{}},
		{name: "env-unknown-errors", config: "file", envVal: "vault", envSet: true, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupEnv := func(name string) (string, bool) {
				if name == "POSTERN_TOKEN_STORE" && tc.envSet {
					return tc.envVal, true
				}
				return "", false
			}

			store, err := defaultTokenStore("postern", tc.config, "POSTERN", lookupEnv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("defaultTokenStore() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("defaultTokenStore() error = %v", err)
			}

			switch tc.want.(type) {
			case tokenstore.Keychain:
				if _, ok := store.(tokenstore.Keychain); !ok {
					t.Fatalf("defaultTokenStore() = %T, want tokenstore.Keychain", store)
				}
			case tokenstore.File:
				if _, ok := store.(tokenstore.File); !ok {
					t.Fatalf("defaultTokenStore() = %T, want tokenstore.File", store)
				}
			}
		})
	}
}

// TestDefaultTokenStoreFileDir verifies the file backend persists under
// ~/.<binary-name>/tokens/ so engineers know where the on-disk state lives.
func TestDefaultTokenStoreFileDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}

	store, err := defaultTokenStore("acme-access", "file", "ACME_ACCESS", func(name string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatalf("defaultTokenStore() error = %v", err)
	}

	want := tokenstore.NewFile(filepath.Join(home, ".acme-access", "tokens"))
	if store != want {
		t.Fatalf("defaultTokenStore() = %#v, want %#v", store, want)
	}
}

// TestDefaultDeleteTokenUsesProfileBackend exercises the real defaultDeleteToken
// closure end-to-end: it must thread the resolved profile's token_store into the
// File backend and delete by profile name. This is the one network-free token
// closure, so it guards the profile.TokenStore -> backend wiring that login and
// refresh share but cannot test without an OAuth round trip.
func TestDefaultDeleteTokenUsesProfileBackend(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tokensDir := filepath.Join(home, ".postern", "tokens")
	fileStore := tokenstore.NewFile(tokensDir)
	state := tokenstore.State{
		Version:      tokenstore.StateVersion,
		IDPIssuer:    "https://idp.example.com",
		IDPClientID:  "client-123",
		RefreshToken: "refresh-token",
	}
	if err := fileStore.Save("acct", state); err != nil {
		t.Fatalf("seed Save() error = %v", err)
	}

	deleteToken := defaultDeleteToken("postern", "POSTERN", emptyEnv)
	resolved := ResolvedProfile{Name: "acct", Profile: Profile{TokenStore: "file"}}
	if err := deleteToken(resolved); err != nil {
		t.Fatalf("deleteToken() error = %v", err)
	}

	if _, err := fileStore.Load("acct"); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("after delete, Load() error = %v, want ErrNotFound (file backend should have removed the slot)", err)
	}
}
