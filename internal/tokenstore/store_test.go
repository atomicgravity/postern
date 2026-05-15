package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestKeychainRoundTrip(t *testing.T) {
	client := newFakeKeyringClient()
	store := newKeychain("acme-access", client)
	state := sampleState()

	if err := store.Save("staging", state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	refreshToken, ok := client.values["acme-access\x00staging:refresh-token"]
	if !ok {
		t.Fatal("refresh token key was not saved")
	}
	if refreshToken != state.RefreshToken {
		t.Fatalf("refresh token = %q, want %q", refreshToken, state.RefreshToken)
	}
	accessToken, ok := client.values["acme-access\x00staging:access-token"]
	if !ok {
		t.Fatal("access token key was not saved")
	}
	if accessToken != state.AccessToken {
		t.Fatalf("access token = %q, want %q", accessToken, state.AccessToken)
	}
	if _, ok := client.values["acme-access\x00staging:metadata"]; !ok {
		t.Fatal("metadata key was not saved")
	}

	got, err := store.Load("staging")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertStateEqual(t, got, state)
}

func TestKeychainLoadAllowsMissingAccessToken(t *testing.T) {
	client := newFakeKeyringClient()
	store := newKeychain("postern", client)
	state := sampleState()

	if err := store.Save("default", state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	delete(client.values, "postern\x00default:access-token")

	got, err := store.Load("default")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	state.AccessToken = ""
	assertStateEqual(t, got, state)
}

func TestKeychainLoadMissing(t *testing.T) {
	store := newKeychain("postern", newFakeKeyringClient())

	_, err := store.Load("default")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestKeychainDeleteRemovesEntries(t *testing.T) {
	client := newFakeKeyringClient()
	store := newKeychain("postern", client)
	if err := store.Save("default", sampleState()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Delete("default"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(client.values) != 0 {
		t.Fatalf("remaining keyring values = %#v, want empty", client.values)
	}
}

func TestKeychainIntegration(t *testing.T) {
	if os.Getenv("POSTERN_KEYCHAIN_INTEGRATION") != "1" {
		t.Skip("set POSTERN_KEYCHAIN_INTEGRATION=1 to exercise the OS keychain")
	}

	service := "postern-test"
	profile := "integration-test"
	store := NewKeychain(service)
	state := sampleState()
	state.RefreshToken = "postern-keychain-integration-refresh-token"

	if err := store.Save(profile, state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if os.Getenv("POSTERN_KEYCHAIN_KEEP") != "1" {
		defer func() {
			if err := store.Delete(profile); err != nil {
				t.Errorf("Delete() cleanup error = %v", err)
			}
		}()
	} else {
		t.Logf("left keychain entries for inspection: service=%q accounts=%q,%q,%q", service, key(profile, accessTokenKeySuffix), key(profile, refreshTokenKeySuffix), key(profile, metadataKeySuffix))
	}

	got, err := store.Load(profile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertStateEqual(t, got, state)
}

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewFile(dir)
	state := sampleState()

	if err := store.Save("team/dev", state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	path := filepath.Join(dir, "state-team%2Fdev.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if runtime.GOOS != "windows" {
		assertFileMode(t, dir, 0o700)
		assertFileMode(t, path, 0o600)
	}

	got, err := store.Load("team/dev")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	assertStateEqual(t, got, state)
}

func TestFileDeleteMissingSucceeds(t *testing.T) {
	store := NewFile(t.TempDir())

	if err := store.Delete("default"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

// TestFileSaveOverwriteIsAtomic regression-guards the temp-file + rename Save
// path: an overwrite must leave the destination file with the new full payload,
// never the zero-length window the older O_TRUNC + Write sequence exposed on a
// process kill. Also confirms no .tmp leftover from the rename path.
func TestFileSaveOverwriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	store := NewFile(dir)

	first := sampleState()
	first.AccessToken = "first-access-token"
	if err := store.Save("default", first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	second := sampleState()
	second.AccessToken = "second-access-token"
	if err := store.Save("default", second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}

	got, err := store.Load("default")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.AccessToken != second.AccessToken {
		t.Fatalf("access token after overwrite = %q, want %q", got.AccessToken, second.AccessToken)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Fatalf("orphan temp file present: %q", entry.Name())
		}
	}
}

func TestStateVersionMismatch(t *testing.T) {
	_, err := decodeState([]byte(`{"version":2,"idp_issuer":"https://idp.example.com","idp_client_id":"client","refresh_token":"refresh"}`))
	if !errors.Is(err, ErrUnsupportedStateVersion) {
		t.Fatalf("decodeState() error = %v, want ErrUnsupportedStateVersion", err)
	}
}

func TestDecodeStateValidatesRequiredFields(t *testing.T) {
	_, err := decodeState([]byte(`{"version":1,"idp_issuer":"https://idp.example.com","idp_client_id":"client"}`))
	if err == nil {
		t.Fatal("decodeState() returned nil error")
	}
	if !errors.Is(err, ErrTokenStateRefreshTokenRequired) {
		t.Fatalf("decodeState() error = %v, want ErrTokenStateRefreshTokenRequired", err)
	}
}

type fakeKeyringClient struct {
	values map[string]string
}

func newFakeKeyringClient() *fakeKeyringClient {
	return &fakeKeyringClient{values: map[string]string{}}
}

func (c *fakeKeyringClient) Get(service string, user string) (string, error) {
	value, ok := c.values[service+"\x00"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (c *fakeKeyringClient) Set(service string, user string, password string) error {
	c.values[service+"\x00"+user] = password
	return nil
}

func (c *fakeKeyringClient) Delete(service string, user string) error {
	key := service + "\x00" + user
	if _, ok := c.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(c.values, key)
	return nil
}

func sampleState() State {
	return State{
		IDPIssuer:             "https://idp.example.com",
		IDPClientID:           "client-123",
		AccessToken:           "access-token-123",
		RefreshToken:          "refresh-token-123",
		RefreshTokenExpiresAt: 1777777777,
		Subject:               "user-123",
		Email:                 "engineer@example.com",
		IssuedAt:              1777000000,
	}
}

func assertStateEqual(t *testing.T, got State, want State) {
	t.Helper()
	want.Version = StateVersion
	if got != want {
		t.Fatalf("State = %#v, want %#v", got, want)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%q) = %v, want %v", path, got, want)
	}
}
