package certcache

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestOpenStoreCreatesProfileDir(t *testing.T) {
	base := t.TempDir()
	store, err := OpenStore(base, "default")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}

	profileDir := filepath.Join(base, "default")
	info, err := os.Stat(profileDir)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", profileDir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%q is not a directory", profileDir)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Fatalf("profile dir mode = %v, want 0700", mode)
		}
	}

	if _, err := os.Stat(filepath.Join(profileDir, "key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile key created eagerly: stat err = %v", err)
	}
	_ = store
}

func TestOpenStoreRejectsBadProfile(t *testing.T) {
	base := t.TempDir()
	cases := []string{"", "  ", ".", "..", "a/b", "x\\y"}
	for _, profile := range cases {
		profile := profile
		t.Run("profile="+profile, func(t *testing.T) {
			if _, err := OpenStore(base, profile); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("OpenStore(%q) error = %v, want ErrInvalidProfile", profile, err)
			}
		})
	}

	if _, err := OpenStore("", "default"); err == nil {
		t.Fatal("OpenStore with empty baseDir returned nil error")
	}
}

func TestProfileKeyIsCreatedOnceAndReused(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")

	priv1, pub1, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() first error = %v", err)
	}
	keyPath := filepath.Join(base, "default", "key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", keyPath, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("key file mode = %v, want 0600", mode)
		}
	}

	priv2, pub2, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() second error = %v", err)
	}
	if !priv1.Equal(priv2) {
		t.Fatalf("private key changed across calls on same Store")
	}
	if string(pub1.Marshal()) != string(pub2.Marshal()) {
		t.Fatalf("public key changed across calls on same Store")
	}

	store2 := mustOpenStore(t, base, "default")
	priv3, _, err := store2.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() after reopen error = %v", err)
	}
	if !priv1.Equal(priv3) {
		t.Fatal("private key changed after reopening store on the same directory")
	}
}

func TestPutGetCertRoundTrip(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")

	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)
	cert := ca.mintCert(t, profilePub, "device-1234", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))

	if err := store.PutCert("device-1234", cert); err != nil {
		t.Fatalf("PutCert() error = %v", err)
	}

	certPath := filepath.Join(base, "default", "device-1234.cert")
	info, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", certPath, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o644 {
			t.Fatalf("cert file mode = %v, want 0644", mode)
		}
	}

	store.SetClock(func() time.Time { return time.Unix(1_700_001_000, 0) })
	got, remaining, err := store.GetCert("device-1234")
	if err != nil {
		t.Fatalf("GetCert() error = %v", err)
	}
	if got.Serial != cert.Serial {
		t.Fatalf("cert serial = %d, want %d", got.Serial, cert.Serial)
	}
	if want := 2600 * time.Second; remaining != want {
		t.Fatalf("remaining = %v, want %v", remaining, want)
	}
}

func TestGetCertNotCached(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")

	if _, _, err := store.GetCert("never-minted"); !errors.Is(err, ErrNotCached) {
		t.Fatalf("GetCert() error = %v, want ErrNotCached", err)
	}
}

func TestGetCertExpired(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)
	cert := ca.mintCert(t, profilePub, "device-9", time.Unix(1_700_000_000, 0), time.Unix(1_700_000_001, 0))
	if err := store.PutCert("device-9", cert); err != nil {
		t.Fatalf("PutCert() error = %v", err)
	}

	store.SetClock(func() time.Time { return time.Unix(1_700_000_002, 0) })
	got, remaining, err := store.GetCert("device-9")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("GetCert() error = %v, want ErrExpired", err)
	}
	if got == nil {
		t.Fatal("GetCert() cert is nil under ErrExpired; want non-nil for inspection")
	}
	if remaining != 0 {
		t.Fatalf("remaining = %v, want 0 for expired cert", remaining)
	}
}

func TestPutCertRejectsBadDevice(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)
	cert := ca.mintCert(t, profilePub, "device", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))

	cases := []string{"", "  ", "..", ".", "../escape", "a/b", "x\\y"}
	for _, device := range cases {
		device := device
		t.Run("device="+device, func(t *testing.T) {
			if err := store.PutCert(device, cert); !errors.Is(err, ErrInvalidDevice) {
				t.Fatalf("PutCert(%q) error = %v, want ErrInvalidDevice", device, err)
			}
		})
	}
}

func TestPutCertRejectsMismatchedKey(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	if _, _, err := store.ProfileKey(); err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}

	otherPub, _ := newEd25519PublicKey(t)
	ca := newTestCA(t)
	cert := ca.mintCert(t, otherPub, "device-foreign", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))

	if err := store.PutCert("device-foreign", cert); !errors.Is(err, ErrCertKeyMismatch) {
		t.Fatalf("PutCert() error = %v, want ErrCertKeyMismatch", err)
	}
}

// TestPutCertDetectsTamperedProfileKey simulates an engineer overwriting the
// profile key out-of-band (e.g. copying a key file from another machine)
// after a cert was minted against the original key. Subsequent PutCert
// calls for that cert must fail rather than silently writing a cert that
// won't authenticate.
func TestPutCertDetectsTamperedProfileKey(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)
	cert := ca.mintCert(t, profilePub, "device-1", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))

	keyPath := filepath.Join(base, "default", "key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("Remove(%q) error = %v", keyPath, err)
	}
	_, replacementPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	block, err := ssh.MarshalPrivateKey(replacementPriv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", keyPath, err)
	}

	freshStore := mustOpenStore(t, base, "default")
	if err := freshStore.PutCert("device-1", cert); !errors.Is(err, ErrCertKeyMismatch) {
		t.Fatalf("PutCert() error = %v, want ErrCertKeyMismatch", err)
	}
}

func TestPutCertOverwriteIsAtomic(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)

	first := ca.mintCert(t, profilePub, "device-A", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))
	first.Serial = 1
	if err := first.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	if err := store.PutCert("device-A", first); err != nil {
		t.Fatalf("PutCert(first) error = %v", err)
	}

	second := ca.mintCert(t, profilePub, "device-A", time.Unix(1_700_000_500, 0), time.Unix(1_700_007_200, 0))
	second.Serial = 2
	if err := second.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	if err := store.PutCert("device-A", second); err != nil {
		t.Fatalf("PutCert(second) error = %v", err)
	}

	store.SetClock(func() time.Time { return time.Unix(1_700_000_600, 0) })
	got, _, err := store.GetCert("device-A")
	if err != nil {
		t.Fatalf("GetCert() error = %v", err)
	}
	if got.Serial != 2 {
		t.Fatalf("cert serial after overwrite = %d, want 2", got.Serial)
	}

	dirents, err := os.ReadDir(filepath.Join(base, "default"))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, dirent := range dirents {
		if strings.HasPrefix(dirent.Name(), ".tmp-") {
			t.Fatalf("temp file leftover: %q", dirent.Name())
		}
	}
}

// TestConcurrentReadersWriters spawns many readers and writers against the
// same device and asserts no reader ever observes a torn or mismatched
// cert. With race detection on, this also catches plain data races in the
// Store implementation.
func TestConcurrentReadersWriters(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)

	const writes = 50
	certs := make([]*ssh.Certificate, writes)
	for i := 0; i < writes; i++ {
		c := ca.mintCert(t, profilePub, "device-X", time.Unix(1_700_000_000, 0), time.Unix(1_700_900_000, 0))
		c.Serial = uint64(i + 1)
		if err := c.SignCert(rand.Reader, ca.signer); err != nil {
			t.Fatalf("SignCert() error = %v", err)
		}
		certs[i] = c
	}
	if err := store.PutCert("device-X", certs[0]); err != nil {
		t.Fatalf("PutCert(seed) error = %v", err)
	}

	store.SetClock(func() time.Time { return time.Unix(1_700_001_000, 0) })

	var wg sync.WaitGroup
	var readErrors atomic.Int64
	stop := make(chan struct{})

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, _, err := store.GetCert("device-X")
				if err != nil {
					if errors.Is(err, ErrNotCached) || errors.Is(err, ErrExpired) {
						continue
					}
					t.Errorf("GetCert() error = %v", err)
					readErrors.Add(1)
					return
				}
				if !publicKeysEqual(got.Key, profilePub) {
					t.Errorf("torn read: cert key does not match profile key")
					readErrors.Add(1)
					return
				}
			}
		}()
	}

	for i, c := range certs {
		if err := store.PutCert("device-X", c); err != nil {
			t.Fatalf("PutCert(%d) error = %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	if readErrors.Load() != 0 {
		t.Fatalf("observed %d read errors", readErrors.Load())
	}
}

// TestConcurrentFirstMintIsExactlyOnceKey verifies that two stores opened on
// the same baseDir + profile cannot both successfully create the profile
// key — the second-to-write loses the O_EXCL race and re-reads the
// already-written key.
func TestConcurrentFirstMintIsExactlyOnceKey(t *testing.T) {
	base := t.TempDir()
	const goroutines = 16
	stores := make([]*Store, goroutines)
	for i := range stores {
		stores[i] = mustOpenStore(t, base, "default")
	}

	privs := make([]ed25519.PrivateKey, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			priv, _, err := stores[i].ProfileKey()
			privs[i] = priv
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("ProfileKey()[%d] error = %v", i, err)
		}
	}
	for i := 1; i < goroutines; i++ {
		if !privs[0].Equal(privs[i]) {
			t.Fatalf("goroutine %d saw a different key than goroutine 0", i)
		}
	}
}

func TestProfileIsolation(t *testing.T) {
	base := t.TempDir()
	storeA := mustOpenStore(t, base, "profileA")
	storeB := mustOpenStore(t, base, "profileB")

	privA, pubA, err := storeA.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey(A) error = %v", err)
	}
	privB, pubB, err := storeB.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey(B) error = %v", err)
	}
	if privA.Equal(privB) {
		t.Fatal("profileA and profileB share the same private key")
	}
	if string(pubA.Marshal()) == string(pubB.Marshal()) {
		t.Fatal("profileA and profileB share the same public key")
	}

	ca := newTestCA(t)
	certA := ca.mintCert(t, pubA, "device-1", time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))
	if err := storeA.PutCert("device-1", certA); err != nil {
		t.Fatalf("PutCert(A, device-1) error = %v", err)
	}

	if _, _, err := storeB.GetCert("device-1"); !errors.Is(err, ErrNotCached) {
		t.Fatalf("GetCert(B, device-1) error = %v, want ErrNotCached", err)
	}

	entriesA, err := storeA.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries(A) error = %v", err)
	}
	if len(entriesA) != 1 || entriesA[0].Device != "device-1" {
		t.Fatalf("ListEntries(A) = %#v, want [device-1]", entriesA)
	}
	entriesB, err := storeB.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries(B) error = %v", err)
	}
	if len(entriesB) != 0 {
		t.Fatalf("ListEntries(B) = %#v, want []", entriesB)
	}
}

func TestListEntriesSortedAndIgnoresJunk(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)

	devices := []string{"device-charlie", "device-alpha", "device-bravo"}
	for _, d := range devices {
		c := ca.mintCert(t, profilePub, d, time.Unix(1_700_000_000, 0), time.Unix(1_700_003_600, 0))
		if err := store.PutCert(d, c); err != nil {
			t.Fatalf("PutCert(%q) error = %v", d, err)
		}
	}

	if err := os.WriteFile(filepath.Join(base, "default", "notes.txt"), []byte("scratch"), 0o644); err != nil {
		t.Fatalf("WriteFile(notes.txt) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "default", "garbage.cert"), []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("WriteFile(garbage.cert) error = %v", err)
	}

	entries, err := store.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Device
	}
	want := []string{"device-alpha", "device-bravo", "device-charlie"}
	if !equalStringSlices(got, want) {
		t.Fatalf("ListEntries devices = %v, want %v", got, want)
	}

	if entries[0].SerialNumber == 0 {
		t.Fatal("entry SerialNumber unset; want broker-side serial parsed from cert")
	}
	if entries[0].ValidBefore.IsZero() || entries[0].ValidAfter.IsZero() {
		t.Fatal("entry validity bounds unset")
	}
}

func TestPruneExpiredRemovesExpiredAndIsIdempotent(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)

	near := time.Unix(1_700_000_000, 0)
	old := ca.mintCert(t, profilePub, "device-old", near, near.Add(1*time.Hour))
	fresh := ca.mintCert(t, profilePub, "device-fresh", near, near.Add(24*time.Hour))
	if err := store.PutCert("device-old", old); err != nil {
		t.Fatalf("PutCert(old) error = %v", err)
	}
	if err := store.PutCert("device-fresh", fresh); err != nil {
		t.Fatalf("PutCert(fresh) error = %v", err)
	}

	pruned, err := store.PruneExpired(near.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("PruneExpired() error = %v", err)
	}
	if !equalStringSlices(pruned, []string{"device-old"}) {
		t.Fatalf("PruneExpired() = %v, want [device-old]", pruned)
	}

	if _, err := os.Stat(filepath.Join(base, "default", "device-old.cert")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("device-old cert still on disk after prune: stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "default", "device-fresh.cert")); err != nil {
		t.Fatalf("device-fresh cert missing after prune: %v", err)
	}

	keyInfo, err := os.Stat(filepath.Join(base, "default", "key"))
	if err != nil {
		t.Fatalf("profile key removed by prune: %v", err)
	}
	if keyInfo.Size() == 0 {
		t.Fatal("profile key truncated by prune")
	}

	pruned2, err := store.PruneExpired(near.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("PruneExpired() second call error = %v", err)
	}
	if len(pruned2) != 0 {
		t.Fatalf("second PruneExpired() = %v, want empty (idempotency)", pruned2)
	}
}

// TestPruneExpiredZeroNowUsesStoreClock verifies the convention unification:
// passing a zero time.Time defers to the Store's clock, the same source
// GetCert reads. Callers that already work in the Store's clock can pass
// time.Time{} instead of duplicating the clock plumbing.
func TestPruneExpiredZeroNowUsesStoreClock(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	ca := newTestCA(t)

	near := time.Unix(1_700_000_000, 0)
	old := ca.mintCert(t, profilePub, "device-old", near, near.Add(1*time.Hour))
	fresh := ca.mintCert(t, profilePub, "device-fresh", near, near.Add(24*time.Hour))
	if err := store.PutCert("device-old", old); err != nil {
		t.Fatalf("PutCert(old) error = %v", err)
	}
	if err := store.PutCert("device-fresh", fresh); err != nil {
		t.Fatalf("PutCert(fresh) error = %v", err)
	}

	store.SetClock(func() time.Time { return near.Add(2 * time.Hour) })
	pruned, err := store.PruneExpired(time.Time{})
	if err != nil {
		t.Fatalf("PruneExpired(zero) error = %v", err)
	}
	if !equalStringSlices(pruned, []string{"device-old"}) {
		t.Fatalf("PruneExpired(zero) = %v, want [device-old]", pruned)
	}
}

func TestCachePathReturnsAbsoluteUnderProfileDir(t *testing.T) {
	base := t.TempDir()
	store := mustOpenStore(t, base, "default")

	certPath, keyPath, err := store.CachePath("device-1")
	if err != nil {
		t.Fatalf("CachePath() error = %v", err)
	}
	if !filepath.IsAbs(certPath) {
		t.Fatalf("certPath %q is not absolute", certPath)
	}
	if !filepath.IsAbs(keyPath) {
		t.Fatalf("keyPath %q is not absolute", keyPath)
	}
	wantCert := filepath.Join(base, "default", "device-1.cert")
	wantKey := filepath.Join(base, "default", "key")
	if certPath != wantCert {
		t.Fatalf("certPath = %q, want %q", certPath, wantCert)
	}
	if keyPath != wantKey {
		t.Fatalf("keyPath = %q, want %q", keyPath, wantKey)
	}

	if _, _, err := store.CachePath("../escape"); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("CachePath(../escape) error = %v, want ErrInvalidDevice", err)
	}
}

// testCA signs SSH certificates with a stable ed25519 authority. The package
// under test only stores certs; the CA exists solely to mint plausible cert
// blobs for the tests.
type testCA struct {
	signer ssh.Signer
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return &testCA{signer: signer}
}

func (ca *testCA) mintCert(t *testing.T, subject ssh.PublicKey, device string, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             subject,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           device + "-operator",
		ValidPrincipals: []string{device + "-operator"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	return cert
}

func newEd25519PublicKey(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return sshPub, priv
}

func mustOpenStore(t *testing.T, base, profile string) *Store {
	t.Helper()
	store, err := OpenStore(base, profile)
	if err != nil {
		t.Fatalf("OpenStore(%q, %q) error = %v", base, profile, err)
	}
	return store
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
