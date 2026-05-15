// Package certcache persists per-profile SSH subject keys and per-device
// OpenSSH certificates on local disk for the engineer CLI.
//
// Layout under baseDir:
//
//	<baseDir>/<profile>/key                # ed25519 private key, OpenSSH PEM, 0600
//	<baseDir>/<profile>/<device>.cert      # OpenSSH cert (authorized_keys form), 0644
//
// One subject key per profile is reused across every device under it; the
// cert (not the key) names the device. Key writes use os.Link for
// exactly-once create semantics so concurrent first-mints can't both win
// with different bytes. Cert writes use rename so concurrent readers always
// see either the prior cert or the new one.
//
// GetCert / ListEntries report cert validity bounds; callers decide their
// own safety margin.
package certcache

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atomicgravity/postern/internal/atomicfile"
	"golang.org/x/crypto/ssh"
)

var (
	ErrNotCached = errors.New("certcache: cert not cached")

	// ErrExpired is returned by GetCert when the cert's ValidBefore is in
	// the past; the cert value is still returned for inspection.
	ErrExpired = errors.New("certcache: cached cert expired")

	// ErrInvalidDevice rejects empty device ids and any value containing
	// path separators or "..".
	ErrInvalidDevice = errors.New("certcache: invalid device id")

	// ErrInvalidProfile rejects empty profile names and path-traversal
	// characters.
	ErrInvalidProfile = errors.New("certcache: invalid profile name")

	// ErrCertKeyMismatch is returned by PutCert/GetCert when the cert's
	// subject public key does not match the profile's stored key —
	// catches manual cross-profile file moves and out-of-band key
	// replacement.
	ErrCertKeyMismatch = errors.New("certcache: cert public key does not match profile key")
)

// Store owns a single (baseDir, profile) cache namespace. Concurrent use is
// safe: writes rename into place atomically, and an in-process mutex guards
// first-time key creation against same-process races.
type Store struct {
	baseDir string
	profile string
	now     func() time.Time

	keyMu sync.Mutex
}

// Entry describes one cached cert as surfaced by ListEntries.
type Entry struct {
	Device       string
	CertPath     string
	ValidAfter   time.Time
	ValidBefore  time.Time
	SerialNumber uint64
	KeyID        string
	Principals   []string
}

// OpenStore opens (and lazily creates) the profile cache directory at mode
// 0700. The profile key and cert files are created on demand.
func OpenStore(baseDir, profile string) (*Store, error) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return nil, fmt.Errorf("%w: baseDir is required", ErrInvalidProfile)
	}
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	dir := filepath.Join(baseDir, profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("certcache: create profile dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("certcache: chmod profile dir %q: %w", dir, err)
	}

	return &Store{
		baseDir: baseDir,
		profile: profile,
		now:     time.Now,
	}, nil
}

// SetClock replaces the Store's time source (for tests).
func (s *Store) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// ProfileKey returns the profile's ed25519 keypair, generating and persisting
// it on first call. The key file is created with O_EXCL semantics so
// concurrent first-time callers cannot both win — the loser re-reads the
// on-disk key.
func (s *Store) ProfileKey() (ed25519.PrivateKey, ssh.PublicKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()

	keyPath := s.keyPath()
	priv, pub, err := loadProfileKey(keyPath)
	if err == nil {
		return priv, pub, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("certcache: generate ed25519 key: %w", err)
	}

	if err := writeProfileKeyExclusive(keyPath, priv); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadProfileKey(keyPath)
		}
		return nil, nil, err
	}

	pub, err = ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("certcache: derive ssh public key: %w", err)
	}

	return priv, pub, nil
}

// PutCert atomically writes cert for device. The cert's public key is
// verified against the profile key before any disk write to catch
// cross-profile contamination.
func (s *Store) PutCert(device string, cert *ssh.Certificate) error {
	if err := validateDevice(device); err != nil {
		return err
	}
	if cert == nil {
		return errors.New("certcache: cert is nil")
	}

	_, profilePub, err := s.ProfileKey()
	if err != nil {
		return err
	}
	if !publicKeysEqual(cert.Key, profilePub) {
		return ErrCertKeyMismatch
	}

	marshaled := ssh.MarshalAuthorizedKey(cert)

	return atomicfile.WriteFile(s.certPath(device), marshaled, 0o644)
}

// GetCert returns the cached cert and its remaining validity at the Store's
// clock. An expired-on-disk cert is returned alongside ErrExpired; a
// missing cert returns (nil, 0, ErrNotCached).
func (s *Store) GetCert(device string) (*ssh.Certificate, time.Duration, error) {
	if err := validateDevice(device); err != nil {
		return nil, 0, err
	}

	cert, err := loadCert(s.certPath(device))
	if err != nil {
		return nil, 0, err
	}

	_, profilePub, err := s.ProfileKey()
	if err != nil {
		return nil, 0, err
	}
	if !publicKeysEqual(cert.Key, profilePub) {
		return nil, 0, ErrCertKeyMismatch
	}

	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	remaining := validBefore.Sub(s.now())
	if remaining <= 0 {
		return cert, 0, ErrExpired
	}

	return cert, remaining, nil
}

// CachePath returns the cert and identity-file paths callers pass to
// ssh / scp. The files may not yet exist.
func (s *Store) CachePath(device string) (certPath, keyPath string, err error) {
	if err := validateDevice(device); err != nil {
		return "", "", err
	}
	return s.certPath(device), s.keyPath(), nil
}

// ListEntries returns every cached cert under the profile, sorted by device.
// Unparseable cert files are skipped — the cache is opportunistic.
func (s *Store) ListEntries() ([]Entry, error) {
	dir := s.profileDir()
	dirents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("certcache: read profile dir %q: %w", dir, err)
	}

	var entries []Entry
	for _, dirent := range dirents {
		if dirent.IsDir() {
			continue
		}
		name := dirent.Name()
		if !strings.HasSuffix(name, certFileSuffix) {
			continue
		}
		device := strings.TrimSuffix(name, certFileSuffix)
		certPath := filepath.Join(dir, name)
		cert, err := loadCert(certPath)
		if err != nil {
			continue
		}

		entries = append(entries, Entry{
			Device:       device,
			CertPath:     certPath,
			ValidAfter:   time.Unix(int64(cert.ValidAfter), 0),
			ValidBefore:  time.Unix(int64(cert.ValidBefore), 0),
			SerialNumber: cert.Serial,
			KeyID:        cert.KeyId,
			Principals:   append([]string(nil), cert.ValidPrincipals...),
		})
	}

	slices.SortFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.Device, b.Device)
	})
	return entries, nil
}

// PruneExpired removes every cached cert whose ValidBefore is at or before
// now. The profile key is never touched. Passing a zero time falls back to
// the Store's clock.
func (s *Store) PruneExpired(now time.Time) ([]string, error) {
	if now.IsZero() {
		now = s.now()
	}

	entries, err := s.ListEntries()
	if err != nil {
		return nil, err
	}

	var pruned []string
	for _, entry := range entries {
		if entry.ValidBefore.After(now) {
			continue
		}
		if err := os.Remove(entry.CertPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return pruned, fmt.Errorf("certcache: remove %q: %w", entry.CertPath, err)
		}
		pruned = append(pruned, entry.Device)
	}
	slices.Sort(pruned)
	return pruned, nil
}

const certFileSuffix = ".cert"

func (s *Store) profileDir() string {
	return filepath.Join(s.baseDir, s.profile)
}

func (s *Store) keyPath() string {
	return filepath.Join(s.profileDir(), "key")
}

func (s *Store) certPath(device string) string {
	return filepath.Join(s.profileDir(), device+certFileSuffix)
}

// writeProfileKeyExclusive serializes the ed25519 private key in OpenSSH PEM
// format and writes it atomically with exactly-once semantics via os.Link.
// Returns an os.ErrExist-matching error when another caller won the race.
func writeProfileKeyExclusive(path string, priv ed25519.PrivateKey) error {
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("certcache: marshal private key: %w", err)
	}
	return atomicfile.WriteFileExclusive(path, pem.EncodeToMemory(block), 0o600)
}

func loadProfileKey(path string) (ed25519.PrivateKey, ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("certcache: parse profile key %q: %w", path, err)
	}
	priv, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		// ssh.ParseRawPrivateKey may return the bare value instead of the
		// pointer depending on the input format; accept both shapes.
		ed, ok := raw.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("certcache: profile key %q is not ed25519 (got %T)", path, raw)
		}
		priv = &ed
	}

	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("certcache: derive ssh public key: %w", err)
	}
	return *priv, pub, nil
}

// loadCert reads and parses an OpenSSH cert file. Returns ErrNotCached if
// the file is missing.
func loadCert(path string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("certcache: read cert %q: %w", path, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("certcache: parse cert %q: %w", path, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("certcache: %q is not an SSH certificate (got %T)", path, pub)
	}
	return cert, nil
}

func validateProfile(profile string) error {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return fmt.Errorf("%w: empty", ErrInvalidProfile)
	}
	if profile == "." || profile == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidProfile, profile)
	}
	if strings.ContainsAny(profile, "/\\") {
		return fmt.Errorf("%w: %q contains path separator", ErrInvalidProfile, profile)
	}
	return nil
}

func validateDevice(device string) error {
	device = strings.TrimSpace(device)
	if device == "" {
		return fmt.Errorf("%w: empty", ErrInvalidDevice)
	}
	if device == "." || device == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidDevice, device)
	}
	if strings.ContainsAny(device, "/\\") {
		return fmt.Errorf("%w: %q contains path separator", ErrInvalidDevice, device)
	}
	if strings.Contains(device, "..") {
		return fmt.Errorf("%w: %q contains '..'", ErrInvalidDevice, device)
	}
	return nil
}

func publicKeysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}
