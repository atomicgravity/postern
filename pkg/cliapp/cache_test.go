package cliapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func TestCacheListEmpty(t *testing.T) {
	rt, _, stdout := newCacheTestRuntime(t)
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "ls"); err != nil {
		t.Fatalf("Run(cache ls) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "No cached certs") {
		t.Fatalf("stdout missing empty-cache message:\n%s", stdout.String())
	}
}

func TestCacheListShowsAllEntries(t *testing.T) {
	rt, cacheDir, stdout := newCacheTestRuntime(t)
	ca := newMintTestCA(t)
	seedCachedCert(t, cacheDir, ca, "device-bravo", time.Hour)
	seedCachedCert(t, cacheDir, ca, "device-alpha", 30*time.Minute)
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "ls"); err != nil {
		t.Fatalf("Run(cache ls) error = %v", err)
	}

	output := stdout.String()
	for _, want := range []string{
		"DEVICE",
		"VALID UNTIL",
		"TIME LEFT",
		"PRINCIPALS",
		"CERT PATH",
		"device-alpha",
		"device-bravo",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("cache ls output missing %q:\n%s", want, output)
		}
	}

	alpha := strings.Index(output, "device-alpha")
	bravo := strings.Index(output, "device-bravo")
	if alpha < 0 || bravo < 0 || alpha > bravo {
		t.Fatalf("cache ls not sorted by device id:\n%s", output)
	}
}

func TestCacheListMarksExpired(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	entries := []certcache.Entry{
		{
			Device:       "device-expired",
			CertPath:     "/tmp/cache/default/device-expired.cert",
			ValidAfter:   now.Add(-2 * time.Hour),
			ValidBefore:  now.Add(-time.Minute),
			SerialNumber: 1,
			KeyID:        "device-expired-operator",
			Principals:   []string{"device-expired-operator"},
		},
		{
			Device:       "device-fresh",
			CertPath:     "/tmp/cache/default/device-fresh.cert",
			ValidAfter:   now.Add(-time.Hour),
			ValidBefore:  now.Add(2 * time.Hour),
			SerialNumber: 2,
			KeyID:        "device-fresh-operator",
			Principals:   []string{"device-fresh-operator"},
		},
	}

	var buf bytes.Buffer
	if err := writeCacheList(&buf, entries, now); err != nil {
		t.Fatalf("writeCacheList() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "EXPIRED") {
		t.Fatalf("output missing EXPIRED marker:\n%s", output)
	}
	expiredLine := lineContaining(t, output, "device-expired")
	if !strings.Contains(expiredLine, "EXPIRED") {
		t.Fatalf("device-expired line missing EXPIRED marker: %q", expiredLine)
	}
	freshLine := lineContaining(t, output, "device-fresh")
	if strings.Contains(freshLine, "EXPIRED") {
		t.Fatalf("device-fresh line wrongly marked EXPIRED: %q", freshLine)
	}
}

func TestCachePruneRemovesExpiredEntries(t *testing.T) {
	rt, cacheDir, stdout := newCacheTestRuntime(t)
	ca := newMintTestCA(t)
	seedExpiredCert(t, cacheDir, ca, "device-stale")
	seedCachedCert(t, cacheDir, ca, "device-keep", time.Hour)
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "prune"); err != nil {
		t.Fatalf("Run(cache prune) error = %v", err)
	}

	if !strings.Contains(stdout.String(), "device-stale") {
		t.Fatalf("stdout missing pruned device:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "device-keep") {
		t.Fatalf("stdout names device-keep as pruned:\n%s", stdout.String())
	}

	if _, err := os.Stat(filepath.Join(cacheDir, "default", "device-stale.cert")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("device-stale still on disk: stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "default", "device-keep.cert")); err != nil {
		t.Fatalf("device-keep missing after prune: %v", err)
	}
}

func TestCachePruneDryRunDoesNotDelete(t *testing.T) {
	rt, cacheDir, stdout := newCacheTestRuntime(t)
	ca := newMintTestCA(t)
	seedExpiredCert(t, cacheDir, ca, "device-stale")
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "prune", "--dry-run"); err != nil {
		t.Fatalf("Run(cache prune --dry-run) error = %v", err)
	}

	if !strings.Contains(stdout.String(), "Would remove") {
		t.Fatalf("stdout missing dry-run header:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "device-stale") {
		t.Fatalf("stdout missing dry-run target:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "default", "device-stale.cert")); err != nil {
		t.Fatalf("device-stale removed by dry-run: %v", err)
	}
}

func TestCachePruneIdempotent(t *testing.T) {
	rt, cacheDir, stdout := newCacheTestRuntime(t)
	ca := newMintTestCA(t)
	seedExpiredCert(t, cacheDir, ca, "device-stale")
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "prune"); err != nil {
		t.Fatalf("Run(cache prune) first error = %v", err)
	}
	stdout.Reset()

	if err := execute(context.Background(), root, "cache", "prune"); err != nil {
		t.Fatalf("Run(cache prune) second error = %v", err)
	}
	if !strings.Contains(stdout.String(), "No expired entries to prune") {
		t.Fatalf("second prune did not no-op:\n%s", stdout.String())
	}
}

func TestCachePruneEmptyCache(t *testing.T) {
	rt, _, stdout := newCacheTestRuntime(t)
	root := rootWithCacheForTest(rt, stdout)

	if err := execute(context.Background(), root, "cache", "prune"); err != nil {
		t.Fatalf("Run(cache prune) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "No expired entries to prune") {
		t.Fatalf("empty cache prune output unexpected:\n%s", stdout.String())
	}
}

// seedExpiredCert seeds an already-expired cert into the cache by writing the
// cert directly to disk with a ValidBefore in the past. The Store rejects
// expired certs via GetCert (ErrExpired), but PutCert+disk-listing accepts
// the file as long as the subject key matches the profile.
func seedExpiredCert(t *testing.T, cacheDir string, ca *mintTestCA, device string) {
	t.Helper()
	store, err := certcache.OpenStore(cacheDir, "default")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	cert := &ssh.Certificate{
		Key:             profilePub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           device + "-operator",
		ValidPrincipals: []string{device + "-operator"},
		ValidAfter:      uint64(time.Now().Add(-2 * time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(-time.Minute).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	if err := store.PutCert(device, cert); err != nil {
		t.Fatalf("PutCert(%q) error = %v", device, err)
	}
}

// newCacheTestRuntime returns a runtime wired to a tmpdir-backed cert store so
// cache subcommand tests never touch the engineer's real cache. The cache
// directory is returned so callers can seed it directly.
func newCacheTestRuntime(t *testing.T) (runtime, string, *bytes.Buffer) {
	t.Helper()
	cacheDir := t.TempDir()
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com"},
		}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	return rt, cacheDir, &bytes.Buffer{}
}

func rootWithCacheForTest(rt runtime, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	root.SetOut(stdout)
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(cacheCommand(rt))
	return root
}

// lineContaining returns the first line of output that contains needle, or
// fails the test if none is found. Used by tabular-output assertions where
// the wrapping output may include header rows we don't want to match.
func lineContaining(t *testing.T, output, needle string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("output missing %q:\n%s", needle, output)
	return ""
}
