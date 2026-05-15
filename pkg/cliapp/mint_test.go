package cliapp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func TestMintWritesCertAndKeyAndPrintsHint(t *testing.T) {
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-1234"
	brokerCalls := 0
	var stdout bytes.Buffer

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default", Profile: Profile{Broker: "https://broker.example.com"}}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token-abc", nil
	}
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		brokerCalls++
		return broker.SSHCertIssueResponse{
			SSHCert:             marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
			CAPubkeyFingerprint: ssh.FingerprintSHA256(ca.signer.PublicKey()),
		}, nil
	}
	root := rootWithMintForTest(rt, &stdout)

	if err := execute(context.Background(), root, "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}

	if brokerCalls != 1 {
		t.Fatalf("broker calls = %d, want 1", brokerCalls)
	}
	certPath := filepath.Join(cacheDir, "default", deviceID+".cert")
	keyPath := filepath.Join(cacheDir, "default", "key")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file %s missing: %v", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file %s missing: %v", keyPath, err)
	}

	output := stdout.String()
	for _, want := range []string{
		"Cert minted for " + deviceID,
		"Cert: " + certPath,
		"Key:  " + keyPath,
		"ssh -i " + keyPath,
		"CertificateFile=" + certPath,
		"engineer@<device-ip>",
		"add-host " + deviceID + " --ip <device-ip>",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout missing %q:\n%s", want, output)
		}
	}
}

// TestMintAlwaysCallsBroker exercises the verb-of-action contract: even with
// a valid cached cert on disk, mint must hit the broker every invocation and
// overwrite the cached entry.
func TestMintAlwaysCallsBroker(t *testing.T) {
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-5678"

	// Pre-populate the cache by minting one cert and storing it through the
	// real Store, so we can later assert the bytes on disk changed.
	store, err := certcache.OpenStore(cacheDir, "default")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	preExisting := ca.mintCert(t, profilePub, deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))
	if err := store.PutCert(deviceID, preExisting); err != nil {
		t.Fatalf("PutCert() error = %v", err)
	}
	certPath := filepath.Join(cacheDir, "default", deviceID+".cert")
	preBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read pre-mint cert: %v", err)
	}

	freshSerial := uint64(99)
	brokerCalls := 0
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default", Profile: Profile{Broker: "https://broker.example.com"}}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token", nil
	}
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		brokerCalls++
		fresh := ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))
		fresh.Serial = freshSerial
		if err := fresh.SignCert(rand.Reader, ca.signer); err != nil {
			t.Fatalf("SignCert() error = %v", err)
		}
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, fresh),
		}, nil
	}
	root := rootWithMintForTest(rt, nil)

	if err := execute(context.Background(), root, "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}
	if brokerCalls != 1 {
		t.Fatalf("broker calls = %d, want 1 (mint must always re-mint)", brokerCalls)
	}

	postBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read post-mint cert: %v", err)
	}
	if bytes.Equal(preBytes, postBytes) {
		t.Fatal("cert file unchanged; mint did not re-write the cache")
	}
}

func TestMintAuthFailureNamesLogin(t *testing.T) {
	tokenErr := errors.New("no token cached")
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "staging"}, nil
	}
	rt.openCertStore = openTestStore(t.TempDir())
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "", tokenErr
	}
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		t.Fatal("broker must not be called when access-token retrieval fails")
		return broker.SSHCertIssueResponse{}, nil
	}
	root := rootWithMintForTest(rt, nil)

	err := execute(context.Background(), root, "mint", "device-1")
	if err == nil {
		t.Fatal("Run(mint) returned nil error")
	}
	if !errors.Is(err, ErrMintNoAuth) {
		t.Fatalf("Run(mint) error = %v, want ErrMintNoAuth on chain", err)
	}
	if !errors.Is(err, tokenErr) {
		t.Fatalf("Run(mint) error = %v, want underlying token error preserved", err)
	}
	if !strings.Contains(err.Error(), `"postern" --profile "staging" login`) {
		t.Fatalf("Run(mint) error = %v, want login hint", err)
	}
}

// TestMintAuthErrorQuotesShellMetaProfileName covers the shell-safety contract:
// a profile name carrying shell metacharacters (spaces, backticks, $, quotes)
// must render through %q so the engineer can copy-paste the hint into a shell
// without surprises.
func TestMintAuthErrorQuotesShellMetaProfileName(t *testing.T) {
	tokenErr := errors.New("no token cached")
	hostile := "foo; rm -rf /"

	err := mintAuthError("postern", hostile, tokenErr)
	if err == nil {
		t.Fatal("mintAuthError returned nil")
	}
	wantQuoted := `--profile "foo; rm -rf /" login`
	if !strings.Contains(err.Error(), wantQuoted) {
		t.Fatalf("mintAuthError = %q, want substring %q", err.Error(), wantQuoted)
	}
	// The unquoted bare form must NOT appear; if it does, the engineer would
	// paste an arg-splitting hint into their shell.
	if strings.Contains(err.Error(), "--profile foo; rm -rf / login") {
		t.Fatalf("mintAuthError = %q, leaked unquoted profile name", err.Error())
	}
}

func TestMintSurfacesBrokerErrors(t *testing.T) {
	brokerErr := errors.New("policy denied: device not in fleet")
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default"}, nil
	}
	rt.openCertStore = openTestStore(t.TempDir())
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token", nil
	}
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{}, brokerErr
	}
	root := rootWithMintForTest(rt, nil)

	err := execute(context.Background(), root, "mint", "device-1")
	if !errors.Is(err, brokerErr) {
		t.Fatalf("Run(mint) error = %v, want broker error", err)
	}
}

// TestMintProfileWhitespaceCanonicalized verifies the profile resolver trims
// surrounding whitespace once at the boundary so the cache directory layout
// is the canonical "default", not a literal directory named with leading or
// trailing spaces.
func TestMintProfileWhitespaceCanonicalized(t *testing.T) {
	configPath := writeConfigFileForTest(t, `
default:
  broker: https://broker.example.com
  idp:
    issuer: https://idp.example.com
    client_id: client-123
    audience: https://broker.example.com
`)
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-ws"

	rt := newRuntimeForTest(Options{ConfigPath: configPath, LookupEnv: emptyEnv})
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token", nil
	}
	rt.sshCertRequester = func(_ context.Context, profile ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		if profile.Name != "default" {
			t.Fatalf("profile name = %q, want trimmed %q", profile.Name, "default")
		}
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}
	root := rootWithMintForTest(rt, nil)

	if err := execute(context.Background(), root, "--profile", "  default  ", "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}

	trimmedDir := filepath.Join(cacheDir, "default")
	if _, err := os.Stat(trimmedDir); err != nil {
		t.Fatalf("trimmed profile dir missing: %v", err)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("ReadDir(cacheDir): %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "default" {
			t.Fatalf("unexpected cache dir entry %q (whitespace leaked into layout)", entry.Name())
		}
	}
}

func TestMintRejectsInvalidDeviceID(t *testing.T) {
	cases := []struct {
		name      string
		device    string
		wantInErr string
	}{
		{"empty", "", "device id is required"},
		{"path-traversal-with-slash", "../escape", "path separators"},
		{"path-traversal-no-slash", "..", "'..' is not allowed"},
		{"forward-slash", "a/b", "path separators"},
		{"backslash", `a\b`, "path separators"},
	}
	// Device-id validation runs at the boundary before any runtime dep is
	// consulted, so a minimal runtime with no mocks is sufficient.
	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		t.Fatal("profile resolver must not be called for an invalid device id")
		return ResolvedProfile{}, nil
	}
	root := rootWithMintForTest(rt, nil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := execute(context.Background(), root, "mint", tc.device)
			if err == nil {
				t.Fatalf("Run(mint %q) returned nil error", tc.device)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("Run(mint %q) error = %v, want substring %q", tc.device, err, tc.wantInErr)
			}
		})
	}
}

// TestMintRegisteredBranchCollapsesHint covers LD-116: when the device
// has a stanza in the Postern-managed ssh.conf (persistent or
// ephemeral), the post-mint output collapses to the single-line
// `ssh <device>` connect hint and drops the manual fallback.
func TestMintRegisteredBranchCollapsesHint(t *testing.T) {
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-registered"
	sshConfPath := filepath.Join(t.TempDir(), "ssh.conf")
	var stdout bytes.Buffer

	// Seed a persistent stanza for the device so writer.Has() returns
	// true at mint time.
	seedWriter := sshconf.NewWriter(sshConfPath)
	if err := seedWriter.Upsert(sshconf.Stanza{
		Device:          deviceID,
		User:            "engineer",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default", Profile: Profile{Broker: "https://broker.example.com"}}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) { return "access-token", nil }
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		return sshconf.NewWriter(sshConfPath), nil
	}

	root := rootWithMintForTest(rt, &stdout)
	if err := execute(context.Background(), root, "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Connect with:\n  ssh "+deviceID) {
		t.Fatalf("registered branch missing single-line connect hint:\n%s", out)
	}
	if strings.Contains(out, "add-host "+deviceID+" --ip <device-ip>") {
		t.Fatalf("registered branch leaked add-host suggestion:\n%s", out)
	}
	if strings.Contains(out, "engineer@<device-ip>") {
		t.Fatalf("registered branch leaked manual ssh -i fallback:\n%s", out)
	}
}

// TestMintNotRegisteredBranchSuggestsAddHost covers the negative side
// of LD-116: when the device is not in the ssh.conf, the post-mint
// output names `add-host` as the primary next step and keeps the
// manual `ssh -i ... -o CertificateFile=...` line as a fallback.
func TestMintNotRegisteredBranchSuggestsAddHost(t *testing.T) {
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-unregistered"
	sshConfPath := filepath.Join(t.TempDir(), "ssh.conf")
	var stdout bytes.Buffer

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default", Profile: Profile{Broker: "https://broker.example.com"}}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) { return "access-token", nil }
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		// File doesn't exist → Has() returns false.
		return sshconf.NewWriter(sshConfPath), nil
	}

	root := rootWithMintForTest(rt, &stdout)
	if err := execute(context.Background(), root, "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "add-host "+deviceID+" --ip <device-ip>") {
		t.Fatalf("not-registered branch missing add-host primary:\n%s", out)
	}
	if !strings.Contains(out, "engineer@<device-ip>") {
		t.Fatalf("not-registered branch missing manual fallback:\n%s", out)
	}
}

// TestMintRegisteredBranchAfterAddHostNoMint exercises the LD-112+LD-116
// interaction: after `add-host --no-mint`, the stanza is in ssh.conf
// but the cache is empty. The next `mint` invocation mints the cert
// AND prints the registered-branch single-line connect hint —
// reinforcing the "after mint says I'm good, ssh works" mental model.
func TestMintRegisteredBranchAfterAddHostNoMint(t *testing.T) {
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	deviceID := "device-staged"
	sshConfPath := filepath.Join(t.TempDir(), "ssh.conf")
	var stdout bytes.Buffer

	// Simulate `add-host --no-mint`: stanza exists, no cache entry.
	seedWriter := sshconf.NewWriter(sshConfPath)
	if err := seedWriter.Upsert(sshconf.Stanza{
		Device:          deviceID,
		User:            "engineer",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{Name: "default", Profile: Profile{Broker: "https://broker.example.com"}}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) { return "access-token", nil }
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), deviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		return sshconf.NewWriter(sshConfPath), nil
	}

	root := rootWithMintForTest(rt, &stdout)
	if err := execute(context.Background(), root, "mint", deviceID); err != nil {
		t.Fatalf("Run(mint) error = %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Connect with:\n  ssh "+deviceID) {
		t.Fatalf("staged-then-minted output missing connect hint:\n%s", out)
	}
}

// rootWithMintForTest assembles a minimal cobra root carrying just the mint
// subcommand. Matches the pattern used by rootWithSSHForTest /
// rootWithLoginForTest in sibling test files.
func rootWithMintForTest(rt runtime, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(mintCommand(rt))
	return root
}

// openTestStore returns an openCertStoreFunc rooted at baseDir, so tests
// never touch the engineer's real cache. Mirrors defaultOpenCertStore but
// skips the home-directory derivation.
func openTestStore(baseDir string) openCertStoreFunc {
	return func(profile string) (*certcache.Store, error) {
		return certcache.OpenStore(baseDir, strings.TrimSpace(profile))
	}
}

// mintTestCA mints SSH certificates over a caller-supplied subject key.
// The CA exists only to produce plausible cert blobs for the mint handler
// to parse and cache.
type mintTestCA struct {
	signer ssh.Signer
}

func newMintTestCA(t *testing.T) *mintTestCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return &mintTestCA{signer: signer}
}

func (ca *mintTestCA) mintCert(t *testing.T, subject ssh.PublicKey, device string, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             subject,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "device-" + device + "-operator",
		ValidPrincipals: []string{"device-" + device + "-operator"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	return cert
}

func marshalCertForTest(t *testing.T, cert *ssh.Certificate) string {
	t.Helper()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

func mustParseRequestKey(t *testing.T, authorizedKey string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(%q) error = %v", authorizedKey, err)
	}
	return pub
}
