//go:build timefix_test_path

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fixedTime is the wall-clock the verifier sees in tests. It is not
// consulted by the verifier today (the now check is against the payload's
// `now` field versus a hard-coded 2024/2099 bound, not against the device
// clock — DESIGN.md §"Device-side validation" check #7), but verify()
// takes it as a parameter for future test scenarios that exercise
// device-clock-dependent paths. Keep it pinned mid-2026 for stability.
var fixedTime = time.Date(2026, time.May, 13, 12, 0, 0, 0, time.UTC)

// validClaims returns a fresh, on-spec set of payload claims keyed to the
// shared test serial + a caller-supplied nonce. Tests that exercise a
// specific claim-content failure mutate one field after calling this.
func validClaims(t *testing.T, serial, nonce string) map[string]any {
	t.Helper()
	return map[string]any{
		"aud":           "device-" + serial + "-timefix",
		"device_serial": serial,
		"iat":           int64(1747000000),
		"iss":           "postern.broker",
		"issued_to":     "sub-123",
		"jti":           "01969cc1-2800-7000-8000-000000000001",
		"nonce":         nonce,
		"now":           time.Date(2026, time.May, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

// signJWS builds a JWS Compact serialization with a caller-supplied header
// + payload + Ed25519 signer. The signer is the same key the verifier's
// CA-pubkey resolution returns, so happy-path tests verify against the
// "right" key and tampering tests can corrupt either segment to assert
// the signature step fires.
func signJWS(t *testing.T, header, payload []byte, signer ed25519.PrivateKey) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(signer, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mustMarshal is a t.Fatal-on-error json.Marshal wrapper that keeps the
// test bodies linear.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// writeAuthorizedKey writes a fresh Ed25519 keypair's public side to a
// tempfile in OpenSSH authorized_keys format — the same format
// /etc/ssh/postern_ca.pub uses on the device. Returns the path + the
// private key so the test body can sign with the matching key. The
// tempfile is cleaned up by t.Cleanup.
func writeAuthorizedKey(t *testing.T) (path string, privateKey ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "postern_ca.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return path, priv
}

// TestVerifyHappyPath confirms the canonical wire format the broker emits
// validates cleanly and the parsed timestamp matches the payload's `now`.
// This is the load-bearing positive test: every failure-mode test below
// shares the same fixture shape and mutates one field, so happy-path
// drift would invalidate all of them.
func TestVerifyHappyPath(t *testing.T) {
	caPath, priv := writeAuthorizedKey(t)
	caPub := loadCAOrFatal(t, caPath)
	const serial = "SERIAL123"
	const nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	header := []byte(`{"alg":"EdDSA","typ":"postern-timefix+jwt"}`)
	payload := mustMarshal(t, validClaims(t, serial, nonce))
	jws := signJWS(t, header, payload, priv)

	result := verify(verifyParams{
		JWS:            jws,
		ExpectedSerial: serial,
		ExpectedNonce:  nonce,
		CAPublicKey:    caPub,
	})
	if result.ExitCode != exitSuccess {
		t.Fatalf("verify exit = %d (err=%v), want 0", result.ExitCode, result.Err)
	}
	wantTS := time.Date(2026, time.May, 13, 12, 0, 0, 0, time.UTC).Unix()
	if result.Timestamp != wantTS {
		t.Fatalf("verify ts = %d, want %d", result.Timestamp, wantTS)
	}
}

// TestVerifyFailureTable exercises every failure-class branch and asserts
// the exit code maps to invariant P. Each row mutates a single dimension
// of the happy-path fixture and the assertion is on the exit-code value
// — invariant P is a stable wire contract, so any reordering of these
// codes would silently break on-device log analysis.
func TestVerifyFailureTable(t *testing.T) {
	caPath, priv := writeAuthorizedKey(t)
	caPub := loadCAOrFatal(t, caPath)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub

	const serial = "SERIAL123"
	const nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	canonicalHeader := []byte(`{"alg":"EdDSA","typ":"postern-timefix+jwt"}`)
	canonicalPayload := mustMarshal(t, validClaims(t, serial, nonce))
	tamperedSig := signJWS(t, canonicalHeader, canonicalPayload, otherPriv)
	canonicalJWS := signJWS(t, canonicalHeader, canonicalPayload, priv)

	mutated := func(mut func(m map[string]any)) string {
		claims := validClaims(t, serial, nonce)
		mut(claims)
		return signJWS(t, canonicalHeader, mustMarshal(t, claims), priv)
	}

	tests := []struct {
		name string
		jws  string
		want int
	}{
		{"empty input", "", exitBadInput},
		{"single segment", "abc", exitBadInput},
		{"two segments", "abc.def", exitBadInput},
		{"four segments", "abc.def.ghi.jkl", exitBadInput},
		{"header base64url decode failure", "!!!." +
			base64.RawURLEncoding.EncodeToString(canonicalPayload) + ".AAAA", exitBadInput},
		{"payload base64url decode failure",
			base64.RawURLEncoding.EncodeToString(canonicalHeader) + ".!!!.AAAA", exitBadInput},
		{"over size cap", strings.Repeat("a", MaxJWSBytes+1), exitBadInput},
		{"alg none", signJWS(t, []byte(`{"alg":"none","typ":"postern-timefix+jwt"}`), canonicalPayload, priv), exitAlgTypMismatch},
		{"alg RS256", signJWS(t, []byte(`{"alg":"RS256","typ":"postern-timefix+jwt"}`), canonicalPayload, priv), exitAlgTypMismatch},
		{"alg HS256", signJWS(t, []byte(`{"alg":"HS256","typ":"postern-timefix+jwt"}`), canonicalPayload, priv), exitAlgTypMismatch},
		{"typ JWT", signJWS(t, []byte(`{"alg":"EdDSA","typ":"JWT"}`), canonicalPayload, priv), exitAlgTypMismatch},
		{"typ missing", signJWS(t, []byte(`{"alg":"EdDSA"}`), canonicalPayload, priv), exitAlgTypMismatch},
		{"signature tampered", tamperedSig, exitSignatureFailure},
		{"signature bytes corrupted", corruptSignature(canonicalJWS), exitSignatureFailure},
		{"aud mismatch", mutated(func(m map[string]any) { m["aud"] = "device-OTHER-timefix" }), exitClaimFailure},
		{"device_serial mismatch", mutated(func(m map[string]any) { m["device_serial"] = "OTHER" }), exitClaimFailure},
		{"nonce mismatch", mutated(func(m map[string]any) { m["nonce"] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA" }), exitClaimFailure},
		{"now in 2023", mutated(func(m map[string]any) { m["now"] = "2023-12-31T23:59:59Z" }), exitClaimFailure},
		{"now in 2100", mutated(func(m map[string]any) { m["now"] = "2100-01-01T00:00:00Z" }), exitClaimFailure},
		{"now malformed", mutated(func(m map[string]any) { m["now"] = "not-an-iso8601" }), exitClaimFailure},
		{"now missing", mutated(func(m map[string]any) { delete(m, "now") }), exitClaimFailure},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := verify(verifyParams{
				JWS:            tc.jws,
				ExpectedSerial: serial,
				ExpectedNonce:  nonce,
				CAPublicKey:    caPub,
			})
			if result.ExitCode != tc.want {
				t.Fatalf("exit = %d (err=%v), want %d", result.ExitCode, result.Err, tc.want)
			}
		})
	}
}

// corruptSignature decodes the last segment, flips a byte, re-encodes.
// Distinct from "signed with another key" — exercises the same branch
// (signature verify failure) from a different angle so a future bug that
// short-circuits only one path still trips the table.
func corruptSignature(jws string) string {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return jws
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jws
	}
	if len(sig) == 0 {
		return jws
	}
	sig[0] ^= 0xFF
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// loadCAOrFatal exercises the production loadCAPubKey path (including
// the OpenSSH-format parse + Ed25519 downcast) so the test fixtures
// match the production resolution shape byte-for-byte.
func loadCAOrFatal(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	pub, err := loadCAPubKey(path)
	if err != nil {
		t.Fatalf("loadCAPubKey(%s): %v", path, err)
	}
	return pub
}

// TestLoadCAPubKeyRejectsNonEd25519 is a defense-in-depth regression
// guard for invariant N: the broker's KMSSigner is locked to Ed25519,
// so any on-device pubkey of a different type is an installer error.
// The verifier rejects with exitBadInput rather than progressing to
// signature verification with a wrong-shape key.
func TestLoadCAPubKeyRejectsNonEd25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")
	// Sample RSA SSH pubkey — structurally valid OpenSSH format but not
	// Ed25519. Generating one inline keeps the test self-contained.
	rsaPubLine := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQwfg8s8b0NoB3a6CW6sGJBSV0gA0iJpUGEvbAd9wdEzGZSm56j1iikIuOcRMQqlSv3HOl3oVHIcvB+TYAjL4xR8gqzfA0KhrIIyZTI7lJ7w8FLh4f8KE1zRY9PdAehbtTbjE2K8K9HW/qWMcAaUDB99FwHbWQa+wpe40zPjr30tH4yKKVm3HOL5kjwBh4S2pgcybfQzaJp5jJYr5h0DcVy6n6QFqlZx7iitT44V62uJ+M0FwIozWl2tTl3STD3oqkVwTYHZF6yIaR1ihPDM6JKnsXg7d8B+yvkFNCMW6gNs+0qmDpfRO+9tCqsAUkVKXMb38FRiTtxV3oxq2dN/8d test@host\n"
	if err := os.WriteFile(path, []byte(rsaPubLine), 0o600); err != nil {
		t.Fatalf("write bad pubkey: %v", err)
	}
	_, err := loadCAPubKey(path)
	if err == nil {
		t.Fatal("loadCAPubKey accepted non-Ed25519 key; want error")
	}
	if !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("loadCAPubKey err = %v, want one mentioning ed25519", err)
	}
}

// TestRunHappyPathExecsSetterWithTimestamp confirms the full main-path
// (load CA, read serial, generate nonce, emit, read JWS, verify, exec)
// wires the validated timestamp into the setter's argv. The setter exec
// is stubbed so the test stays in-process; in production syscall.Exec
// replaces the verifier process and this branch is unreachable.
func TestRunHappyPathExecsSetterWithTimestamp(t *testing.T) {
	caPath, priv := writeAuthorizedKey(t)
	principalsPath := writePrincipalsFile(t, principalsBodyFor("SERIAL123"))
	t.Setenv("POSTERN_TIMEFIX_CA_PUB", caPath)

	// The verifier emits the nonce to stdout first, then reads stdin.
	// We can't predict the nonce ahead of time, so wire the harness to
	// generate the nonce via a deterministic Random reader and feed the
	// resulting JWS through stdin after observing stdout.
	deterministicNonce := bytes.Repeat([]byte{0xAB}, 32)
	encodedNonce := base64.RawURLEncoding.EncodeToString(deterministicNonce)

	header := []byte(`{"alg":"EdDSA","typ":"postern-timefix+jwt"}`)
	payload := mustMarshal(t, validClaims(t, "SERIAL123", encodedNonce))
	jws := signJWS(t, header, payload, priv)

	var stdout, stderr bytes.Buffer
	var capturedArgv []string
	stub := func(argv []string) error {
		capturedArgv = argv
		return nil
	}
	exitCode := run(deps{
		Stdin:          strings.NewReader(jws + "\n"),
		Stdout:         &stdout,
		Stderr:         &stderr,
		Random:         bytes.NewReader(deterministicNonce),
		Now:            func() time.Time { return fixedTime },
		PrincipalsPath: principalsPath,
		CAPubPath:      caPath,
		ExecSetter:     stub,
	})
	if exitCode != exitSuccess {
		t.Fatalf("run exit = %d (stderr=%q), want 0", exitCode, stderr.String())
	}
	// The verifier emits two lines: nonce, then "device-clock: <RFC3339>".
	stdoutLines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(stdoutLines) != 2 {
		t.Fatalf("stdout lines = %d (%q), want 2", len(stdoutLines), stdout.String())
	}
	if got := stdoutLines[0]; got != encodedNonce {
		t.Fatalf("stdout nonce = %q, want %q", got, encodedNonce)
	}
	clockLine := stdoutLines[1]
	clockPrefix := "device-clock: "
	if !strings.HasPrefix(clockLine, clockPrefix) {
		t.Fatalf("stdout line 2 = %q, want prefix %q", clockLine, clockPrefix)
	}
	clockValue := strings.TrimPrefix(clockLine, clockPrefix)
	parsedClock, err := time.Parse(time.RFC3339, clockValue)
	if err != nil {
		t.Fatalf("device-clock %q: parse RFC3339: %v", clockValue, err)
	}
	if !parsedClock.Equal(fixedTime) {
		t.Fatalf("device-clock = %v, want %v", parsedClock, fixedTime)
	}
	if len(capturedArgv) != 2 || capturedArgv[0] != "timefix-set-clock" {
		t.Fatalf("setter argv = %v, want [timefix-set-clock <ts>]", capturedArgv)
	}
	wantTS := fmt.Sprintf("%d", fixedTime.Unix())
	if capturedArgv[1] != wantTS {
		t.Fatalf("setter timestamp = %q, want %q", capturedArgv[1], wantTS)
	}
}

// TestRunEmitsDeviceClockOnRejection confirms the device-clock line is
// emitted even when the verifier later rejects the JWS — the engineer's
// CLI shows the device-clock snapshot regardless of outcome, since
// "what does the device think it is?" is the recovery-scenario debug
// signal. The verifier emits both stdout lines before the stdin read,
// so any post-emit rejection (alg mismatch, signature failure, etc.)
// still leaves both lines on the wire.
func TestRunEmitsDeviceClockOnRejection(t *testing.T) {
	caPath, _ := writeAuthorizedKey(t)
	principalsPath := writePrincipalsFile(t, principalsBodyFor("SERIAL123"))

	var stdout, stderr bytes.Buffer
	exitCode := run(deps{
		// JWS that fails parsing — three segments but garbage in each.
		Stdin:          strings.NewReader("garbage.garbage.garbage\n"),
		Stdout:         &stdout,
		Stderr:         &stderr,
		Random:         bytes.NewReader(make([]byte, 32)),
		Now:            func() time.Time { return fixedTime },
		PrincipalsPath: principalsPath,
		CAPubPath:      caPath,
		ExecSetter:     func(argv []string) error { return nil },
	})
	if exitCode == exitSuccess {
		t.Fatal("run accepted garbage JWS; want rejection")
	}
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout lines = %d (%q), want 2 even on rejection", len(lines), stdout.String())
	}
	if !strings.HasPrefix(lines[1], "device-clock: ") {
		t.Fatalf("line 2 = %q, want device-clock prefix", lines[1])
	}
}

// TestRunSetterExecFailureExits6 confirms invariant P's exit-code-6 path
// fires when the production exec call returns an error (in production
// that means missing binary, permission denied, etc. — the setter exec
// stub returns a sentinel error here).
func TestRunSetterExecFailureExits6(t *testing.T) {
	caPath, priv := writeAuthorizedKey(t)
	principalsPath := writePrincipalsFile(t, principalsBodyFor("SERIAL123"))

	deterministicNonce := bytes.Repeat([]byte{0xCD}, 32)
	encodedNonce := base64.RawURLEncoding.EncodeToString(deterministicNonce)
	header := []byte(`{"alg":"EdDSA","typ":"postern-timefix+jwt"}`)
	payload := mustMarshal(t, validClaims(t, "SERIAL123", encodedNonce))
	jws := signJWS(t, header, payload, priv)

	var stdout, stderr bytes.Buffer
	stub := func(argv []string) error { return errors.New("simulated exec failure") }
	exitCode := run(deps{
		Stdin:          strings.NewReader(jws),
		Stdout:         &stdout,
		Stderr:         &stderr,
		Random:         bytes.NewReader(deterministicNonce),
		Now:            func() time.Time { return fixedTime },
		PrincipalsPath: principalsPath,
		CAPubPath:      caPath,
		ExecSetter:     stub,
	})
	if exitCode != exitSetterExecFailure {
		t.Fatalf("run exit = %d, want %d", exitCode, exitSetterExecFailure)
	}
}

// TestRunBadCAPathExits2 confirms an unreadable CA pubkey path maps to
// invariant P's bad-input class. Same exit class as truncated JWS — both
// are "the verifier couldn't get to validating the signed claims."
func TestRunBadCAPathExits2(t *testing.T) {
	principalsPath := writePrincipalsFile(t, principalsBodyFor("SERIAL123"))
	var stdout, stderr bytes.Buffer
	exitCode := run(deps{
		Stdin:          strings.NewReader(""),
		Stdout:         &stdout,
		Stderr:         &stderr,
		Random:         bytes.NewReader(make([]byte, 32)),
		Now:            func() time.Time { return fixedTime },
		PrincipalsPath: principalsPath,
		CAPubPath:      filepath.Join(t.TempDir(), "does-not-exist"),
		ExecSetter:     func(argv []string) error { return nil },
	})
	if exitCode != exitBadInput {
		t.Fatalf("run exit = %d, want %d", exitCode, exitBadInput)
	}
}

// TestReadPrincipalSerialExtractsAndRejects exercises the parser against
// the on-device principals file shape: valid single-line principals are
// accepted with the serial extracted; comments and blanks are skipped;
// off-format lines are rejected loudly so a principals-init misconfig
// surfaces at verifier startup rather than as an opaque claim mismatch.
func TestReadPrincipalSerialExtractsAndRejects(t *testing.T) {
	okTests := []struct {
		name string
		body string
		want string
	}{
		{"single line", "device-ABC123-timefix\n", "ABC123"},
		{"no trailing newline", "device-ABC123-timefix", "ABC123"},
		{"trailing whitespace", "  device-ABC123-timefix  \n", "ABC123"},
		{"leading blanks", "\n\n  \ndevice-ABC123-timefix\n", "ABC123"},
		{"comments before", "# operator note\n# device id: ABC123\ndevice-ABC123-timefix\n", "ABC123"},
		{"hyphenated serial", "device-AMIR-023-timefix\n", "AMIR-023"},
		{"numeric serial", "device-1612824600893-timefix\n", "1612824600893"},
	}
	for _, tc := range okTests {
		t.Run("ok/"+tc.name, func(t *testing.T) {
			path := writePrincipalsFile(t, tc.body)
			got, err := readPrincipalSerial(path)
			if err != nil {
				t.Fatalf("readPrincipalSerial: %v", err)
			}
			if got != tc.want {
				t.Fatalf("readPrincipalSerial = %q, want %q", got, tc.want)
			}
		})
	}

	errTests := []struct {
		name string
		body string
	}{
		{"empty file", ""},
		{"only blanks and comments", "# a comment\n\n   \n"},
		{"missing device- prefix", "ABC123-timefix\n"},
		{"missing -timefix suffix", "device-ABC123\n"},
		{"empty serial", "device--timefix\n"},
		{"wrong principal type", "device-ABC123-operator\n"},
	}
	for _, tc := range errTests {
		t.Run("err/"+tc.name, func(t *testing.T) {
			path := writePrincipalsFile(t, tc.body)
			if _, err := readPrincipalSerial(path); err == nil {
				t.Fatalf("readPrincipalSerial returned nil error for %q", tc.body)
			}
		})
	}
}

// TestResolveCAPubPathHonorsEnvOverride confirms the build-tag-gated env
// override is wired in test builds — this is the regression guard for
// LD-69's "production builds do not contain os.Getenv" rule. If a future
// edit moves the env lookup into the !timefix_test_path file, this test
// passes but the production-build (`go build` without tags) still won't
// contain it, which is the load-bearing property.
func TestResolveCAPubPathHonorsEnvOverride(t *testing.T) {
	t.Setenv("POSTERN_TIMEFIX_CA_PUB", "/tmp/custom-pubkey")
	if got := resolveCAPubPath(); got != "/tmp/custom-pubkey" {
		t.Fatalf("resolveCAPubPath = %q, want /tmp/custom-pubkey", got)
	}
	t.Setenv("POSTERN_TIMEFIX_CA_PUB", "")
	if got := resolveCAPubPath(); got != "/etc/ssh/postern_ca.pub" {
		t.Fatalf("resolveCAPubPath fallback = %q, want /etc/ssh/postern_ca.pub", got)
	}
}

// writePrincipalsFile drops an authorized_principals-style fixture into a
// tempdir and returns the path. Bodies should match the on-device file
// shape: one or more lines, each either blank, a `#`-prefixed comment, or
// a `device-<serial>-timefix` principal.
func writePrincipalsFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "timefix")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write principals: %v", err)
	}
	return path
}

// principalsBodyFor returns a single-line principals fixture for the given
// serial — the shape principals-init writes on the device.
func principalsBodyFor(serial string) string {
	return "device-" + serial + "-timefix\n"
}

// readAllOrFatal is a t.Fatal-on-error io.ReadAll wrapper used by a few
// tests to assert stdout contents without obscuring the actual assertion
// in error plumbing.
func readAllOrFatal(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	return b
}

var _ = readAllOrFatal // reserved for follow-on integration tests
