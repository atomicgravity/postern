//go:build timefix_test_path

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"golang.org/x/crypto/ssh"
)

// TestIntegrationBrokerMintsTimePayloadVerifierAccepts wires the real broker
// time-payload pipeline (IssueTimePayload with a KMS-equivalent SSHSigner)
// to the real verifier (`run()` with a stubbed setter exec) through pipes
// that simulate the CLI's stdin/stdout plumbing. The assertion is that the
// timestamp the setter would have been exec'd with matches the broker's
// signed `now` value within 1 second — the end-to-end correctness check
// that no per-sub-phase test covers in isolation.
//
// The integration boundary stops at the setter exec: the verifier's pure
// validation logic + the broker's signing pipeline + the wire format are
// all exercised here. The setter binary's actual clock_settime / RTC ioctl
// are unit-tested in cmd/timefix-set-clock and aren't relevant to the
// "broker + verifier + CLI plumbing speak the same wire format" assertion
// this integration test owns.
func TestIntegrationBrokerMintsTimePayloadVerifierAccepts(t *testing.T) {
	// Step 1: build a CA keypair the broker signs with AND the verifier
	// trusts as its on-device CA pubkey. Same key on both ends models the
	// production flow (broker signs with the KMS key whose pubkey is
	// installed at /etc/ssh/postern_ca.pub on every device).
	caPubPath, caPriv := writeAuthorizedKey(t)
	sshSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	// Step 2: stand up the broker pipeline with a fixed clock so the
	// signed `now` value is deterministic and we can assert on it.
	now := time.Date(2026, time.May, 13, 12, 0, 0, 0, time.UTC)
	pipelineDeps := broker.PipelineDeps{
		TokenVerifier: integrationTokenVerifier{claims: broker.EngineerClaims{Subject: "test-engineer", Email: "engineer@example.com"}},
		Registry:      integrationRegistry{device: broker.DeviceRecord{Serial: "SERIAL123"}},
		Policy:        integrationPolicy{},
		RateLimiter:   integrationRateLimiter{},
		Audit:         integrationAudit{},
		Clock:         integrationClock{now: now},
	}
	// LD-93 SRP split: cert-mint and time-payload pipelines live on
	// sibling concrete types now. The integration test exercises the
	// time-payload path end-to-end (IssueTimePayload + on-device
	// verifier), so wire the TimePayloadIssuer.
	issuer, err := broker.NewTimePayloadIssuer(broker.TimePayloadIssuerDeps{
		PipelineDeps: pipelineDeps,
		Signer:       broker.SSHSigner{Signer: sshSigner},
	})
	if err != nil {
		t.Fatalf("NewTimePayloadIssuer: %v", err)
	}

	// Step 3: authorized_principals file for the verifier (production
	// reads /etc/ssh/authorized_principals/timefix populated by the
	// operator's principals-init at boot; tests inject a tempfile).
	principalsPath := writePrincipalsFile(t, principalsBodyFor("SERIAL123"))

	// Step 4: stitch stdin/stdout pipes between the verifier and the
	// "CLI goroutine" that reads the nonce, calls the broker, writes
	// the JWS. The verifier's stdout is the source of (nonce, clock);
	// the verifier's stdin is where the broker's JWS goes.
	stdoutReader, stdoutWriter := io.Pipe()
	stdinReader, stdinWriter := io.Pipe()
	defer stdoutReader.Close()
	defer stdinWriter.Close()

	var (
		capturedArgv []string
		setterCalled bool
	)
	stubSetter := func(argv []string) error {
		capturedArgv = argv
		setterCalled = true
		return nil
	}

	// Step 5: the verifier runs in its own goroutine because run()
	// blocks on stdin/stdout (real I/O semantics). The test goroutine
	// plays the role of the CLI: read both stdout lines, call the
	// broker, write the JWS to stdin.
	verifierDone := make(chan int, 1)
	go func() {
		defer stdoutWriter.Close()
		defer stdinReader.Close()
		exitCode := run(deps{
			Stdin:          stdinReader,
			Stdout:         stdoutWriter,
			Stderr:         io.Discard,
			Random:         rand.Reader,
			Now:            func() time.Time { return now },
			PrincipalsPath: principalsPath,
			CAPubPath:      caPubPath,
			ExecSetter:     stubSetter,
		})
		verifierDone <- exitCode
	}()

	// CLI side: drain stdout (two lines), then ask broker to sign,
	// then write JWS to stdin so the verifier unblocks.
	var stdoutCapture bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	var (
		nonce       string
		deviceClock string
		readErr     error
	)
	go func() {
		defer wg.Done()
		// Read everything the verifier emits to stdout; the two-line
		// emit lands in the first chunk plus newline-delimited
		// terminations.
		buf := make([]byte, 1024)
		for {
			n, err := stdoutReader.Read(buf)
			if n > 0 {
				stdoutCapture.Write(buf[:n])
				// Bail once we have both lines (two newlines
				// total). Reading further would block since
				// the verifier next moves to stdin.
				if strings.Count(stdoutCapture.String(), "\n") >= 2 {
					return
				}
			}
			if err != nil {
				readErr = err
				return
			}
		}
	}()
	wg.Wait()
	if readErr != nil && readErr != io.EOF {
		t.Fatalf("read verifier stdout: %v", readErr)
	}
	lines := strings.SplitN(stdoutCapture.String(), "\n", 3)
	if len(lines) < 2 {
		t.Fatalf("verifier stdout = %q, want at least two newline-terminated lines", stdoutCapture.String())
	}
	nonce = lines[0]
	deviceClock = strings.TrimPrefix(lines[1], "device-clock: ")

	if !strings.HasPrefix(lines[1], "device-clock: ") {
		t.Fatalf("verifier line 2 = %q, want device-clock prefix", lines[1])
	}
	if _, parseErr := time.Parse(time.RFC3339, deviceClock); parseErr != nil {
		t.Fatalf("device-clock %q: parse RFC3339: %v", deviceClock, parseErr)
	}

	// Step 6: ask the real broker to issue a JWS bound to (device, nonce).
	resp, err := issuer.IssueTimePayload(context.Background(), broker.TimePayloadIssueRequest{
		AccessToken: "test-access-token",
		DeviceID:    "device-1234",
		Nonce:       nonce,
		UserAgent:   "integration-test",
		RemoteAddr:  "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("IssueTimePayload: %v", err)
	}
	if resp.TimePayload == "" {
		t.Fatal("IssueTimePayload returned empty TimePayload")
	}

	// Step 7: pipe the JWS to the verifier's stdin and close so the
	// verifier's stdin-read returns; the verifier validates and either
	// exec's the stub setter (success) or rejects (non-zero exit).
	if _, err := io.WriteString(stdinWriter, resp.TimePayload+"\n"); err != nil {
		t.Fatalf("write JWS to verifier stdin: %v", err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	exitCode := <-verifierDone
	if exitCode != exitSuccess {
		t.Fatalf("verifier exit = %d, want %d (jws=%q)", exitCode, exitSuccess, resp.TimePayload)
	}
	if !setterCalled {
		t.Fatal("verifier did not exec setter on success path")
	}
	if len(capturedArgv) != 2 {
		t.Fatalf("setter argv = %v, want [binary, timestamp]", capturedArgv)
	}

	gotTS, err := strconv.ParseInt(capturedArgv[1], 10, 64)
	if err != nil {
		t.Fatalf("parse setter timestamp %q: %v", capturedArgv[1], err)
	}
	// Allow 1 second of skew between the broker's signed `now` and the
	// timestamp the setter received. They flow through different
	// pipelines (broker.Clock.Now() → JWS payload `now` → verifier
	// parse → setter arg), so byte-equality is fragile; equivalence
	// within a second is the meaningful assertion.
	wantTS := now.Unix()
	if delta := gotTS - wantTS; delta < -1 || delta > 1 {
		t.Fatalf("setter timestamp = %d, want within 1s of broker now %d (delta %d)", gotTS, wantTS, delta)
	}

}

// Integration-test broker fakes — same shape the cliapp tests use but
// duplicated here because cmd/timefix-apply tests can't import the
// pkg/cliapp test package. Kept minimal: every dep returns success so
// the broker pipeline runs through to Sign.

type integrationTokenVerifier struct {
	claims broker.EngineerClaims
}

func (v integrationTokenVerifier) VerifyAccessToken(context.Context, string) (broker.EngineerClaims, error) {
	return v.claims, nil
}

type integrationRegistry struct {
	device broker.DeviceRecord
}

func (r integrationRegistry) ResolveDevice(context.Context, string) (broker.DeviceRecord, error) {
	return r.device, nil
}

type integrationPolicy struct{}

func (integrationPolicy) Allow(context.Context, broker.PolicyRequest) error { return nil }

type integrationRateLimiter struct{}

func (integrationRateLimiter) Allow(context.Context, broker.RateLimitRequest) error { return nil }

type integrationAudit struct{}

func (integrationAudit) Record(context.Context, broker.AuditEvent) error { return nil }

type integrationClock struct {
	now time.Time
}

func (c integrationClock) Now() time.Time { return c.now }
