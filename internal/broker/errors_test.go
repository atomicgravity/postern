package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestErrorCarriesStatusCodeViaErrorsAs(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", Error{StatusCode: http.StatusUnauthorized, Message: "invalid access token"})

	var domainErr Error
	if !errors.As(wrapped, &domainErr) {
		t.Fatalf("errors.As() did not match wrapped Error: %v", wrapped)
	}
	if got, want := domainErr.StatusCode, http.StatusUnauthorized; got != want {
		t.Fatalf("StatusCode = %d, want %d", got, want)
	}
	if got, want := domainErr.Message, "invalid access token"; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
}

func TestSentinelDependencyErrorsMatchViaErrorsIs(t *testing.T) {
	// The constructor joins all missing-dep errors via errors.Join. Each
	// sentinel must match through errors.Is so callers can distinguish
	// "you forgot the registry" from "you forgot the audit sink".
	_, err := NewSSHCertIssuer(SSHCertIssuerDeps{})
	if err == nil {
		t.Fatal("NewSSHCertIssuer({}) returned nil error")
	}
	for _, sentinel := range []error{
		ErrTokenVerifierRequired,
		ErrRegistryRequired,
		ErrPolicyRequired,
		ErrRateLimiterRequired,
		ErrSignerRequired,
		ErrAuditRequired,
	} {
		if !errors.Is(err, sentinel) {
			t.Errorf("errors.Is(err, %v) = false, want true", sentinel)
		}
	}
}

func TestSentinelOnlyFiresForMissingDep(t *testing.T) {
	// When all deps are present, the constructor must not surface any
	// sentinel: the error path is silent. Regression guard against a
	// constructor that returns sentinels speculatively.
	issuer, err := NewSSHCertIssuer(SSHCertIssuerDeps{
		PipelineDeps: PipelineDeps{
			TokenVerifier: stubVerifier{},
			Registry:      stubRegistry{},
			Policy:        stubPolicy{},
			RateLimiter:   stubRateLimiter{},
			Audit:         stubAudit{},
		},
		Signer: stubSigner{},
	})
	if err != nil {
		t.Fatalf("NewSSHCertIssuer(all deps) error = %v", err)
	}
	if issuer == nil {
		t.Fatal("NewSSHCertIssuer(all deps) returned nil issuer")
	}
}

// Minimal stubs satisfying the broker abstraction interfaces. These are local
// to the errors test so we don't pull in the heavier mocks from sshcert_test.

type stubVerifier struct{}

func (stubVerifier) VerifyAccessToken(_ context.Context, _ string) (CallerClaims, error) {
	return CallerClaims{}, nil
}

type stubRegistry struct{}

func (stubRegistry) ResolveDevice(_ context.Context, _ string) (DeviceRecord, error) {
	return DeviceRecord{}, nil
}

type stubPolicy struct{}

func (stubPolicy) Allow(_ context.Context, _ PolicyRequest) error { return nil }

type stubRateLimiter struct{}

func (stubRateLimiter) Allow(_ context.Context, _ RateLimitRequest) error { return nil }

type stubSigner struct{}

func (stubSigner) PublicKey() ssh.PublicKey                             { return nil }
func (stubSigner) SignCert(_ context.Context, _ *ssh.Certificate) error { return nil }
func (stubSigner) SignTimePayload(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

type stubAudit struct{}

func (stubAudit) Record(_ context.Context, _ AuditEvent) error { return nil }
