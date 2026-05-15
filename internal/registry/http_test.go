package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestHTTPRegistryResolveDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got, want := request.Method, http.MethodGet; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := request.URL.Query().Get("device_id"), "prod-a012"; got != want {
			t.Fatalf("device_id = %q, want %q", got, want)
		}
		_ = json.NewEncoder(response).Encode(HTTPRegistryResponse{
			Serial:     " SERIAL123 ",
			FriendlyID: " prod-a012 ",
			Attributes: map[string]any{
				" fleet ":           " prod ",
				"empty":             " ",
				"production":        true,
				"firmware_revision": 42,
				"decimal":           1.5,
				"nested":            map[string]any{"dropped": true},
			},
		})
	}))
	defer server.Close()

	registry, err := NewHTTPRegistry(server.URL + "/resolve?source=postern")
	if err != nil {
		t.Fatalf("NewHTTPRegistry() error = %v", err)
	}
	device, err := registry.ResolveDevice(context.Background(), " prod-a012 ")
	if err != nil {
		t.Fatalf("ResolveDevice() error = %v", err)
	}
	if got, want := device.Serial, "SERIAL123"; got != want {
		t.Fatalf("serial = %q, want %q", got, want)
	}
	if got, want := device.FriendlyID, "prod-a012"; got != want {
		t.Fatalf("friendly id = %q, want %q", got, want)
	}
	if got, want := device.Attributes["fleet"], "prod"; got != want {
		t.Fatalf("fleet = %q, want %q", got, want)
	}
	if got, want := device.Attributes["production"], true; got != want {
		t.Fatalf("production = %v, want %v", got, want)
	}
	if got, want := device.Attributes["firmware_revision"], int64(42); got != want {
		t.Fatalf("firmware_revision = %v, want %v", got, want)
	}
	if _, ok := device.Attributes["empty"]; ok {
		t.Fatalf("empty attribute was retained: %#v", device.Attributes)
	}
	if _, ok := device.Attributes["decimal"]; ok {
		t.Fatalf("non-integer number attribute was retained: %#v", device.Attributes)
	}
	if _, ok := device.Attributes["nested"]; ok {
		t.Fatalf("nested-object attribute was retained: %#v", device.Attributes)
	}
}

func TestHTTPRegistryMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	registry, err := NewHTTPRegistry(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistry() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "missing")
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusNotFound {
		t.Fatalf("ResolveDevice() error = %v, want %d broker.Error", err, http.StatusNotFound)
	}
}

func TestHTTPRegistryRequiresSerial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(HTTPRegistryResponse{FriendlyID: "prod-a012"})
	}))
	defer server.Close()

	registry, err := NewHTTPRegistry(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistry() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "prod-a012")
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("ResolveDevice() error = %v, want %d broker.Error", err, http.StatusBadGateway)
	}
}

// TestHTTPRegistryRejectsMalformedSerial locks M-20: a registry response
// containing a serial with shell-meta / whitespace / newline characters
// fails as a registry-side error rather than landing in a cert principal.
func TestHTTPRegistryRejectsMalformedSerial(t *testing.T) {
	cases := []string{
		"SERIAL 123",             // space
		"SERIAL\n123",            // newline
		"SERIAL;rm -rf /",        // shell meta
		"",                       // empty handled separately, but covered
		string(make([]byte, 65)), // too long (zero bytes, fails regex)
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(response).Encode(HTTPRegistryResponse{Serial: bad})
			}))
			defer server.Close()

			registry, err := NewHTTPRegistry(server.URL)
			if err != nil {
				t.Fatalf("NewHTTPRegistry() error = %v", err)
			}
			_, err = registry.ResolveDevice(context.Background(), "prod-a012")
			var domainErr broker.Error
			if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadGateway {
				t.Fatalf("ResolveDevice(serial=%q) error = %v, want %d broker.Error", bad, err, http.StatusBadGateway)
			}
		})
	}
}

func TestHTTPRegistryRejectsRelativeURL(t *testing.T) {
	_, err := NewHTTPRegistry("/resolve")
	if err == nil {
		t.Fatal("NewHTTPRegistry() returned nil error")
	}
}

// TestBearerAuthClientAddsHeader verifies the bearer wrapper prepends the
// Authorization header on every request and delegates the call.
func TestBearerAuthClientAddsHeader(t *testing.T) {
	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		captured = request.Header.Get("Authorization")
		_ = json.NewEncoder(response).Encode(HTTPRegistryResponse{Serial: "SERIAL123"})
	}))
	defer server.Close()

	client := NewBearerAuthClient(server.Client(), "secret-token")
	registry, err := NewHTTPRegistryWithClient(client, server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistryWithClient() error = %v", err)
	}
	if _, err := registry.ResolveDevice(context.Background(), "prod-a012"); err != nil {
		t.Fatalf("ResolveDevice() error = %v", err)
	}
	if got, want := captured, "Bearer secret-token"; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

// TestSigV4AuthClientSignsRequest verifies the SigV4 wrapper attaches a
// signed Authorization header with the expected service+region in the
// credential scope. The test inspects the header rather than verifying the
// signature cryptographically (server-side SigV4 verification is API
// Gateway's job; ours is to construct a well-formed signed request).
func TestSigV4AuthClientSignsRequest(t *testing.T) {
	var captured http.Header
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		captured = request.Header.Clone()
		_ = json.NewEncoder(response).Encode(HTTPRegistryResponse{Serial: "SERIAL123"})
	}))
	defer server.Close()

	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     "AKIATESTACCESSKEY",
			SecretAccessKey: "test-secret",
		}, nil
	})

	client := NewSigV4AuthClient(server.Client(), provider, "us-east-1")
	// Pin the signer's clock so test failures aren't time-dependent.
	client.(*sigV4AuthClient).now = func() time.Time {
		return time.Date(2026, 5, 12, 18, 0, 0, 0, time.UTC)
	}

	registry, err := NewHTTPRegistryWithClient(client, server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistryWithClient() error = %v", err)
	}
	if _, err := registry.ResolveDevice(context.Background(), "prod-a012"); err != nil {
		t.Fatalf("ResolveDevice() error = %v", err)
	}

	auth := captured.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q, want AWS4-HMAC-SHA256 prefix", auth)
	}
	if !strings.Contains(auth, "Credential=AKIATESTACCESSKEY/20260512/us-east-1/execute-api/aws4_request") {
		t.Fatalf("Authorization = %q, want execute-api/us-east-1 credential scope", auth)
	}
	if got := captured.Get("X-Amz-Date"); got != "20260512T180000Z" {
		t.Fatalf("X-Amz-Date = %q, want 20260512T180000Z", got)
	}
}

// TestSigV4AuthClientRetrieveError surfaces credential-provider failures
// instead of silently sending unsigned requests. The signer-Do path must
// fail-closed so the broker doesn't leak the registry call past auth.
func TestSigV4AuthClientRetrieveError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("server must not be called when credentials cannot be retrieved")
	}))
	defer server.Close()

	credsErr := errors.New("imds unreachable")
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, credsErr
	})

	client := NewSigV4AuthClient(server.Client(), provider, "us-east-1")
	registry, err := NewHTTPRegistryWithClient(client, server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistryWithClient() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "prod-a012")
	if !errors.Is(err, credsErr) {
		t.Fatalf("ResolveDevice() error = %v, want wrapped imds error", err)
	}
}

// TestSigV4AuthClientRequiresRegion guards the empty-region case so it fails
// at the call site rather than producing a syntactically valid but
// semantically wrong signature ("/" service scope).
func TestSigV4AuthClientRequiresRegion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("server must not be called when region is empty")
	}))
	defer server.Close()

	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret"}, nil
	})

	client := NewSigV4AuthClient(server.Client(), provider, "  ")
	registry, err := NewHTTPRegistryWithClient(client, server.URL)
	if err != nil {
		t.Fatalf("NewHTTPRegistryWithClient() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "prod-a012")
	if err == nil || !strings.Contains(err.Error(), "region is required") {
		t.Fatalf("ResolveDevice() error = %v, want region-required error", err)
	}
}
