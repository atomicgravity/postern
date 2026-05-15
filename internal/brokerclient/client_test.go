package brokerclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
)

func TestMintSSHCertPostsRequestWithBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := request.URL.Path, "/api/ssh/cert"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer access-token-123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		var body broker.SSHCertIssueRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if got, want := body.DeviceID, "device-123"; got != want {
			t.Fatalf("device_id = %q, want %q", got, want)
		}
		if got, want := body.PrincipalType, broker.PrincipalTypeOperator; got != want {
			t.Fatalf("principal_type = %q, want %q", got, want)
		}
		if got, want := body.PublicKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"; got != want {
			t.Fatalf("public_key = %q, want %q", got, want)
		}
		_ = json.NewEncoder(writer).Encode(broker.SSHCertIssueResponse{
			SSHCert:             "ssh-ed25519-cert-v01@openssh.com AAAA...",
			CAPubkeyFingerprint: "SHA256:abc123",
		})
	}))
	defer server.Close()

	client := New(server.URL+"/api/", server.Client())
	response, err := client.MintSSHCert(context.Background(), "access-token-123", broker.SSHCertIssueRequest{
		DeviceID:      "device-123",
		PrincipalType: broker.PrincipalTypeOperator,
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
	})
	if err != nil {
		t.Fatalf("MintSSHCert() error = %v", err)
	}
	if got, want := response.SSHCert, "ssh-ed25519-cert-v01@openssh.com AAAA..."; got != want {
		t.Fatalf("SSHCert = %q, want %q", got, want)
	}
}

func TestMintSSHCertReturnsHTTPErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	client := New(server.URL, server.Client())
	_, err := client.MintSSHCert(context.Background(), "access-token-123", broker.SSHCertIssueRequest{
		DeviceID:      "device-123",
		PrincipalType: broker.PrincipalTypeOperator,
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
	})
	if err == nil {
		t.Fatal("MintSSHCert() returned nil error")
	}
}

// TestMintSSHCertRejectsHTTPNonLocalhost locks M-13: the CLI must not send
// the engineer's bearer token over plaintext HTTP to a remote broker. The
// localhost escape stays so local-dev brokers work; everything else fails
// at the URL-build step before any token is transmitted.
func TestMintSSHCertRejectsHTTPNonLocalhost(t *testing.T) {
	client := New("http://broker.example.com", http.DefaultClient)
	_, err := client.MintSSHCert(context.Background(), "access-token-123", broker.SSHCertIssueRequest{
		DeviceID:      "device-123",
		PrincipalType: broker.PrincipalTypeOperator,
		PublicKey:     "ssh-ed25519 AAAA",
	})
	if err == nil {
		t.Fatal("MintSSHCert() returned nil error for http:// non-localhost URL")
	}
}

// TestRequestTimePayloadPostsRequestWithBearerToken mirrors
// TestMintSSHCertPostsRequestWithBearerToken for the /ssh/time-payload route:
// POST + bearer + JSON body carrying {device_id, nonce}; response decodes
// time_payload off the JSON envelope and surfaces it to the caller.
func TestRequestTimePayloadPostsRequestWithBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := request.URL.Path, "/api/ssh/time-payload"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer access-token-123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		var body broker.TimePayloadIssueRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if got, want := body.DeviceID, "device-123"; got != want {
			t.Fatalf("device_id = %q, want %q", got, want)
		}
		if got, want := body.Nonce, "nonce-abc"; got != want {
			t.Fatalf("nonce = %q, want %q", got, want)
		}
		_ = json.NewEncoder(writer).Encode(broker.TimePayloadIssueResponse{
			TimePayload: "header.payload.signature",
			JTI:         "01969cc1",
		})
	}))
	defer server.Close()

	client := New(server.URL+"/api/", server.Client())
	payload, err := client.RequestTimePayload(context.Background(), "access-token-123", "device-123", "nonce-abc")
	if err != nil {
		t.Fatalf("RequestTimePayload() error = %v", err)
	}
	if got, want := payload, "header.payload.signature"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

// TestRequestTimePayloadReturnsHTTPErrorBody locks the status-code-to-error
// mapping: the broker's HTTP status + body are surfaced to the caller so the
// CLI can render a useful failure message (404 device-not-found, 403
// policy-deny, 429 rate-limit) without parsing the response itself.
func TestRequestTimePayloadReturnsHTTPErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "device not registered", http.StatusNotFound)
	}))
	defer server.Close()

	client := New(server.URL, server.Client())
	_, err := client.RequestTimePayload(context.Background(), "access-token-123", "device-123", "nonce-abc")
	if err == nil {
		t.Fatal("RequestTimePayload() returned nil error")
	}
}

// TestRequestTimePayloadRejectsHTTPNonLocalhost mirrors the cert-mint
// plaintext-HTTP guard for the time-payload route: the engineer's bearer
// token must not be transmitted over unencrypted HTTP to a non-loopback
// broker.
func TestRequestTimePayloadRejectsHTTPNonLocalhost(t *testing.T) {
	client := New("http://broker.example.com", http.DefaultClient)
	_, err := client.RequestTimePayload(context.Background(), "access-token-123", "device-123", "nonce-abc")
	if err == nil {
		t.Fatal("RequestTimePayload() returned nil error for http:// non-localhost URL")
	}
}

// TestRequestTimePayloadValidatesArguments locks the client-side guard rails
// against missing access token / device id / nonce; the broker is contract
// authority for content shape but obvious-emptiness rejects locally so the
// CLI doesn't waste a network round-trip on an unbuilt request.
func TestRequestTimePayloadValidatesArguments(t *testing.T) {
	client := New("https://broker.example.com", http.DefaultClient)
	cases := []struct {
		name        string
		accessToken string
		deviceID    string
		nonce       string
	}{
		{name: "missing-access-token", deviceID: "d", nonce: "n"},
		{name: "missing-device-id", accessToken: "t", nonce: "n"},
		{name: "missing-nonce", accessToken: "t", deviceID: "d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.RequestTimePayload(context.Background(), tc.accessToken, tc.deviceID, tc.nonce)
			if err == nil {
				t.Fatalf("RequestTimePayload(%+v) returned nil error", tc)
			}
		})
	}
}

// TestOpenTunnelPostsRequestWithBearerToken mirrors the cert + time-payload
// tests for the /ssh/tunnel route: POST + bearer + JSON body carrying
// {device_id, max_lifetime_minutes}; response decodes the AWS-side tunnel
// triple off the JSON envelope.
func TestOpenTunnelPostsRequestWithBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := request.URL.Path, "/api/ssh/tunnel"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := request.Header.Get("Authorization"), "Bearer access-token-123"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		var body broker.TunnelOpenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if got, want := body.DeviceID, "device-123"; got != want {
			t.Fatalf("device_id = %q, want %q", got, want)
		}
		if got, want := body.MaxLifetimeMinutes, int32(120); got != want {
			t.Fatalf("max_lifetime_minutes = %d, want %d", got, want)
		}
		_ = json.NewEncoder(writer).Encode(broker.TunnelOpenResponse{
			TunnelID:           "tun-xyz",
			SourceAccessToken:  "source-token",
			Region:             "us-west-2",
			MaxLifetimeMinutes: 120,
		})
	}))
	defer server.Close()

	client := New(server.URL+"/api/", server.Client())
	response, err := client.OpenTunnel(context.Background(), "access-token-123", "device-123", 120)
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := response.TunnelID, "tun-xyz"; got != want {
		t.Fatalf("tunnel_id = %q, want %q", got, want)
	}
	if got, want := response.SourceAccessToken, "source-token"; got != want {
		t.Fatalf("source_access_token = %q, want %q", got, want)
	}
	if got, want := response.Region, "us-west-2"; got != want {
		t.Fatalf("region = %q, want %q", got, want)
	}
	if got, want := response.MaxLifetimeMinutes, int32(120); got != want {
		t.Fatalf("max_lifetime_minutes = %d, want %d", got, want)
	}
}

// TestOpenTunnelReturnsHTTPErrorBody locks the status-code-to-error
// mapping: broker errors propagate to the caller for CLI rendering.
func TestOpenTunnelReturnsHTTPErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "tunneling backend unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := New(server.URL, server.Client())
	_, err := client.OpenTunnel(context.Background(), "access-token-123", "device-123", 0)
	if err == nil {
		t.Fatal("OpenTunnel() returned nil error")
	}
}

// TestOpenTunnelRejectsHTTPNonLocalhost mirrors the cert + time-payload
// plaintext-HTTP guards: the bearer token must not transmit over
// unencrypted HTTP to a non-loopback broker.
func TestOpenTunnelRejectsHTTPNonLocalhost(t *testing.T) {
	client := New("http://broker.example.com", http.DefaultClient)
	_, err := client.OpenTunnel(context.Background(), "access-token-123", "device-123", 0)
	if err == nil {
		t.Fatal("OpenTunnel() returned nil error for http:// non-localhost URL")
	}
}

// TestOpenTunnelValidatesArguments locks client-side guard rails: missing
// access token / device id / negative max_lifetime reject locally so the
// CLI doesn't waste a network round-trip on an unbuilt request.
func TestOpenTunnelValidatesArguments(t *testing.T) {
	client := New("https://broker.example.com", http.DefaultClient)
	cases := []struct {
		name        string
		accessToken string
		deviceID    string
		maxLifetime int32
	}{
		{name: "missing-access-token", deviceID: "d"},
		{name: "missing-device-id", accessToken: "t"},
		{name: "negative-max-lifetime", accessToken: "t", deviceID: "d", maxLifetime: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.OpenTunnel(context.Background(), tc.accessToken, tc.deviceID, tc.maxLifetime)
			if err == nil {
				t.Fatalf("OpenTunnel(%+v) returned nil error", tc)
			}
		})
	}
}

// TestOpenTunnelRejectsEmptyResponseFields locks the defensive guard
// against a broker that returns a 200 with missing tunnel-id / source-
// access-token / region — that would crash the CLI's source proxy at
// dial time, so reject up front.
func TestOpenTunnelRejectsEmptyResponseFields(t *testing.T) {
	cases := []struct {
		name string
		body broker.TunnelOpenResponse
	}{
		{"missing-source-access-token", broker.TunnelOpenResponse{TunnelID: "t", Region: "r"}},
		{"missing-tunnel-id", broker.TunnelOpenResponse{SourceAccessToken: "s", Region: "r"}},
		{"missing-region", broker.TunnelOpenResponse{TunnelID: "t", SourceAccessToken: "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(writer).Encode(tc.body)
			}))
			defer server.Close()
			client := New(server.URL, server.Client())
			_, err := client.OpenTunnel(context.Background(), "access-token-123", "device-123", 0)
			if err == nil {
				t.Fatalf("OpenTunnel() returned nil error for response %+v", tc.body)
			}
		})
	}
}
