// Package brokerhandlers exposes the broker's HTTP surface as composable
// handlers wrappers can mount on their own router. It's the wire-format
// adapter: JSON requests in, broker domain types out and vice versa.
package brokerhandlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/realclientip/realclientip-go"
)

// MaxRequestBodyBytes caps every request body. The largest legitimate
// payload is an authorized_keys public key (a few KB); 64KB leaves
// generous slack while bounding handler memory.
const MaxRequestBodyBytes = 64 * 1024

// Per-field rune caps for engineer-influenced inputs. Without these, an
// oversized value lands in CloudWatch (256KB-per-event ceiling) or the
// DynamoDB rate-limit partition key (2KB cap) and surfaces as a 500;
// bounding here turns that into a clean 400.
//
// maxNonceRunes: a 32-byte base64url nonce is 43 ASCII chars; the cap
// leaves slack but stops kilobyte payloads from landing in the audit row
// before the 32-byte structured check runs.
const (
	maxUserAgentRunes = 512
	maxDeviceIDRunes  = 256
	maxNonceRunes     = 256
)

// Deps wires the abstractions the HTTP handlers call. A nil HealthChecker
// makes /healthz unconditionally OK; a nil SSHCertIssuer makes /healthz
// return 503 and /ssh/cert return 501 — a wrapping-misconfigured broker
// fails health checks closed rather than looking green to a load balancer.
//
// A nil TimePayloadIssuer / TunnelIssuer makes the matching endpoint return
// 501 (same pattern). ClientIPStrategy parses the source IP defending
// against X-Forwarded-For forgery; nil falls back to the socket address.
type Deps struct {
	HealthChecker     HealthChecker
	SSHCertIssuer     SSHCertIssuer
	TimePayloadIssuer TimePayloadIssuer
	TunnelIssuer      TunnelIssuer
	ClientIPStrategy  realclientip.Strategy
}

// HealthChecker is invoked by /healthz. The unwrapped broker ships no
// built-in checker; operators supply their own when needed.
type HealthChecker interface {
	CheckHealth(context.Context) error
}

// SSHCertIssuer is the abstraction /ssh/cert invokes. Concrete impl is
// *broker.SSHCertIssuer. RecordSSHCertHandlerDenial emits the deny audit
// row when the handler rejects before IssueSSHCert can run.
type SSHCertIssuer interface {
	IssueSSHCert(context.Context, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error)
	RecordSSHCertHandlerDenial(context.Context, broker.HandlerDenial)
}

// TimePayloadIssuer is the abstraction /ssh/time-payload invokes.
type TimePayloadIssuer interface {
	IssueTimePayload(context.Context, broker.TimePayloadIssueRequest) (broker.TimePayloadIssueResponse, error)
	RecordTimePayloadHandlerDenial(context.Context, broker.HandlerDenial)
}

// TunnelIssuer is the abstraction /ssh/tunnel invokes.
type TunnelIssuer interface {
	OpenTunnel(context.Context, broker.TunnelOpenRequest) (broker.TunnelOpenResponse, error)
	RecordTunnelHandlerDenial(context.Context, broker.HandlerDenial)
}

// New returns the broker's HTTP handler mounted on a fresh ServeMux.
// Wrappers wanting their own router compose the per-endpoint handlers
// directly.
func New(deps Deps) http.Handler {
	if deps.ClientIPStrategy == nil {
		deps.ClientIPStrategy = realclientip.RemoteAddrStrategy{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz(deps.HealthChecker, deps.SSHCertIssuer))
	mux.HandleFunc("POST /ssh/cert", handleSSHCert(deps.SSHCertIssuer, deps.ClientIPStrategy))
	mux.HandleFunc("POST /ssh/time-payload", handleTimePayload(deps.TimePayloadIssuer, deps.ClientIPStrategy))
	mux.HandleFunc("POST /ssh/tunnel", handleTunnel(deps.TunnelIssuer, deps.ClientIPStrategy))
	return withBodyLimit(mux)
}

// withBodyLimit wraps every body with http.MaxBytesReader so handlers (and
// the API Gateway → Lambda buffer) can't be coerced into holding unbounded
// payloads.
func withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Body != nil {
			request.Body = http.MaxBytesReader(response, request.Body, MaxRequestBodyBytes)
		}
		next.ServeHTTP(response, request)
	})
}

func handleHealthz(checker HealthChecker, issuer SSHCertIssuer) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		// Fail closed when SSHCertIssuer isn't wired — a "healthy" broker
		// that can't actually mint certs looks green to a load balancer
		// while every /ssh/cert returns 501.
		if issuer == nil {
			writeError(response, http.StatusServiceUnavailable, "ssh cert issuer is not configured")
			return
		}
		if checker != nil {
			if err := checker.CheckHealth(request.Context()); err != nil {
				writeError(response, http.StatusServiceUnavailable, "unhealthy")
				return
			}
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
	}
}

// handleIssueEndpoint is the shared handler shape for every issue endpoint:
// cap UserAgent → resolve source IP → parse bearer (handler-denial on miss)
// → JSON-decode with DisallowUnknownFields (handler-denial on malformed) →
// normalize → dispatch → empty-check → writeJSON. Per-endpoint variation is
// the normalize / dispatch / emptyCheck closures.
func handleIssueEndpoint[Req, Resp any](
	handlerDenialEmit func(context.Context, broker.HandlerDenial),
	clientIP realclientip.Strategy,
	label string,
	normalize func(body *Req, accessToken, userAgent, sourceIP string),
	dispatch func(context.Context, Req) (Resp, error),
	emptyCheck func(Resp) (bool, string),
) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		userAgent := broker.TruncateRunes(request.UserAgent(), maxUserAgentRunes)
		sourceIP := clientIP.ClientIP(request.Header, request.RemoteAddr)

		accessToken, err := bearerToken(request.Header.Get("Authorization"))
		if err != nil {
			handlerDenialEmit(request.Context(), broker.HandlerDenial{
				DeniedReason: broker.DenyReasonMissingBearerToken,
				SourceIP:     sourceIP,
				UserAgent:    userAgent,
			})
			writeError(response, http.StatusUnauthorized, err.Error())
			return
		}

		var body Req
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			handlerDenialEmit(request.Context(), broker.HandlerDenial{
				DeniedReason: broker.DenyReasonMalformedRequestBody,
				SourceIP:     sourceIP,
				UserAgent:    userAgent,
			})
			writeError(response, http.StatusBadRequest, "invalid JSON request body")
			return
		}

		// Normalize + cap. Deeper shape checks (principal_type, nonce
		// length, TTL clamp) run inside the pipeline so rejections produce
		// audit rows with engineer/device context known at that point.
		normalize(&body, accessToken, userAgent, sourceIP)

		issued, err := dispatch(request.Context(), body)
		if err != nil {
			writeIssueError(response, label+" issuer", err)
			return
		}
		if ok, message := emptyCheck(issued); !ok {
			writeError(response, http.StatusInternalServerError, message)
			return
		}
		writeJSON(response, http.StatusOK, issued)
	}
}

// notConfiguredHandler returns the 501 handler used when an issuer is nil.
// The unwrapped broker always supplies one; nil is a wrapping signal.
func notConfiguredHandler(label string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		writeError(response, http.StatusNotImplemented, label+" issuer is not configured")
	}
}

func handleSSHCert(issuer SSHCertIssuer, clientIP realclientip.Strategy) http.HandlerFunc {
	if issuer == nil {
		return notConfiguredHandler("ssh cert")
	}
	return handleIssueEndpoint(
		issuer.RecordSSHCertHandlerDenial,
		clientIP,
		"ssh cert",
		func(body *broker.SSHCertIssueRequest, accessToken, userAgent, sourceIP string) {
			body.DeviceID = broker.TruncateRunes(strings.TrimSpace(body.DeviceID), maxDeviceIDRunes)
			body.PublicKey = strings.TrimSpace(body.PublicKey)
			body.AccessToken = accessToken
			body.UserAgent = userAgent
			body.RemoteAddr = sourceIP
		},
		issuer.IssueSSHCert,
		func(resp broker.SSHCertIssueResponse) (bool, string) {
			if strings.TrimSpace(resp.SSHCert) == "" {
				return false, "ssh cert issuer returned empty certificate"
			}
			return true, ""
		},
	)
}

func handleTimePayload(issuer TimePayloadIssuer, clientIP realclientip.Strategy) http.HandlerFunc {
	if issuer == nil {
		return notConfiguredHandler("time-payload")
	}
	return handleIssueEndpoint(
		issuer.RecordTimePayloadHandlerDenial,
		clientIP,
		"time-payload",
		func(body *broker.TimePayloadIssueRequest, accessToken, userAgent, sourceIP string) {
			body.DeviceID = broker.TruncateRunes(strings.TrimSpace(body.DeviceID), maxDeviceIDRunes)
			body.Nonce = broker.TruncateRunes(strings.TrimSpace(body.Nonce), maxNonceRunes)
			body.AccessToken = accessToken
			body.UserAgent = userAgent
			body.RemoteAddr = sourceIP
		},
		issuer.IssueTimePayload,
		func(resp broker.TimePayloadIssueResponse) (bool, string) {
			if strings.TrimSpace(resp.TimePayload) == "" {
				return false, "time payload issuer returned empty payload"
			}
			return true, ""
		},
	)
}

func handleTunnel(issuer TunnelIssuer, clientIP realclientip.Strategy) http.HandlerFunc {
	if issuer == nil {
		return notConfiguredHandler("tunnel")
	}
	return handleIssueEndpoint(
		issuer.RecordTunnelHandlerDenial,
		clientIP,
		"tunnel",
		func(body *broker.TunnelOpenRequest, accessToken, userAgent, sourceIP string) {
			body.DeviceID = broker.TruncateRunes(strings.TrimSpace(body.DeviceID), maxDeviceIDRunes)
			body.AccessToken = accessToken
			body.UserAgent = userAgent
			body.RemoteAddr = sourceIP
		},
		issuer.OpenTunnel,
		func(resp broker.TunnelOpenResponse) (bool, string) {
			if strings.TrimSpace(resp.SourceAccessToken) == "" {
				return false, "tunnel issuer returned empty source access token"
			}
			return true, ""
		},
	)
}

// bearerToken parses an "Authorization: Bearer <token>" header per RFC 6750.
// Strict on the whitespace shape — strings.Fields would accept folded
// headers and arbitrary Unicode whitespace, a header-smuggling primitive
// against downstream filters that disagree with Go on whitespace.
func bearerToken(header string) (string, error) {
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", errors.New("authorization bearer token is required")
	}
	token := strings.TrimSpace(header[len(scheme):])
	if token == "" {
		return "", errors.New("authorization bearer token is required")
	}
	return token, nil
}

// writeIssueError surfaces a pipeline error as an HTTP response. routeLabel
// flows into both the slog line and the engineer-facing 500 body so the
// three handlers don't share a single hardcoded label that misattributes
// failures across routes. 4xx domain errors stay quiet in logs (engineer
// fault); 5xx logs at error; non-domain errors log raw but surface a
// generic message so internal detail doesn't leak to the CLI.
func writeIssueError(response http.ResponseWriter, routeLabel string, err error) {
	var domainErr broker.Error
	if errors.As(err, &domainErr) && domainErr.StatusCode >= 400 {
		if domainErr.StatusCode >= 500 {
			slog.Error(routeLabel+" returned server-fault error",
				slog.Int("status", domainErr.StatusCode),
				slog.String("err", err.Error()))
		}
		writeError(response, domainErr.StatusCode, domainErr.Message)
		return
	}

	slog.Error(routeLabel+" failed with unexpected error",
		slog.String("err", err.Error()))
	writeError(response, http.StatusInternalServerError, routeLabel+" failed")
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}
