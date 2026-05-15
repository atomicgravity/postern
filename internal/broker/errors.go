// Package broker is the broker's domain layer: the issuer pipelines
// (SSHCertIssuer, TimePayloadIssuer, TunnelIssuer), the abstraction
// interfaces they depend on, the wire-format request/response types, and
// the error vocabulary.
//
// Two error patterns live here: sentinel errors (callers match with
// errors.Is) and a status-bearing Error (HTTP handlers translate via
// errors.As). The HTTP shim in pkg/brokerhandlers translates outward — the
// import direction stays one-way.
package broker

import "errors"

// Sentinel errors for issuer dependency validation. Joined via errors.Join
// in the New*Issuer constructors when multiple deps are missing.
var (
	ErrTokenVerifierRequired = errors.New("token verifier is required")
	ErrRegistryRequired      = errors.New("registry is required")
	ErrPolicyRequired        = errors.New("policy is required")
	ErrRateLimiterRequired   = errors.New("rate limiter is required")
	ErrSignerRequired        = errors.New("signer is required")
	ErrAuditRequired         = errors.New("audit sink is required")
	ErrTunnelingRequired     = errors.New("tunneling backend is required")
)

// Error is a broker-domain error carrying an HTTP status code. The HTTP
// handler extracts StatusCode via errors.As and writes the matching JSON
// error body. Use Error for failures the wire side should surface with a
// specific status; return plain errors for things that should default to
// 500.
type Error struct {
	StatusCode int
	Message    string
}

func (e Error) Error() string {
	return e.Message
}
