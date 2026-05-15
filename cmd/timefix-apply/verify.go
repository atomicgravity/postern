// Pure verifier core for timefix-apply. main.go wires it to stdin/stdout/exec.
//
// Wire format:
//
//	header:    {"alg":"EdDSA","typ":"postern-timefix+jwt"}
//	payload:   {"iss","aud","device_serial","nonce","now","issued_to","jti","iat"}
//
// EdDSA-only accepted-algorithm list at ParseSigned closes algorithm-confusion
// at parse time before any signature work. Unknown header/payload fields
// are tolerated so a future broker rev can add fields without breaking
// deployed verifiers.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Exit codes are a stable wire contract for on-device log analysis. Do not
// reorder or repurpose.
const (
	exitSuccess           = 0
	exitBadInput          = 2
	exitAlgTypMismatch    = 3
	exitSignatureFailure  = 4
	exitClaimFailure      = 5
	exitSetterExecFailure = 6
)

// expectedTyp is the JWS header `typ` the broker pins on every payload.
const expectedTyp = "postern-timefix+jwt"

// Sanity-range bounds for the payload's `now`. The setter applies the same
// independent check so the broker→verifier→setter chain rejects garbage
// consistently.
var (
	nowMinBound = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	nowMaxBound = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// MaxJWSBytes caps the JWS Compact read. A real payload is ~400 bytes; the
// cap is 10x. Oversized input maps to exitBadInput.
const MaxJWSBytes = 4096

// timePayloadClaims is the verifier's view of the pinned payload fields.
// Unknown fields are tolerated for forward-compat.
type timePayloadClaims struct {
	Aud          string `json:"aud"`
	DeviceSerial string `json:"device_serial"`
	IAT          int64  `json:"iat"`
	Iss          string `json:"iss"`
	IssuedTo     string `json:"issued_to"`
	JTI          string `json:"jti"`
	Nonce        string `json:"nonce"`
	Now          string `json:"now"`
}

type verifyParams struct {
	JWS            string
	ExpectedSerial string
	ExpectedNonce  string
	CAPublicKey    ed25519.PublicKey
}

// verifyResult carries the validated timestamp and the exit code. Err is
// informational stderr; ExitCode is the wire contract.
type verifyResult struct {
	Timestamp int64
	ExitCode  int
	Err       error
}

// verify is pure: input → exit code + timestamp, no I/O.
//
// Order is load-bearing. The alg pin (via go-jose's accepted-algs list) runs
// before any structural inspection. typ check follows parse. Signature
// verify runs before any claim-content check — payload bytes are
// unauthenticated until verify succeeds.
func verify(params verifyParams) verifyResult {
	if len(params.JWS) == 0 {
		return verifyResult{ExitCode: exitBadInput, Err: errors.New("empty JWS")}
	}
	if len(params.JWS) > MaxJWSBytes {
		return verifyResult{ExitCode: exitBadInput, Err: fmt.Errorf("JWS exceeds %d byte cap", MaxJWSBytes)}
	}
	if len(params.CAPublicKey) != ed25519.PublicKeySize {
		return verifyResult{ExitCode: exitSignatureFailure, Err: fmt.Errorf("CA public key wrong size: %d", len(params.CAPublicKey))}
	}

	// EdDSA-only accepted-algorithm list is the alg-confusion defense:
	// any other alg (including "none") fails at parse before any field
	// beyond alg is inspected.
	parsed, err := jose.ParseSigned(params.JWS, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		var algErr *jose.ErrUnexpectedSignatureAlgorithm
		if errors.As(err, &algErr) {
			return verifyResult{ExitCode: exitAlgTypMismatch, Err: fmt.Errorf("alg pin: %w", err)}
		}
		return verifyResult{ExitCode: exitBadInput, Err: fmt.Errorf("parse JWS: %w", err)}
	}
	if len(parsed.Signatures) != 1 {
		return verifyResult{ExitCode: exitBadInput, Err: fmt.Errorf("JWS must carry exactly one signature, got %d", len(parsed.Signatures))}
	}

	typ, _ := parsed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ != expectedTyp {
		return verifyResult{ExitCode: exitAlgTypMismatch, Err: fmt.Errorf("header typ = %q, want %q", typ, expectedTyp)}
	}

	payloadBytes, err := parsed.Verify(params.CAPublicKey)
	if err != nil {
		return verifyResult{ExitCode: exitSignatureFailure, Err: fmt.Errorf("verify signature: %w", err)}
	}

	var claims timePayloadClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return verifyResult{ExitCode: exitClaimFailure, Err: fmt.Errorf("parse payload: %w", err)}
	}

	expectedAud := "device-" + params.ExpectedSerial + "-timefix"
	if claims.Aud != expectedAud {
		return verifyResult{ExitCode: exitClaimFailure, Err: fmt.Errorf("aud = %q, want %q", claims.Aud, expectedAud)}
	}
	if claims.DeviceSerial != params.ExpectedSerial {
		return verifyResult{ExitCode: exitClaimFailure, Err: fmt.Errorf("device_serial = %q, want %q", claims.DeviceSerial, params.ExpectedSerial)}
	}
	if claims.Nonce != params.ExpectedNonce {
		return verifyResult{ExitCode: exitClaimFailure, Err: errors.New("nonce mismatch")}
	}

	// `now` must parse as RFC 3339 and fall within [2024, 2099). The device
	// clock is NOT consulted — the broker's `now` is what we're using to
	// fix it.
	parsedNow, err := time.Parse(time.RFC3339, claims.Now)
	if err != nil {
		return verifyResult{ExitCode: exitClaimFailure, Err: fmt.Errorf("parse now: %w", err)}
	}
	if parsedNow.Before(nowMinBound) || !parsedNow.Before(nowMaxBound) {
		return verifyResult{ExitCode: exitClaimFailure, Err: fmt.Errorf("now %s out of [2024,2099) bound", claims.Now)}
	}

	return verifyResult{Timestamp: parsedNow.Unix(), ExitCode: exitSuccess}
}
