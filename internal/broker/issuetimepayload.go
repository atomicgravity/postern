package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// TimePayloadIssuer runs the broker's time-payload-mint pipeline.
//
// Wire format:
//
//	header:  {"alg":"EdDSA","typ":"postern-timefix+jwt"}
//	payload: {"iss","aud","device_serial","nonce","now","issued_to","jti","iat"}
//
// JWS Compact serialization via go-jose/v4 with an EdDSA-only accepted-
// algorithm list on the device side. Library-on-both-sides removes the
// parser/serializer differential surface where alg-confusion and
// malformed-segment bugs live.
const (
	timePayloadIssuer    = "postern.broker"
	timePayloadAudPrefix = "device-"
	timePayloadAudSuffix = "-timefix"

	// timePayloadJWSType is the JWS header `typ` the verifier requires.
	// Together with the EdDSA alg pin it forms the two-field minimum the
	// device side enforces against algorithm-confusion.
	timePayloadJWSType = "postern-timefix+jwt"

	// nonceDecodedBytes is the engineer-supplied nonce shape: 32 random
	// bytes from the device, base64url-encoded with no padding.
	nonceDecodedBytes = 32
)

// TimePayloadIssueRequest is the broker-domain request to mint a signed JWS
// time payload. JSON tags pin the wire format on /ssh/time-payload.
type TimePayloadIssueRequest struct {
	AccessToken string `json:"-"`
	DeviceID    string `json:"device_id"`
	Nonce       string `json:"nonce"`
	UserAgent   string `json:"-"`
	RemoteAddr  string `json:"-"`
}

// TimePayloadIssueResponse is the broker-domain response. TimePayload is the
// JWS Compact serialization the CLI pipes to the device; JTI is surfaced for
// operator log correlation with the audit trail.
type TimePayloadIssueResponse struct {
	TimePayload string `json:"time_payload"`
	JTI         string `json:"jti"`
}

// TimePayloadIssuerDeps wires the per-issue dependencies into the
// time-payload-mint pipeline.
type TimePayloadIssuerDeps struct {
	PipelineDeps
	Signer CertSigner
}

// TimePayloadIssuer runs /ssh/time-payload's pipeline.
type TimePayloadIssuer struct {
	PipelineDeps
	signer CertSigner
}

// NewTimePayloadIssuer constructs a TimePayloadIssuer. Missing deps return
// joined Err* sentinels.
func NewTimePayloadIssuer(deps TimePayloadIssuerDeps) (*TimePayloadIssuer, error) {
	pipelineErr := deps.PipelineDeps.validate()

	var signerErr error
	if deps.Signer == nil {
		signerErr = ErrSignerRequired
	}

	if joined := errors.Join(pipelineErr, signerErr); joined != nil {
		return nil, joined
	}

	return &TimePayloadIssuer{PipelineDeps: deps.PipelineDeps.withDefaults(), signer: deps.Signer}, nil
}

// timePayloadClaims is the eight-field payload set the broker emits. Adding
// a field is a v2 wire-format change; the on-device verifier inspects only
// these eight.
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

// IssueTimePayload runs the time-payload-mint pipeline end to end. Mirrors
// IssueSSHCert's shape: engineer preamble, request-shape (nonce) check,
// device preamble, fail-closed pre-sign audit, JWS sign, best-effort
// post-sign audit. On sign failure a paired denied row is emitted with
// denied_reason=signer_failure so operators can join authorized vs denied
// on jti.
func (i *TimePayloadIssuer) IssueTimePayload(ctx context.Context, request TimePayloadIssueRequest) (TimePayloadIssueResponse, error) {
	engineerCtx, denial, err := i.verifyEngineer(ctx, engineerPreambleRequest{
		AccessToken: request.AccessToken,
		Mode:        ModeTimefix,
		SourceIP:    request.RemoteAddr,
		UserAgent:   request.UserAgent,
	})
	if err != nil {
		return TimePayloadIssueResponse{}, fmt.Errorf("generate time payload id: %w", err)
	}
	if denial != nil {
		i.recordTimePayloadDenialFor(ctx, denial.Event, denial.DeniedReason, request)
		return TimePayloadIssueResponse{}, denial.Err
	}

	trimmedNonce := strings.TrimSpace(request.Nonce)
	if trimmedNonce == "" {
		i.recordTimePayloadDenialFor(ctx, denialTemplate(engineerCtx), DenyReasonMissingNonce, request)
		return TimePayloadIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: "nonce is required"}
	}
	decodedNonce, err := base64.RawURLEncoding.DecodeString(trimmedNonce)
	if err != nil || len(decodedNonce) != nonceDecodedBytes {
		i.recordTimePayloadDenialFor(ctx, denialTemplate(engineerCtx), DenyReasonInvalidNonce, request)
		return TimePayloadIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("nonce must be %d base64url-decoded bytes", nonceDecodedBytes)}
	}

	deviceCtx, denial, err := i.resolveDevice(ctx, devicePreambleRequest{
		Engineer:    engineerCtx.Engineer,
		AccessToken: request.AccessToken,
		DeviceID:    request.DeviceID,
		Mode:        ModeTimefix,
		SourceIP:    engineerCtx.SourceIP,
		UserAgent:   engineerCtx.UserAgent,
		JTI:         engineerCtx.JTI,
		Now:         engineerCtx.Now,
	})
	if err != nil {
		return TimePayloadIssueResponse{}, err
	}
	if denial != nil {
		i.recordTimePayloadDenialFor(ctx, denial.Event, denial.DeniedReason, request)
		return TimePayloadIssueResponse{}, denial.Err
	}

	// `now` is ISO8601 per DESIGN.md; `iat` is unix seconds per JWT RFC 7519.
	// `issued_to` carries the engineer subject for on-device audit logs
	// without exposing the access token.
	claims := timePayloadClaims{
		Aud:          timePayloadAudPrefix + deviceCtx.Device.Serial + timePayloadAudSuffix,
		DeviceSerial: deviceCtx.Device.Serial,
		IAT:          engineerCtx.Now.Unix(),
		Iss:          timePayloadIssuer,
		IssuedTo:     engineerCtx.Engineer.Subject,
		JTI:          engineerCtx.JTI,
		Nonce:        trimmedNonce,
		Now:          engineerCtx.Now.Format(time.RFC3339),
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return TimePayloadIssueResponse{}, fmt.Errorf("marshal time payload claims: %w", err)
	}

	authorized := AuditEvent{
		Timestamp:      engineerCtx.Now,
		Event:          EventTimePayloadAuthorized,
		EngineerSub:    engineerCtx.Engineer.Subject,
		EngineerEmail:  engineerCtx.Engineer.Email,
		EngineerGroups: engineerCtx.Engineer.Groups,
		DeviceSerial:   deviceCtx.Device.Serial,
		DeviceIDUsed:   request.DeviceID,
		PrincipalType:  ModeTimefix,
		JTI:            engineerCtx.JTI,
		IssuedAt:       engineerCtx.Now.Unix(),
		SourceIP:       engineerCtx.SourceIP,
		UserAgent:      engineerCtx.UserAgent,
	}
	if err := i.recordAuthorized(ctx, authorized); err != nil {
		return TimePayloadIssueResponse{}, fmt.Errorf("record time payload audit event: %w", err)
	}

	// OpaqueSigner adapts CertSigner.SignTimePayload to go-jose, capturing
	// the per-request ctx so KMS calls inherit cancellation. WithType pins
	// `typ`; SigningKey pins `alg=EdDSA`. Public() returns nil so the
	// library omits kid/jwk — v1 has one CA pubkey installed on device.
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: timePayloadOpaqueSigner{ctx: ctx, signer: i.signer}},
		(&jose.SignerOptions{}).WithType(timePayloadJWSType),
	)
	if err != nil {
		signerDenial := denialTemplate(engineerCtx)
		signerDenial.DeviceSerial = deviceCtx.Device.Serial
		i.recordTimePayloadDenialFor(ctx, signerDenial, DenyReasonSignerFailure, request)
		return TimePayloadIssueResponse{}, fmt.Errorf("new time payload signer: %w", err)
	}
	signed, err := joseSigner.Sign(payloadJSON)
	if err != nil {
		signerDenial := denialTemplate(engineerCtx)
		signerDenial.DeviceSerial = deviceCtx.Device.Serial
		i.recordTimePayloadDenialFor(ctx, signerDenial, DenyReasonSignerFailure, request)
		return TimePayloadIssueResponse{}, fmt.Errorf("sign time payload: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		signerDenial := denialTemplate(engineerCtx)
		signerDenial.DeviceSerial = deviceCtx.Device.Serial
		i.recordTimePayloadDenialFor(ctx, signerDenial, DenyReasonSignerFailure, request)
		return TimePayloadIssueResponse{}, fmt.Errorf("serialize time payload: %w", err)
	}

	// Post-sign audit is best-effort: the payload is already signed and
	// returning to the engineer.
	issued := authorized
	issued.Event = EventTimePayloadIssued
	if err := i.Audit.Record(ctx, issued); err != nil {
		slog.Error("record time payload issuance audit event",
			slog.String("err", err.Error()),
			slog.String("engineer_sub", engineerCtx.Engineer.Subject),
			slog.String("device_serial", deviceCtx.Device.Serial),
			slog.String("jti", engineerCtx.JTI))
	}

	return TimePayloadIssueResponse{
		TimePayload: compact,
		JTI:         engineerCtx.JTI,
	}, nil
}

// recordTimePayloadDenialFor stamps the endpoint fields and emits the
// best-effort time_payload_denied audit row.
func (i *TimePayloadIssuer) recordTimePayloadDenialFor(ctx context.Context, event AuditEvent, deniedReason string, request TimePayloadIssueRequest) {
	event.Event = EventTimePayloadDenied
	event.DeniedReason = deniedReason
	event.DeviceIDUsed = request.DeviceID
	event.PrincipalType = ModeTimefix
	i.recordEndpointDenial(ctx, event, "time payload")
}

// RecordTimePayloadHandlerDenial emits the deny audit row for HTTP-handler-
// layer rejections before IssueTimePayload runs. Parallels
// RecordSSHCertHandlerDenial.
func (i *TimePayloadIssuer) RecordTimePayloadHandlerDenial(ctx context.Context, denial HandlerDenial) {
	i.recordEndpointHandlerDenial(ctx, denial, EventTimePayloadDenied, ModeTimefix, "time payload")
}

// timePayloadOpaqueSigner adapts CertSigner to jose.OpaqueSigner. The ctx is
// captured so the underlying KMS call inherits request cancellation; the
// adapter is built and consumed inside a single IssueTimePayload call.
type timePayloadOpaqueSigner struct {
	ctx    context.Context
	signer CertSigner
}

func (s timePayloadOpaqueSigner) Public() *jose.JSONWebKey {
	return nil
}

func (s timePayloadOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.EdDSA}
}

func (s timePayloadOpaqueSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	return s.signer.SignTimePayload(s.ctx, payload)
}
