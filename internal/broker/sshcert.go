package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// OperatorClockSkewPadding is subtracted from the cert's ValidAfter so a
	// device with a slightly fast clock still accepts a freshly issued cert.
	OperatorClockSkewPadding = time.Hour

	// DefaultOperatorCertTTL is the cert validity window applied when no
	// operator-supplied OperatorTTL is configured.
	DefaultOperatorCertTTL = 12 * time.Hour

	// timefixForceCommandPath is the on-device verifier the timefix cert's
	// force-command pins. Hardcoded because the cert shape is part of the
	// device-side wire contract and must agree with the reference install
	// layout.
	timefixForceCommandPath = "/usr/sbin/timefix-apply"
)

// timefixCertValidAfter / timefixCertValidBefore bracket the timefix cert's
// validity window. The 1970→3000 range is intentional: the recovery flow
// exists precisely for devices whose clock is wildly wrong, so bounding by
// engineer-host clock would defeat the use case. The JWS payload's `now`
// carries the time-binding for the actual clock-set, validated separately.
//
// The lower bound is pinned to the Unix epoch — dead-RTC devices commonly
// boot reading exactly that. Going earlier is actively wrong: Unix() returns
// negative int64 for pre-epoch dates and uint64(-1) wraps to MaxUint64,
// making the cert "not yet valid" until year 292277.
var (
	timefixCertValidAfter  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	timefixCertValidBefore = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
)

// SSHCertIssuerDeps wires the per-issue dependencies into the cert-mint
// pipeline. OperatorTTL falls back to DefaultOperatorCertTTL when zero.
type SSHCertIssuerDeps struct {
	PipelineDeps
	Signer      CertSigner
	OperatorTTL time.Duration
}

// SSHCertIssuer runs the broker's cert-mint pipeline.
type SSHCertIssuer struct {
	PipelineDeps
	signer      CertSigner
	operatorTTL time.Duration
}

// NewSSHCertIssuer constructs an SSHCertIssuer. Missing deps are reported via
// errors.Join of the Err* sentinels so callers can match each with errors.Is.
func NewSSHCertIssuer(deps SSHCertIssuerDeps) (*SSHCertIssuer, error) {
	pipelineErr := deps.PipelineDeps.validate()

	var signerErr error
	if deps.Signer == nil {
		signerErr = ErrSignerRequired
	}

	if joined := errors.Join(pipelineErr, signerErr); joined != nil {
		return nil, joined
	}

	pipeline := deps.PipelineDeps.withDefaults()
	ttl := deps.OperatorTTL
	if ttl <= 0 {
		ttl = DefaultOperatorCertTTL
	}

	return &SSHCertIssuer{PipelineDeps: pipeline, signer: deps.Signer, operatorTTL: ttl}, nil
}

// IssueSSHCert runs the cert-mint pipeline end to end and returns the signed
// cert + CA pubkey fingerprint. broker.Error values carry the intended HTTP
// status; other errors default to 500 at the HTTP boundary.
//
// Pipeline order is load-bearing in two places. public_key validation runs
// AFTER Policy: an unauthorized engineer's malformed key doesn't get input
// feedback — they see authorization_denied, not invalid_public_key. And
// recordAuthorized runs BEFORE Sign and fails closed on emit failure — the
// broker refuses to sign a cert it can't record having decided to issue.
func (i *SSHCertIssuer) IssueSSHCert(ctx context.Context, request SSHCertIssueRequest) (SSHCertIssueResponse, error) {
	engineerCtx, denial, err := i.verifyEngineer(ctx, engineerPreambleRequest{
		AccessToken: request.AccessToken,
		Mode:        ModeOperator,
		SourceIP:    request.RemoteAddr,
		UserAgent:   request.UserAgent,
	})
	if err != nil {
		return SSHCertIssueResponse{}, fmt.Errorf("generate cert id: %w", err)
	}
	if denial != nil {
		i.recordCertDenial(ctx, denial.Event, denial.DeniedReason, request)
		return SSHCertIssueResponse{}, denial.Err
	}

	var mode string
	switch request.PrincipalType {
	case PrincipalTypeOperator:
		mode = ModeOperator
	case PrincipalTypeTimefix:
		mode = ModeTimefix
	default:
		i.recordCertDenial(ctx, denialTemplate(engineerCtx), DenyReasonInvalidPrincipalType, request)
		return SSHCertIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: fmt.Sprintf("principal_type must be %q or %q", PrincipalTypeOperator, PrincipalTypeTimefix)}
	}

	deviceCtx, denial, err := i.resolveDevice(ctx, devicePreambleRequest{
		Engineer:    engineerCtx.Engineer,
		AccessToken: request.AccessToken,
		DeviceID:    request.DeviceID,
		Mode:        mode,
		SourceIP:    engineerCtx.SourceIP,
		UserAgent:   engineerCtx.UserAgent,
		JTI:         engineerCtx.JTI,
		Now:         engineerCtx.Now,
	})
	if err != nil {
		return SSHCertIssueResponse{}, err
	}
	if denial != nil {
		i.recordCertDenial(ctx, denial.Event, denial.DeniedReason, request)
		return SSHCertIssueResponse{}, denial.Err
	}

	if strings.TrimSpace(request.PublicKey) == "" {
		i.recordCertDenialWithDevice(ctx, engineerCtx, deviceCtx, DenyReasonMissingPublicKey, request)
		return SSHCertIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: "public_key is required"}
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(request.PublicKey))
	if err != nil {
		i.recordCertDenialWithDevice(ctx, engineerCtx, deviceCtx, DenyReasonInvalidPublicKey, request)
		return SSHCertIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: "public_key must be an authorized_keys public key"}
	}

	// ParseAuthorizedKey accepts cert-shaped inputs and returns *ssh.Certificate.
	// The downstream cert.SignCert path panics on a cert-as-Key, so reject up
	// front — an authorized engineer can otherwise crash the broker.
	if _, isCert := publicKey.(*ssh.Certificate); isCert {
		i.recordCertDenialWithDevice(ctx, engineerCtx, deviceCtx, DenyReasonInvalidPublicKey, request)
		return SSHCertIssueResponse{}, Error{StatusCode: http.StatusBadRequest, Message: "public_key must be a bare public key, not an SSH certificate"}
	}

	var (
		cert        *ssh.Certificate
		validAfter  time.Time
		validBefore time.Time
	)
	switch mode {
	case ModeOperator:
		validAfter = engineerCtx.Now.Add(-OperatorClockSkewPadding)
		validBefore = engineerCtx.Now.Add(i.operatorTTL)
		cert = buildOperatorCert(engineerCtx, deviceCtx, publicKey, validAfter, validBefore)
	case ModeTimefix:
		validAfter = timefixCertValidAfter
		validBefore = timefixCertValidBefore
		cert = buildTimefixCert(engineerCtx, deviceCtx, publicKey)
	}

	// Pre-sign audit. Fail-closed: a non-nil error aborts before KMS Sign so
	// the broker never mints a cert it couldn't record having decided to mint.
	authorized := AuditEvent{
		Timestamp:      engineerCtx.Now,
		Event:          EventCertAuthorized,
		EngineerSub:    engineerCtx.Engineer.Subject,
		EngineerEmail:  engineerCtx.Engineer.Email,
		EngineerGroups: engineerCtx.Engineer.Groups,
		DeviceSerial:   deviceCtx.Device.Serial,
		DeviceIDUsed:   request.DeviceID,
		PrincipalType:  mode,
		CertSerial:     strconv.FormatUint(engineerCtx.ID.Serial, 10),
		JTI:            engineerCtx.JTI,
		ValidAfter:     validAfter.Unix(),
		ValidBefore:    validBefore.Unix(),
		IssuedAt:       engineerCtx.Now.Unix(),
		SourceIP:       engineerCtx.SourceIP,
		UserAgent:      engineerCtx.UserAgent,
	}
	if err := i.recordAuthorized(ctx, authorized); err != nil {
		return SSHCertIssueResponse{}, fmt.Errorf("record SSH cert audit event: %w", err)
	}

	if err := i.signer.SignCert(ctx, cert); err != nil {
		// Sign failure emits a best-effort deny so the trail records
		// "authorized but couldn't sign" rather than leaving the authorized
		// row unjoined.
		denied := authorized
		denied.Event = EventCertDenied
		denied.DeniedReason = DenyReasonSignerFailure
		i.recordEndpointDenial(ctx, denied, "SSH cert")
		return SSHCertIssueResponse{}, fmt.Errorf("sign SSH cert: %w", err)
	}

	// Post-sign audit is best-effort: the cert is already minted; operators
	// reconcile missed issued rows by joining authorized vs issued on `jti`.
	issued := authorized
	issued.Event = EventCertIssued
	if err := i.Audit.Record(ctx, issued); err != nil {
		slog.Error("record SSH cert issuance audit event",
			slog.String("err", err.Error()),
			slog.String("engineer_sub", engineerCtx.Engineer.Subject),
			slog.String("device_serial", deviceCtx.Device.Serial),
			slog.String("jti", engineerCtx.JTI))
	}

	return SSHCertIssueResponse{
		SSHCert:             strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		CAPubkeyFingerprint: ssh.FingerprintSHA256(i.signer.PublicKey()),
	}, nil
}

// recordCertDenial stamps cert-endpoint Event / PrincipalType / DeviceIDUsed /
// DeniedReason onto a template and emits the best-effort deny row.
func (i *SSHCertIssuer) recordCertDenial(ctx context.Context, event AuditEvent, deniedReason string, request SSHCertIssueRequest) {
	event.Event = EventCertDenied
	event.DeniedReason = deniedReason
	event.DeviceIDUsed = request.DeviceID
	event.PrincipalType = string(request.PrincipalType)
	i.recordEndpointDenial(ctx, event, "SSH cert")
}

// recordCertDenialWithDevice is the post-resolveDevice variant — the device
// serial is known and goes into the template.
func (i *SSHCertIssuer) recordCertDenialWithDevice(ctx context.Context, engineerCtx engineerContext, deviceCtx deviceContext, deniedReason string, request SSHCertIssueRequest) {
	event := denialTemplate(engineerCtx)
	event.DeviceSerial = deviceCtx.Device.Serial
	i.recordCertDenial(ctx, event, deniedReason, request)
}

// RecordSSHCertHandlerDenial emits the deny audit row for /ssh/cert requests
// that failed at the HTTP handler layer (missing bearer, malformed body, ...)
// before IssueSSHCert could run. Required to uphold the "one audit row per
// request" invariant.
func (i *SSHCertIssuer) RecordSSHCertHandlerDenial(ctx context.Context, denial HandlerDenial) {
	i.recordEndpointHandlerDenial(ctx, denial, EventCertDenied, "", "SSH cert")
}

// buildOperatorCert produces the engineer-SSH cert: principal
// "device-<serial>-operator", engineer-clock-derived validity window with
// skew padding, and the full default extension set so the cert behaves like a
// normal key rather than a restricted one. The five extensions are exactly
// what ssh-keygen stamps on a cert by default — pty, port/agent/X11
// forwarding, and user-rc. Authorization lives in the broker Policy and the
// short validity window, not in clamping the engineer's interactive surface
// once access is granted. The timefix cert (buildTimefixCert) is the opposite:
// it denies all of these because it grants nothing beyond a forced command.
func buildOperatorCert(engineerCtx engineerContext, deviceCtx deviceContext, publicKey ssh.PublicKey, validAfter, validBefore time.Time) *ssh.Certificate {
	return &ssh.Certificate{
		Key:             publicKey,
		Serial:          engineerCtx.ID.Serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID(engineerCtx.Engineer, engineerCtx.JTI),
		ValidPrincipals: []string{operatorPrincipal(deviceCtx.Device.Serial)},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
}

// buildTimefixCert produces the on-device-recovery cert. The 1970→3000
// validity window is the recovery flow's hard requirement (a normal window
// would lock out the device that needs fixing). Defense-in-depth comes from
// the force-command critical option pinning the on-device exec to the
// verifier and the timefix-only ValidPrincipals the device's sshd config
// gates force-command activation on. No permit-pty: the cert grants nothing
// beyond the forced command.
func buildTimefixCert(engineerCtx engineerContext, deviceCtx deviceContext, publicKey ssh.PublicKey) *ssh.Certificate {
	return &ssh.Certificate{
		Key:             publicKey,
		Serial:          engineerCtx.ID.Serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID(engineerCtx.Engineer, engineerCtx.JTI),
		ValidPrincipals: []string{timefixPrincipal(deviceCtx.Device.Serial)},
		ValidAfter:      uint64(timefixCertValidAfter.Unix()),
		ValidBefore:     uint64(timefixCertValidBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"force-command": timefixForceCommandPath},
			Extensions:      map[string]string{},
		},
	}
}

func operatorPrincipal(serial string) string {
	return "device-" + serial + "-operator"
}

func timefixPrincipal(serial string) string {
	return "device-" + serial + "-timefix"
}

// keyID composes the SSH cert KeyId. Subject and email are URL-escaped so a
// compromised IdP can't smuggle ';' or '\n' through the structured KeyId log
// queries parse.
func keyID(engineer EngineerClaims, jti string) string {
	return "engineer_sub:" + url.PathEscape(engineer.Subject) +
		";engineer_email:" + url.PathEscape(engineer.Email) +
		";jti:" + jti
}
