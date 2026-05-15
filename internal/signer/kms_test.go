package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"
)

func TestKMSSignerSignsOpenSSHCert(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	client := &fakeKMSClient{publicKeyDER: publicKeyDER, privateKey: privateKey}
	signer, err := NewKMSSigner(context.Background(), client, "arn:aws:kms:us-west-2:123:key/test")
	if err != nil {
		t.Fatalf("NewKMSSigner() error = %v", err)
	}

	subject := newSubjectPublicKey(t)
	cert := &ssh.Certificate{
		Key:             subject,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "test-cert",
		ValidPrincipals: []string{"device-SERIAL123-operator"},
		ValidAfter:      uint64(time.Unix(1746996400, 0).Unix()),
		ValidBefore:     uint64(time.Unix(1747043200, 0).Unix()),
	}
	if err := signer.SignCert(context.Background(), cert); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	if cert.Signature == nil {
		t.Fatal("cert signature missing")
	}
	if got, want := client.signingAlgorithm, types.SigningAlgorithmSpecEd25519Sha512; got != want {
		t.Fatalf("signing algorithm = %q, want %q", got, want)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(cert)); err != nil {
		t.Fatalf("ParseAuthorizedKey(cert) error = %v", err)
	}
}

// TestKMSSignerSignTimePayloadProducesVerifiableJWS confirms that the
// SignTimePayload method produces a raw Ed25519 signature that, when
// assembled into a JWS Compact serialization (header.payload.signature),
// is parseable by go-jose and verifies against the same Ed25519 public
// key. This is the load-bearing test for invariant R + LD-71: the broker
// pipeline's signed time payload must round-trip through a stock JWS
// parser.
func TestKMSSignerSignTimePayloadProducesVerifiableJWS(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	client := &fakeKMSClient{publicKeyDER: publicKeyDER, privateKey: privateKey}
	signer, err := NewKMSSigner(context.Background(), client, "arn:aws:kms:us-west-2:123:key/test")
	if err != nil {
		t.Fatalf("NewKMSSigner() error = %v", err)
	}

	headerJSON := []byte(`{"alg":"EdDSA","typ":"postern-timefix+jwt"}`)
	payloadJSON := []byte(`{"iss":"postern.broker","aud":"device-SERIAL123-timefix","device_serial":"SERIAL123","nonce":"AAAA","now":"2026-05-13T00:00:00Z","issued_to":"sub-123","jti":"01969cc1-2800-7000-8000-000000000001","iat":1747000000}`)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature, err := signer.SignTimePayload(context.Background(), []byte(signingInput))
	if err != nil {
		t.Fatalf("SignTimePayload() error = %v", err)
	}
	if got, want := client.signingAlgorithm, types.SigningAlgorithmSpecEd25519Sha512; got != want {
		t.Fatalf("signing algorithm = %q, want %q", got, want)
	}

	compact := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	if strings.Count(compact, ".") != 2 {
		t.Fatalf("compact JWS = %q, want exactly three dot-separated segments", compact)
	}

	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("jose.ParseSigned() error = %v", err)
	}
	verifiedPayload, err := parsed.Verify(publicKey)
	if err != nil {
		t.Fatalf("JWS.Verify() error = %v", err)
	}
	if string(verifiedPayload) != string(payloadJSON) {
		t.Fatalf("verified payload = %s, want %s", verifiedPayload, payloadJSON)
	}
}

func newSubjectPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	return sshPublicKey
}

type fakeKMSClient struct {
	publicKeyDER     []byte
	privateKey       ed25519.PrivateKey
	signingAlgorithm types.SigningAlgorithmSpec
}

func (c *fakeKMSClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, options ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{PublicKey: c.publicKeyDER}, nil
}

func (c *fakeKMSClient) Sign(ctx context.Context, input *kms.SignInput, options ...func(*kms.Options)) (*kms.SignOutput, error) {
	c.signingAlgorithm = input.SigningAlgorithm
	return &kms.SignOutput{Signature: ed25519.Sign(c.privateKey, input.Message)}, nil
}
