// Package signer is the broker's CertSigner impl: an AWS KMS-backed Ed25519
// signer that fetches the public key once at startup and delegates each
// signing call to KMS Sign.
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

// ErrKMSKeyARNRequired is returned by NewKMSSigner when the key ARN is empty.
var ErrKMSKeyARNRequired = errors.New("KMS key ARN is required")

// KMSClient is the subset of the KMS API the signer consumes.
type KMSClient interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner signs SSH certificates and time payloads with an Ed25519 key
// held inside AWS KMS.
type KMSSigner struct {
	client    KMSClient
	keyID     string
	publicKey ssh.PublicKey
}

// NewKMSSignerFromConfig wires the KMS client from an aws.Config and
// delegates to NewKMSSigner.
func NewKMSSignerFromConfig(ctx context.Context, config aws.Config, keyID string) (*KMSSigner, error) {
	return NewKMSSigner(ctx, kms.NewFromConfig(config), keyID)
}

// NewKMSSigner constructs a KMSSigner. The public key is fetched once so
// per-issue calls only invoke kms.Sign. Returns an error if the key is not
// Ed25519.
func NewKMSSigner(ctx context.Context, client KMSClient, keyID string) (*KMSSigner, error) {
	if keyID == "" {
		return nil, ErrKMSKeyARNRequired
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}

	ed25519PublicKey, ok := parsedPublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("KMS key must be Ed25519")
	}

	sshPublicKey, err := ssh.NewPublicKey(ed25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("convert KMS public key to SSH: %w", err)
	}

	return &KMSSigner{client: client, keyID: keyID, publicKey: sshPublicKey}, nil
}

func (s *KMSSigner) PublicKey() ssh.PublicKey {
	return s.publicKey
}

// SignCert signs cert via KMS Sign.
func (s *KMSSigner) SignCert(ctx context.Context, cert *ssh.Certificate) error {
	return cert.SignCert(rand.Reader, kmsSSHSigner{ctx: ctx, signer: s})
}

// SignTimePayload signs the JWS signing-input via KMS Sign and returns the
// raw Ed25519 signature bytes. There is intentionally no generic Sign([]byte)
// on this type — domain separation between SSH cert TBS bytes (length-
// prefixed binary opening with "ssh-ed25519-cert-v01@openssh.com") and JWS
// signing-inputs (ASCII base64url starting "eyJ") rests on their structural
// non-overlap. A future signing role MUST add a new purpose-specific method
// with its own non-overlap argument.
func (s *KMSSigner) SignTimePayload(ctx context.Context, signingInput []byte) ([]byte, error) {
	output, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          signingInput,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return output.Signature, nil
}

// kmsSSHSigner adapts KMSSigner to ssh.Signer (which predates
// context.Context). The per-call ctx is captured on the struct so the KMS
// hot path keeps request-cancel propagation; the struct is built and
// consumed inside a single SignCert call.
type kmsSSHSigner struct {
	ctx    context.Context
	signer *KMSSigner
}

func (s kmsSSHSigner) PublicKey() ssh.PublicKey {
	return s.signer.publicKey
}

func (s kmsSSHSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	output, err := s.signer.client.Sign(s.ctx, &kms.SignInput{
		KeyId:            aws.String(s.signer.keyID),
		Message:          data,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return &ssh.Signature{Format: s.signer.publicKey.Type(), Blob: output.Signature}, nil
}
