package broker

import (
	"context"
	"crypto/rand"

	"golang.org/x/crypto/ssh"
)

// SSHSigner adapts an ssh.Signer to the broker's CertSigner interface for
// tests across packages — Go's _test.go convention can't export across
// package boundaries. Production code uses *signer.KMSSigner; do not reach
// for SSHSigner in non-test paths.
type SSHSigner struct {
	Signer ssh.Signer
}

func (s SSHSigner) PublicKey() ssh.PublicKey {
	return s.Signer.PublicKey()
}

func (s SSHSigner) SignCert(_ context.Context, cert *ssh.Certificate) error {
	return cert.SignCert(rand.Reader, s.Signer)
}

func (s SSHSigner) SignTimePayload(_ context.Context, signingInput []byte) ([]byte, error) {
	signature, err := s.Signer.Sign(rand.Reader, signingInput)
	if err != nil {
		return nil, err
	}
	return signature.Blob, nil
}
