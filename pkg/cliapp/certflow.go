package cliapp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// ErrCertNegativeLifetime is the client-side rejection for a negative
// --cert-max-lifetime. Unlike the tunnel TTL there is no client-side
// maximum: the broker clamps the requested cert lifetime to its
// per-class ceiling, so the CLI must not second-guess that bound.
var ErrCertNegativeLifetime = errors.New("--cert-max-lifetime must be a non-negative duration")

// certLifetimeMinutesFromDuration converts a requested cert TTL → the
// broker's int32 minutes. Zero passes through so the broker substitutes
// its per-class default/ceiling; sub-minute positives round up to 1.
// Negatives are rejected (no client-side maximum — the broker clamps).
func certLifetimeMinutesFromDuration(d time.Duration) (int32, error) {
	if d == 0 {
		return 0, nil
	}
	if d < 0 {
		return 0, ErrCertNegativeLifetime
	}
	minutes := int64(d / time.Minute)
	if d%time.Minute != 0 {
		minutes++
	}
	if minutes < 1 {
		minutes = 1
	}
	return int32(minutes), nil
}

// mintAndCache requests a fresh operator cert for deviceID and stores it.
// certMaxLifetimeMinutes carries the engineer's requested cert TTL (zero
// means "broker default/ceiling"); the broker clamps it to its per-class
// ceiling. Auth failures wrap via mintAuthError so the engineer sees a
// login hint; other errors surface unwrapped to preserve their errors.Is
// identity.
func mintAndCache(cmd *cobra.Command, rt runtime, store *certcache.Store, profile ResolvedProfile, deviceID string, certMaxLifetimeMinutes int32, verbose bool) (*ssh.Certificate, error) {
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		return nil, fmt.Errorf("load profile key: %w", err)
	}

	accessToken, err := rt.accessToken(cmd.Context(), profile)
	if err != nil {
		return nil, mintAuthError(rt.binaryName, profile.Name, err)
	}

	verbosef(cmd, verbose, "minting cert for %q via %s", deviceID, profile.Profile.Broker)

	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(profilePub)))
	response, err := rt.sshCertRequester(cmd.Context(), profile, accessToken, broker.SSHCertIssueRequest{
		DeviceID:           deviceID,
		PrincipalType:      broker.PrincipalTypeOperator,
		PublicKey:          publicKey,
		MaxLifetimeMinutes: certMaxLifetimeMinutes,
	})
	if err != nil {
		return nil, err
	}

	cert, err := parseIssuedCert(response.SSHCert)
	if err != nil {
		return nil, err
	}
	if err := store.PutCert(deviceID, cert); err != nil {
		return nil, fmt.Errorf("cache cert for %q: %w", deviceID, err)
	}

	verbosef(cmd, verbose, "minted cert for %q (serial %d, valid until %s)", deviceID, cert.Serial, time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339))

	return cert, nil
}

// ensureFreshCert reuses a cached cert when remaining validity exceeds
// cacheHitSafetyMargin and --refresh wasn't passed; otherwise mints a new
// one through the broker.
func ensureFreshCert(cmd *cobra.Command, rt runtime, store *certcache.Store, profile ResolvedProfile, deviceID string, certMaxLifetimeMinutes int32, refresh bool, verbose bool) error {
	if !refresh {
		cert, remaining, err := store.GetCert(deviceID)
		if err == nil && remaining >= cacheHitSafetyMargin {
			verbosef(cmd, verbose, "using cached cert for %q (serial %d, %s remaining)", deviceID, cert.Serial, remaining.Round(time.Second))
			return nil
		}
		if err != nil && !isCacheMiss(err) {
			return fmt.Errorf("read cached cert: %w", err)
		}
	}

	_, err := mintAndCache(cmd, rt, store, profile, deviceID, certMaxLifetimeMinutes, verbose)
	return err
}

// isCacheMiss reports cache states that warrant a fresh mint (no entry,
// expired, or key mismatch indicating cross-profile contamination).
func isCacheMiss(err error) bool {
	return errors.Is(err, certcache.ErrNotCached) ||
		errors.Is(err, certcache.ErrExpired) ||
		errors.Is(err, certcache.ErrCertKeyMismatch)
}
