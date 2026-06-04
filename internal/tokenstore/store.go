// Package tokenstore persists per-profile OAuth token state for the CLI.
// Backends: Keychain (production default — refresh token in OS keychain
// with metadata in a sidecar entry) and File (encoded JSON on disk, used
// in tests and on platforms without a keychain).
package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Store is the per-profile token persistence abstraction. Two concrete
// backends implement it: Keychain (OS keyring) and File (JSON on disk). Load
// returns ErrNotFound when no state is stored for the profile.
type Store interface {
	Load(profile string) (State, error)
	Save(profile string, state State) error
	Delete(profile string) error
}

// StateVersion is the on-disk/keychain schema version; bump when State gains
// required fields. Older versions decode with ErrUnsupportedStateVersion.
const StateVersion = 1

var (
	ErrNotFound                = errors.New("token state not found")
	ErrUnsupportedStateVersion = errors.New("unsupported token state version")
	ErrProfileNameRequired     = errors.New("profile name is required")

	ErrTokenStateIDPIssuerRequired    = errors.New("idp issuer is required")
	ErrTokenStateClientIDRequired     = errors.New("idp client id is required")
	ErrTokenStateRefreshTokenRequired = errors.New("refresh token is required")
)

// State is the per-profile OAuth token bundle. AccessToken is optional
// (refreshable on demand); RefreshToken is the load-bearing credential —
// without it the engineer must re-login.
type State struct {
	Version               int    `json:"version"`
	IDPIssuer             string `json:"idp_issuer"`
	IDPClientID           string `json:"idp_client_id"`
	AccessToken           string `json:"access_token,omitempty"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at,omitempty"`
	Subject               string `json:"subject,omitempty"`
	Email                 string `json:"email,omitempty"`
	IssuedAt              int64  `json:"issued_at"`
}

func encodeState(state State) ([]byte, error) {
	if state.Version == 0 {
		state.Version = StateVersion
	}
	state = trimState(state)
	if err := validateState(state); err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func decodeState(data []byte) (State, error) {
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	if state.Version != StateVersion {
		return State{}, fmt.Errorf("%w: %d", ErrUnsupportedStateVersion, state.Version)
	}
	state = trimState(state)
	if err := validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

// trimState normalizes whitespace at both encode and decode boundaries.
// Idempotent for the production caller; the encode-side call guards against
// callers that bypass oauthlogin.
func trimState(state State) State {
	state.IDPIssuer = strings.TrimSpace(state.IDPIssuer)
	state.IDPClientID = strings.TrimSpace(state.IDPClientID)
	state.AccessToken = strings.TrimSpace(state.AccessToken)
	state.RefreshToken = strings.TrimSpace(state.RefreshToken)
	state.Subject = strings.TrimSpace(state.Subject)
	state.Email = strings.TrimSpace(state.Email)
	return state
}

func validateState(state State) error {
	if state.Version != StateVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedStateVersion, state.Version)
	}
	var errs []error
	if state.IDPIssuer == "" {
		errs = append(errs, ErrTokenStateIDPIssuerRequired)
	}
	if state.IDPClientID == "" {
		errs = append(errs, ErrTokenStateClientIDRequired)
	}
	if state.RefreshToken == "" {
		errs = append(errs, ErrTokenStateRefreshTokenRequired)
	}
	return errors.Join(errs...)
}

// requireProfileName trims and validates the caller-supplied profile name.
// oauthlogin calls tokenstore directly, so the trim/check stays here even
// though cliapp does its own.
func requireProfileName(profile string) (string, error) {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return "", ErrProfileNameRequired
	}
	return profile, nil
}
