package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	keyring "github.com/zalando/go-keyring"
)

const (
	defaultServiceName    = "postern"
	accessTokenKeySuffix  = "access-token"
	refreshTokenKeySuffix = "refresh-token"
	metadataKeySuffix     = "metadata"
)

type keyringClient interface {
	Get(service string, user string) (string, error)
	Set(service string, user string, password string) error
	Delete(service string, user string) error
}

type systemKeyringClient struct{}

func (systemKeyringClient) Get(service string, user string) (string, error) {
	return keyring.Get(service, user)
}

func (systemKeyringClient) Set(service string, user string, password string) error {
	return keyring.Set(service, user, password)
}

func (systemKeyringClient) Delete(service string, user string) error {
	return keyring.Delete(service, user)
}

// Keychain is the OS-keyring tokenstore backend. Three entries per profile:
// refresh-token, access-token, and a JSON metadata sidecar
// (issuer / client / expiry / identity).
type Keychain struct {
	service string
	client  keyringClient
}

var _ Store = Keychain{}

type keychainMetadata struct {
	Version               int    `json:"version"`
	IDPIssuer             string `json:"idp_issuer"`
	IDPClientID           string `json:"idp_client_id"`
	RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at,omitempty"`
	Subject               string `json:"subject,omitempty"`
	Email                 string `json:"email,omitempty"`
	IssuedAt              int64  `json:"issued_at"`
}

// NewKeychain constructs a Keychain. service namespaces the keyring entries
// (unwrapped CLI uses "postern"; wrappers pass their own binary name).
func NewKeychain(service string) Keychain {
	return newKeychain(service, systemKeyringClient{})
}

func newKeychain(service string, client keyringClient) Keychain {
	service = strings.TrimSpace(service)
	if service == "" {
		service = defaultServiceName
	}
	return Keychain{service: service, client: client}
}

// Load reassembles State from the three keyring entries. ErrNotFound when
// metadata or refresh-token is missing; an absent access-token entry is fine.
func (s Keychain) Load(profile string) (State, error) {
	profile, err := requireProfileName(profile)
	if err != nil {
		return State{}, err
	}

	metadataData, err := s.client.Get(s.service, key(profile, metadataKeySuffix))
	if err != nil {
		return State{}, keyringLoadError(err)
	}

	refreshToken, err := s.client.Get(s.service, key(profile, refreshTokenKeySuffix))
	if err != nil {
		return State{}, keyringLoadError(err)
	}

	accessToken, err := s.client.Get(s.service, key(profile, accessTokenKeySuffix))
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return State{}, err
	}

	var metadata keychainMetadata
	if err := json.Unmarshal([]byte(metadataData), &metadata); err != nil {
		return State{}, fmt.Errorf("decode token metadata: %w", err)
	}

	state := trimState(State{
		Version:               metadata.Version,
		IDPIssuer:             metadata.IDPIssuer,
		IDPClientID:           metadata.IDPClientID,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: metadata.RefreshTokenExpiresAt,
		Subject:               metadata.Subject,
		Email:                 metadata.Email,
		IssuedAt:              metadata.IssuedAt,
	})
	if state.Version == 0 {
		state.Version = StateVersion
	}

	if err := validateState(state); err != nil {
		return State{}, fmt.Errorf("decode token metadata: %w", err)
	}

	return state, nil
}

// Save writes the three keyring entries. An empty AccessToken deletes the
// cached entry rather than writing a placeholder.
func (s Keychain) Save(profile string, state State) error {
	profile, err := requireProfileName(profile)
	if err != nil {
		return err
	}
	if state.Version == 0 {
		state.Version = StateVersion
	}
	if err := validateState(state); err != nil {
		return err
	}

	metadata := keychainMetadata{
		Version:               state.Version,
		IDPIssuer:             state.IDPIssuer,
		IDPClientID:           state.IDPClientID,
		RefreshTokenExpiresAt: state.RefreshTokenExpiresAt,
		Subject:               state.Subject,
		Email:                 state.Email,
		IssuedAt:              state.IssuedAt,
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	if err := s.client.Set(s.service, key(profile, refreshTokenKeySuffix), state.RefreshToken); err != nil {
		return err
	}
	if state.AccessToken != "" {
		if err := s.client.Set(s.service, key(profile, accessTokenKeySuffix), state.AccessToken); err != nil {
			return err
		}
	} else if err := s.client.Delete(s.service, key(profile, accessTokenKeySuffix)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return s.client.Set(s.service, key(profile, metadataKeySuffix), string(metadataData))
}

// Delete removes the three keyring entries. Per-entry not-found is ignored.
func (s Keychain) Delete(profile string) error {
	profile, err := requireProfileName(profile)
	if err != nil {
		return err
	}

	var deleteErrors []error
	for _, suffix := range []string{accessTokenKeySuffix, refreshTokenKeySuffix, metadataKeySuffix} {
		if err := s.client.Delete(s.service, key(profile, suffix)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			deleteErrors = append(deleteErrors, err)
		}
	}
	return errors.Join(deleteErrors...)
}

func keyringLoadError(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func key(profile string, suffix string) string {
	return profile + ":" + suffix
}
