package cliapp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/atomicgravity/postern/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

// Config is the CLI's on-disk YAML shape: a map of profile names to
// Profile values. The unwrapped CLI selects "default" unless --profile or
// $<BINARY>_PROFILE is set.
type Config struct {
	Profiles map[string]Profile
}

// DefaultConfigPath returns the conventional path for binaryName (e.g.
// ~/.postern/config.yaml).
func DefaultConfigPath(binaryName string) (string, error) {
	return BinaryHomeFile(binaryName, "config.yaml")
}

// LoadConfigFile decodes path's YAML into a Config.
func LoadConfigFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	return LoadConfig(file)
}

// SaveConfigFile writes config to path atomically (mode 0o600, parent
// 0o700) so a kill mid-encode can't leave a partial file.
func SaveConfigFile(path string, config Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := SaveConfig(&buf, config); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, buf.Bytes(), 0o600)
}

// LoadConfig decodes YAML profiles from reader. Whitespace is normalized
// at the decode boundary.
func LoadConfig(reader io.Reader) (Config, error) {
	profiles := make(map[string]Profile)
	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&profiles); err != nil {
		return Config{}, err
	}

	for name, profile := range profiles {
		profiles[name] = trimProfile(profile)
	}
	return Config{Profiles: profiles}, nil
}

func trimProfile(profile Profile) Profile {
	profile.Broker = strings.TrimSpace(profile.Broker)
	profile.IDP.Issuer = strings.TrimSpace(profile.IDP.Issuer)
	profile.IDP.ClientID = strings.TrimSpace(profile.IDP.ClientID)
	profile.IDP.Audience = strings.TrimSpace(profile.IDP.Audience)
	profile.IDP.AudienceParam = strings.TrimSpace(profile.IDP.AudienceParam)
	profile.IDP.Scopes = strings.TrimSpace(profile.IDP.Scopes)
	profile.DefaultSSHUser = strings.TrimSpace(profile.DefaultSSHUser)
	profile.TokenStore = strings.TrimSpace(profile.TokenStore)
	return profile
}

// SaveConfig encodes config as YAML to writer.
func SaveConfig(writer io.Writer, config Config) error {
	profiles := config.Profiles
	if profiles == nil {
		profiles = map[string]Profile{}
	}

	encoder := yaml.NewEncoder(writer)
	if err := encoder.Encode(profiles); err != nil {
		_ = encoder.Close()
		return err
	}
	return encoder.Close()
}
