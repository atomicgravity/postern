package tokenstore

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/atomicgravity/postern/internal/atomicfile"
)

// File is the on-disk tokenstore backend. Each profile's State lives in a
// separate JSON file under dir at 0o600 (parent dir 0o700) so other local
// users can't read the cached refresh token.
type File struct {
	dir string
}

// NewFile constructs a File-backed tokenstore rooted at dir.
func NewFile(dir string) File {
	return File{dir: dir}
}

// Load reads the per-profile JSON file. A missing file surfaces as
// ErrNotFound.
func (s File) Load(profile string) (State, error) {
	path, err := s.path(profile)
	if err != nil {
		return State{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, ErrNotFound
		}
		return State{}, err
	}

	state, err := decodeState(data)
	if err != nil {
		return State{}, fmt.Errorf("decode token state %q: %w", path, err)
	}
	return state, nil
}

// Save encodes state and writes the per-profile file with mode 0o600 (parent
// 0o700) via atomicfile so a process killed mid-write never leaves a partial.
func (s File) Save(profile string, state State) error {
	path, err := s.path(profile)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}

	data, err := encodeState(state)
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(path, data, 0o600)
}

// Delete removes the per-profile file; a missing file is not an error.
func (s File) Delete(profile string) error {
	path, err := s.path(profile)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s File) path(profile string) (string, error) {
	profile, err := requireProfileName(profile)
	if err != nil {
		return "", err
	}
	dir := strings.TrimSpace(s.dir)
	if dir == "" {
		return "", errors.New("token state directory is required")
	}
	return filepath.Join(dir, "state-"+url.PathEscape(profile)+".json"), nil
}
