// Package atomicfile writes files atomically (write-temp-then-rename) so a
// concurrent reader sees either the previous content or the new content,
// never a half-written one. Parent directories must already exist.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes data to path atomically with the given mode via rename
// from a temp file in filepath.Dir(path).
func WriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(dir, ".atomicfile-*")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp file in %q: %w", dir, err)
	}
	tempPath := tempFile.Name()
	cleanup := func() { _ = os.Remove(tempPath) }

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		cleanup()
		return fmt.Errorf("atomicfile: write temp file: %w", err)
	}
	if err := tempFile.Chmod(mode); err != nil {
		tempFile.Close()
		cleanup()
		return fmt.Errorf("atomicfile: chmod temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return fmt.Errorf("atomicfile: close temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		cleanup()
		return fmt.Errorf("atomicfile: rename %q -> %q: %w", tempPath, path, err)
	}
	return nil
}

// WriteFileExclusive writes data to path with exactly-once create semantics
// via os.Link from a temp file. Returns an error matching os.ErrExist if
// another caller won the race.
func WriteFileExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	tempFile, err := os.CreateTemp(dir, ".atomicfile-*")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp file in %q: %w", dir, err)
	}
	tempPath := tempFile.Name()
	cleanup := func() { _ = os.Remove(tempPath) }

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		cleanup()
		return fmt.Errorf("atomicfile: write temp file: %w", err)
	}
	if err := tempFile.Chmod(mode); err != nil {
		tempFile.Close()
		cleanup()
		return fmt.Errorf("atomicfile: chmod temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return fmt.Errorf("atomicfile: close temp file: %w", err)
	}
	if err := os.Link(tempPath, path); err != nil {
		cleanup()
		return err
	}
	cleanup()
	return nil
}
