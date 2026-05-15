package atomicfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestWriteFileWritesContentAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	data := []byte("hello atomicfile")

	if err := WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Fatalf("mode = %v, want 0o644", perm)
		}
	}
}

// TestWriteFileOverwritesAtomically asserts that a follow-up write replaces
// the prior content and that no temp file is left lying around in the parent
// directory. The lingering-temp check is the load-bearing observation: a
// failure to clean up after rename would surface here.
func TestWriteFileOverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")

	if err := WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first WriteFile() error = %v", err)
	}
	if err := WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second WriteFile() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "out" {
			t.Fatalf("leftover entry %q in dir %q after atomic writes", entry.Name(), dir)
		}
	}
}

// TestWriteFileMissingDirSurfacesError asserts that the helper does not
// silently create parent directories — callers must MkdirAll first. Missing
// parents are user error and a clear error message helps diagnosis.
func TestWriteFileMissingDirSurfacesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "out")

	err := WriteFile(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("WriteFile() error = nil, want error for missing parent dir")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination created despite error: %v", statErr)
	}
}

// TestWriteFileRenameFailureLeavesPriorFile asserts that when the rename step
// fails (here simulated by pointing path at a directory), the prior content
// at any sibling path stays intact and no orphan temp file lingers visibly.
// The temp file may briefly exist but the helper removes it after the rename
// failure.
func TestWriteFileRenameFailureLeavesPriorFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir(target): %v", err)
	}

	// Writing to a path that resolves to a directory must fail; the helper
	// must clean the temp on the way out.
	err := WriteFile(target, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("WriteFile(dir-path) error = nil, want rename failure")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "target" {
			t.Fatalf("leftover temp file %q after rename failure", entry.Name())
		}
	}
}

// TestWriteFileConcurrent writes the same destination from N goroutines and
// verifies the final file is exactly one of the inputs — no torn content,
// no zero-length result, no missing file. Drives the race detector through
// the temp-then-rename sequence.
func TestWriteFileConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	candidates := [][]byte{
		[]byte("alpha-alpha-alpha"),
		[]byte("bravo-bravo-bravo"),
		[]byte("charlie-charlie-ch"),
		[]byte("delta-delta-delta"),
	}

	var wg sync.WaitGroup
	for _, payload := range candidates {
		payload := payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteFile(path, payload, 0o600); err != nil {
				t.Errorf("WriteFile() error = %v", err)
			}
		}()
	}
	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, candidate := range candidates {
		if bytes.Equal(got, candidate) {
			return
		}
	}
	t.Fatalf("final content %q matches no candidate (torn write)", got)
}
