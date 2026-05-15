package cliapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryHomeSubdir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}

	cases := []struct {
		name       string
		binaryName string
		subdir     string
		want       string
	}{
		{"postern-cache", "postern", "cache", filepath.Join(home, ".postern", "cache")},
		{"wrapper-cache", "acme-access", "cache", filepath.Join(home, ".acme-access", "cache")},
		{"postern-ssh-conf", "postern", "ssh.conf", filepath.Join(home, ".postern", "ssh.conf")},
		{"empty-binary-falls-back", "", "cache", filepath.Join(home, "."+DefaultBinaryName, "cache")},
		{"whitespace-trimmed", "  postern  ", "cache", filepath.Join(home, ".postern", "cache")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BinaryHomeSubdir(tc.binaryName, tc.subdir)
			if err != nil {
				t.Fatalf("BinaryHomeSubdir() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("BinaryHomeSubdir(%q, %q) = %q, want %q", tc.binaryName, tc.subdir, got, tc.want)
			}
		})
	}
}

// TestBinaryHomeFileConsistentWithSubdir verifies DefaultConfigPath and
// defaultCacheBaseDir continue to resolve to the same locations they did
// before the path-derivation refactor, so existing engineer caches and
// config files keep working.
func TestBinaryHomeFileConsistentWithSubdir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}

	gotConfig, err := DefaultConfigPath("postern")
	if err != nil {
		t.Fatalf("DefaultConfigPath() error = %v", err)
	}
	wantConfig := filepath.Join(home, ".postern", "config.yaml")
	if gotConfig != wantConfig {
		t.Fatalf("DefaultConfigPath() = %q, want %q", gotConfig, wantConfig)
	}

	gotCache, err := defaultCacheBaseDir("postern")
	if err != nil {
		t.Fatalf("defaultCacheBaseDir() error = %v", err)
	}
	wantCache := filepath.Join(home, ".postern", "cache")
	if gotCache != wantCache {
		t.Fatalf("defaultCacheBaseDir() = %q, want %q", gotCache, wantCache)
	}
}
