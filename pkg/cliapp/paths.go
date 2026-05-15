package cliapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveBinaryName trims and falls back to DefaultBinaryName for empty.
func resolveBinaryName(binaryName string) string {
	binaryName = strings.TrimSpace(binaryName)
	if binaryName == "" {
		binaryName = DefaultBinaryName
	}
	return binaryName
}

// BinaryHomeSubdir returns ~/.<binary-name>/<subdir>.
func BinaryHomeSubdir(binaryName, subdir string) (string, error) {
	binaryName = resolveBinaryName(binaryName)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(homeDir, "."+binaryName, subdir), nil
}

// BinaryHomeFile returns ~/.<binary-name>/<file>.
func BinaryHomeFile(binaryName, file string) (string, error) {
	binaryName = resolveBinaryName(binaryName)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(homeDir, "."+binaryName, file), nil
}
