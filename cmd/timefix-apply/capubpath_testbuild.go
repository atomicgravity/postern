//go:build timefix_test_path

package main

import "os"

// Test-only CA-pubkey path resolution. Compiled only with -tags
// timefix_test_path so production binaries never carry os.Getenv on this
// path. Filename is *_testbuild.go (not *_test.go) so Go's test tooling
// doesn't special-case it — the build tag is what gates inclusion.
func resolveCAPubPath() string {
	if p := os.Getenv("POSTERN_TIMEFIX_CA_PUB"); p != "" {
		return p
	}
	return "/etc/ssh/postern_ca.pub"
}
