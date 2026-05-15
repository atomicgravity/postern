//go:build !timefix_test_path

package main

// caPubPath is compile-time constant: the env-var override is build-tag
// gated and never compiled into production, so a hostile sshd env-passthrough
// cannot redirect verification to an attacker-controlled CA pubkey.
const caPubPath = "/etc/ssh/postern_ca.pub"

func resolveCAPubPath() string {
	return caPubPath
}
