package cliapp

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRemoveHostDropsManagedStanza(t *testing.T) {
	f := newAddHostFixture(t)

	if err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42"); err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}
	f.stdout.Reset()

	if err := execute(context.Background(), f.root(),
		"remove-host", "device-1234"); err != nil {
		t.Fatalf("Run(remove-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-1234") {
		t.Fatalf("ssh.conf still contains stanza after remove:\n%s", data)
	}

	stdout := f.stdout.String()
	if !strings.Contains(stdout, "Removed device-1234") {
		t.Fatalf("stdout missing removal message:\n%s", stdout)
	}
}

func TestRemoveHostMissingDeviceIsNoOp(t *testing.T) {
	f := newAddHostFixture(t)

	if err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42"); err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}
	pre, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	f.stdout.Reset()

	if err := execute(context.Background(), f.root(),
		"remove-host", "device-never-added"); err != nil {
		t.Fatalf("Run(remove-host) error = %v", err)
	}

	post, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	if string(pre) != string(post) {
		t.Fatalf("ssh.conf changed by no-op remove:\nbefore:\n%s\nafter:\n%s", pre, post)
	}
	if !strings.Contains(f.stdout.String(), "nothing to remove") {
		t.Fatalf("stdout missing no-op message:\n%s", f.stdout.String())
	}
}

func TestRemoveHostPreservesOtherStanzas(t *testing.T) {
	f := newAddHostFixture(t)

	if err := execute(context.Background(), f.root(),
		"add-host", "device-A", "--ip", "10.0.0.1"); err != nil {
		t.Fatalf("Run(add-host A) error = %v", err)
	}
	if err := execute(context.Background(), f.root(),
		"add-host", "device-B", "--ip", "10.0.0.2"); err != nil {
		t.Fatalf("Run(add-host B) error = %v", err)
	}
	f.stdout.Reset()

	if err := execute(context.Background(), f.root(),
		"remove-host", "device-A"); err != nil {
		t.Fatalf("Run(remove-host A) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	content := string(data)
	if strings.Contains(content, "BEGIN POSTERN-MANAGED: device-A") {
		t.Fatalf("ssh.conf still contains device-A stanza:\n%s", content)
	}
	if !strings.Contains(content, "BEGIN POSTERN-MANAGED: device-B") {
		t.Fatalf("ssh.conf no longer contains device-B stanza:\n%s", content)
	}
}

func TestRemoveHostRejectsInvalidDeviceID(t *testing.T) {
	f := newAddHostFixture(t)

	cases := []struct {
		name      string
		device    string
		wantInErr string
	}{
		{"path-traversal", "../escape", "path separators"},
		{"forward-slash", "a/b", "path separators"},
		{"dotdot", "..", "'..' is not allowed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.stdout.Reset()
			err := execute(context.Background(), f.root(),
				"remove-host", tc.device)
			if err == nil {
				t.Fatalf("Run(remove-host %q) returned nil error", tc.device)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("Run(remove-host %q) error = %v, want substring %q",
					tc.device, err, tc.wantInErr)
			}
		})
	}
}
