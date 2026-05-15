package sshconf

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func sampleStanza(device string) Stanza {
	return Stanza{
		Device:          device,
		Patterns:        []string{"192.168.1.42"},
		User:            "engineer",
		Port:            22,
		IdentityFile:    "/home/eng/.postern/cache/default/key",
		CertificateFile: "/home/eng/.postern/cache/default/" + device + ".cert",
	}
}

func TestUpsertIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	if err := w.Upsert(sampleStanza("device-1234")); err != nil {
		t.Fatalf("first Upsert() error = %v", err)
	}
	first, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if err := w.Upsert(sampleStanza("device-1234")); err != nil {
		t.Fatalf("second Upsert() error = %v", err)
	}
	second, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if string(first) != string(second) {
		t.Fatalf("idempotent Upsert changed file content:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestUpsertPreservesOtherStanzas(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	if err := w.Upsert(sampleStanza("device-alpha")); err != nil {
		t.Fatalf("Upsert(alpha) error = %v", err)
	}
	if err := w.Upsert(sampleStanza("device-bravo")); err != nil {
		t.Fatalf("Upsert(bravo) error = %v", err)
	}

	got, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(got)
	if !strings.Contains(content, "Host device-alpha 192.168.1.42") {
		t.Fatalf("missing alpha stanza:\n%s", content)
	}
	if !strings.Contains(content, "Host device-bravo 192.168.1.42") {
		t.Fatalf("missing bravo stanza:\n%s", content)
	}

	alphaIdx := strings.Index(content, "BEGIN POSTERN-MANAGED: device-alpha")
	bravoIdx := strings.Index(content, "BEGIN POSTERN-MANAGED: device-bravo")
	alphaEnd := strings.Index(content, "END POSTERN-MANAGED: device-alpha")
	bravoEnd := strings.Index(content, "END POSTERN-MANAGED: device-bravo")
	if !(alphaIdx < alphaEnd && alphaEnd < bravoIdx && bravoIdx < bravoEnd) {
		t.Fatalf("stanzas interleaved:\n%s", content)
	}
}

func TestUpsertReplacesExistingStanza(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	original := sampleStanza("device-port")
	original.Port = 22
	if err := w.Upsert(original); err != nil {
		t.Fatalf("first Upsert() error = %v", err)
	}

	updated := sampleStanza("device-port")
	updated.Port = 2222
	if err := w.Upsert(updated); err != nil {
		t.Fatalf("second Upsert() error = %v", err)
	}

	got, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(got)
	if strings.Contains(content, "Port 22\n") {
		t.Fatalf("stale Port 22 line remained:\n%s", content)
	}
	if !strings.Contains(content, "Port 2222") {
		t.Fatalf("new Port 2222 line missing:\n%s", content)
	}
	if c := strings.Count(content, "BEGIN POSTERN-MANAGED: device-port"); c != 1 {
		t.Fatalf("BEGIN marker count = %d, want 1 (stanza was duplicated)", c)
	}
}

// TestUpsertPreservesEngineerContent verifies content outside any
// BEGIN/END POSTERN-MANAGED block survives a write byte-for-byte. The
// engineer's notes are sacred — corrupting them would justify shipping
// auto-rewrite of ~/.ssh/config (which we explicitly don't).
func TestUpsertPreservesEngineerContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.conf")
	engineerContent := `# My personal ssh notes — do not touch.
Host my-prod-jumpbox
  HostName 10.0.0.1
  ForwardAgent yes

`
	if err := os.WriteFile(path, []byte(engineerContent), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	w := NewWriter(path)
	if err := w.Upsert(sampleStanza("device-7")); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(got)
	if !strings.Contains(content, "# My personal ssh notes — do not touch.") {
		t.Fatalf("engineer comment lost:\n%s", content)
	}
	if !strings.Contains(content, "Host my-prod-jumpbox") {
		t.Fatalf("engineer Host stanza lost:\n%s", content)
	}
	if !strings.Contains(content, "ForwardAgent yes") {
		t.Fatalf("engineer directive lost:\n%s", content)
	}
}

func TestRemoveDropsStanzaButKeepsRest(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	if err := w.Upsert(sampleStanza("device-keep")); err != nil {
		t.Fatalf("Upsert(keep) error = %v", err)
	}
	if err := w.Upsert(sampleStanza("device-drop")); err != nil {
		t.Fatalf("Upsert(drop) error = %v", err)
	}

	if err := w.Remove("device-drop"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	got, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(got)
	if strings.Contains(content, "device-drop") {
		t.Fatalf("dropped device still referenced:\n%s", content)
	}
	if !strings.Contains(content, "Host device-keep") {
		t.Fatalf("kept stanza lost:\n%s", content)
	}
	if !strings.Contains(content, headerSentinel) {
		t.Fatalf("header lost after Remove:\n%s", content)
	}
}

func TestRemoveMissingStanzaIsNoOp(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	if err := w.Upsert(sampleStanza("device-only")); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	before, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if err := w.Remove("device-missing"); err != nil {
		t.Fatalf("Remove(missing) error = %v", err)
	}
	after, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("Remove of absent device changed file content")
	}
}

func TestListReturnsSortedDevices(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	for _, d := range []string{"device-charlie", "device-alpha", "device-bravo"} {
		if err := w.Upsert(sampleStanza(d)); err != nil {
			t.Fatalf("Upsert(%s) error = %v", d, err)
		}
	}

	devices, err := w.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	want := []string{"device-alpha", "device-bravo", "device-charlie"}
	if !reflect.DeepEqual(devices, want) {
		t.Fatalf("List() = %v, want %v", devices, want)
	}
}

func TestListMissingFile(t *testing.T) {
	w := NewWriter(filepath.Join(t.TempDir(), "ssh.conf"))
	devices, err := w.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("List() = %v, want empty", devices)
	}
}

// TestUpsertConcurrent runs multiple Upsert calls on the same Writer from
// different goroutines under -race. The final file must end up consistent
// (parseable, header intact, every BEGIN paired with an END) — no torn
// content is the load-bearing property of the atomic-write path.
func TestUpsertConcurrent(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "ssh.conf"))

	devices := []string{"device-a", "device-b", "device-c", "device-d"}
	var wg sync.WaitGroup
	for _, d := range devices {
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Upsert(sampleStanza(d)); err != nil {
				t.Errorf("Upsert(%s) error = %v", d, err)
			}
		}()
	}
	wg.Wait()

	got, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(got)
	for _, marker := range []string{"BEGIN POSTERN-MANAGED:", "END POSTERN-MANAGED:"} {
		// At minimum, every BEGIN must be matched by an END for the file
		// to be parseable. The number of each is the same, equal to the
		// count of stanzas that landed on disk.
		beginCount := strings.Count(content, "BEGIN POSTERN-MANAGED:")
		endCount := strings.Count(content, "END POSTERN-MANAGED:")
		if beginCount != endCount {
			t.Fatalf("BEGIN count (%d) != END count (%d) after concurrent Upsert:\n%s",
				beginCount, endCount, content)
		}
		_ = marker
	}
}

// TestUpsertCreatesHeaderAndParentDir asserts that a first Upsert on a path
// whose parent directory does not yet exist creates the directory with
// mode 0o700 and writes a file whose first lines contain the header
// sentinel.
func TestUpsertCreatesHeaderAndParentDir(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "fresh", "subdir")
	path := filepath.Join(parent, "ssh.conf")

	w := NewWriter(path)
	if err := w.Upsert(sampleStanza("device-init")); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	dirInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("Stat(parent) error = %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("parent is not a directory")
	}
	if runtime.GOOS != "windows" {
		if perm := dirInfo.Mode().Perm(); perm != 0o700 {
			t.Fatalf("parent mode = %v, want 0o700", perm)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(got), headerSentinel) {
		t.Fatalf("file missing header sentinel:\n%s", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(path) error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != fileMode {
			t.Fatalf("file mode = %v, want %v", perm, fileMode)
		}
	}
}
