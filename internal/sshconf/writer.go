// Package sshconf manages the Postern-owned ssh-config file the engineer
// includes from ~/.ssh/config. Stanzas bracketed by BEGIN/END POSTERN-MANAGED
// markers are owned by Postern (idempotently upserted by Upsert / Remove);
// any other content in the file is engineer-owned and preserved verbatim.
//
// Writes go through internal/atomicfile so a concurrent reader never sees a
// half-written file.
package sshconf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/atomicgravity/postern/internal/atomicfile"
)

// Stanza is the data Upsert renders into the ssh-config file. Patterns are
// extra Host-match tokens on the Host line (typically the device's LAN IP).
// HostName is the address ssh actually connects to when Device isn't DNS-
// resolvable. Port = 0 omits the Port directive.
type Stanza struct {
	Device          string
	Patterns        []string
	HostName        string
	User            string
	Port            int
	IdentityFile    string
	CertificateFile string
}

// Writer manages a single Postern-owned ssh-config file.
type Writer struct {
	path string
}

// NewWriter returns a Writer bound to path. The file is created on first
// Upsert with mode 0o644 (parent dir 0o700).
func NewWriter(path string) *Writer {
	return &Writer{path: path}
}

// Path is the absolute file path the writer manages.
func (w *Writer) Path() string {
	return w.path
}

const (
	markerPrefix     = "# BEGIN POSTERN-MANAGED: "
	markerSuffix     = "# END POSTERN-MANAGED: "
	headerSentinel   = "# Postern-managed ssh-config file."
	directoryMode    = 0o700
	fileMode         = 0o644
	stanzaIndent     = "  "
	defaultSSHHeader = `# Postern-managed ssh-config file.
# To enable: add ` + "`Include " + tildePostern + "`" + ` to ~/.ssh/config.
# Generated stanzas are bracketed by BEGIN/END POSTERN-MANAGED markers;
# edits outside the markers are preserved.
`
	tildePostern = "~/.postern/ssh.conf"
)

// Upsert adds or replaces the Postern-managed stanza for s.Device.
// Idempotent: repeated calls with the same stanza produce byte-identical
// content.
func (w *Writer) Upsert(s Stanza) error {
	if err := validateDevice(s.Device); err != nil {
		return err
	}

	existing, err := w.readExisting()
	if err != nil {
		return err
	}

	rendered, err := renderStanza(s)
	if err != nil {
		return err
	}

	updated := replaceOrAppendStanza(existing, s.Device, rendered)

	return w.write(updated)
}

// Remove drops the Postern-managed stanza for device. No-op if absent.
func (w *Writer) Remove(device string) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	existing, err := w.readExisting()
	if err != nil {
		return err
	}

	updated, removed := dropStanza(existing, device)
	if !removed {
		return nil
	}

	return w.write(updated)
}

// List returns the device ids of Postern-managed stanzas, sorted. Missing
// file returns an empty result.
func (w *Writer) List() ([]string, error) {
	existing, err := w.readExisting()
	if err != nil {
		return nil, err
	}
	devices := collectDevices(existing)
	slices.Sort(devices)
	return devices, nil
}

func (w *Writer) readExisting() (string, error) {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("sshconf: read %q: %w", w.path, err)
	}
	return string(data), nil
}

func (w *Writer) write(content string) error {
	if err := os.MkdirAll(filepath.Dir(w.path), directoryMode); err != nil {
		return fmt.Errorf("sshconf: create parent dir: %w", err)
	}
	if err := os.Chmod(filepath.Dir(w.path), directoryMode); err != nil {
		return fmt.Errorf("sshconf: chmod parent dir: %w", err)
	}

	if !strings.Contains(content, headerSentinel) {
		content = defaultSSHHeader + "\n" + content
	}

	return atomicfile.WriteFile(w.path, []byte(content), fileMode)
}

// renderStanza is the canonical text shape. Directive order is fixed so
// re-renders are byte-identical.
func renderStanza(s Stanza) (string, error) {
	if strings.TrimSpace(s.User) == "" {
		return "", errors.New("sshconf: stanza User is required")
	}
	if strings.TrimSpace(s.IdentityFile) == "" {
		return "", errors.New("sshconf: stanza IdentityFile is required")
	}
	if strings.TrimSpace(s.CertificateFile) == "" {
		return "", errors.New("sshconf: stanza CertificateFile is required")
	}

	hostLine := s.Device
	for _, pattern := range s.Patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		hostLine += " " + pattern
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s%s\n", markerPrefix, s.Device)
	fmt.Fprintf(&builder, "Host %s\n", hostLine)
	if hostname := strings.TrimSpace(s.HostName); hostname != "" {
		fmt.Fprintf(&builder, "%sHostName %s\n", stanzaIndent, hostname)
	}
	fmt.Fprintf(&builder, "%sUser %s\n", stanzaIndent, s.User)
	if s.Port > 0 {
		fmt.Fprintf(&builder, "%sPort %d\n", stanzaIndent, s.Port)
	}
	fmt.Fprintf(&builder, "%sIdentityFile %s\n", stanzaIndent, s.IdentityFile)
	fmt.Fprintf(&builder, "%sCertificateFile %s\n", stanzaIndent, s.CertificateFile)
	fmt.Fprintf(&builder, "%sIdentitiesOnly yes\n", stanzaIndent)
	fmt.Fprintf(&builder, "%sPreferredAuthentications publickey\n", stanzaIndent)
	fmt.Fprintf(&builder, "%sPasswordAuthentication no\n", stanzaIndent)
	fmt.Fprintf(&builder, "%sKbdInteractiveAuthentication no\n", stanzaIndent)
	fmt.Fprintf(&builder, "%sForwardAgent yes\n", stanzaIndent)
	fmt.Fprintf(&builder, "%s%s\n", markerSuffix, s.Device)
	return builder.String(), nil
}

// replaceOrAppendStanza replaces the stanza for device (BEGIN through END)
// or appends with a blank-line separator. A BEGIN without matching END
// (malformed file) falls back to append, leaving the rest of the file alone.
func replaceOrAppendStanza(existing, device, newStanza string) string {
	begin := markerPrefix + device
	end := markerSuffix + device

	beginIdx := indexLineStart(existing, begin)
	if beginIdx < 0 {
		return appendStanza(existing, newStanza)
	}

	endStart := indexLineStart(existing[beginIdx:], end)
	if endStart < 0 {
		return appendStanza(existing, newStanza)
	}
	endAbs := beginIdx + endStart
	endLineEnd := indexOfNewline(existing, endAbs)

	before := trimTrailingBlank(existing[:beginIdx])
	after := existing[endLineEnd:]
	after = trimLeadingBlank(after)

	var result strings.Builder
	result.WriteString(before)
	if before != "" && !strings.HasSuffix(before, "\n") {
		result.WriteString("\n")
	}
	if before != "" {
		result.WriteString("\n")
	}
	result.WriteString(newStanza)
	if after != "" {
		result.WriteString("\n")
		result.WriteString(after)
	}
	return result.String()
}

// appendStanza adds stanza to the end of existing, separated by a blank line.
func appendStanza(existing, stanza string) string {
	if existing == "" {
		return stanza
	}
	trimmed := strings.TrimRight(existing, "\n")
	return trimmed + "\n\n" + stanza
}

// dropStanza removes the stanza for device, if present. Returns the new
// content and whether a stanza was actually removed.
func dropStanza(existing, device string) (string, bool) {
	begin := markerPrefix + device
	end := markerSuffix + device

	beginIdx := indexLineStart(existing, begin)
	if beginIdx < 0 {
		return existing, false
	}

	endStart := indexLineStart(existing[beginIdx:], end)
	if endStart < 0 {
		return existing, false
	}
	endAbs := beginIdx + endStart
	endLineEnd := indexOfNewline(existing, endAbs)

	before := trimTrailingBlank(existing[:beginIdx])
	after := trimLeadingBlank(existing[endLineEnd:])

	if before == "" {
		return after, true
	}
	if after == "" {
		if !strings.HasSuffix(before, "\n") {
			before += "\n"
		}
		return before, true
	}
	if !strings.HasSuffix(before, "\n") {
		before += "\n"
	}
	return before + "\n" + after, true
}

func collectDevices(existing string) []string {
	var devices []string
	scanner := bufio.NewScanner(strings.NewReader(existing))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, markerPrefix) {
			devices = append(devices, strings.TrimPrefix(line, markerPrefix))
		}
	}
	return devices
}

// indexLineStart returns the byte offset of needle when it occupies a full
// line. The trailing-boundary check is what stops "device-1" from matching
// "device-12".
func indexLineStart(s, needle string) int {
	idx := 0
	for {
		off := strings.Index(s[idx:], needle)
		if off < 0 {
			return -1
		}
		abs := idx + off
		atLineStart := abs == 0 || s[abs-1] == '\n'
		end := abs + len(needle)
		atLineEnd := end == len(s) || s[end] == '\n'
		if atLineStart && atLineEnd {
			return abs
		}
		idx = abs + 1
	}
}

func indexOfNewline(s string, from int) int {
	nl := strings.Index(s[from:], "\n")
	if nl < 0 {
		return len(s)
	}
	return from + nl + 1
}

func trimTrailingBlank(s string) string {
	for strings.HasSuffix(s, "\n\n") {
		s = s[:len(s)-1]
	}
	return s
}

func trimLeadingBlank(s string) string {
	for strings.HasPrefix(s, "\n") {
		s = s[1:]
	}
	return s
}

func validateDevice(device string) error {
	if strings.TrimSpace(device) == "" {
		return errors.New("sshconf: device is required")
	}
	if strings.ContainsAny(device, "\n\r") {
		return fmt.Errorf("sshconf: device %q contains newline", device)
	}
	return nil
}
