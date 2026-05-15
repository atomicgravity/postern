package sshconf

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ephemeralMarkerPrefix is the sentinel comment that tags a stanza as
// ephemeral. Its presence inside the BEGIN/END markers lets the Upsert /
// Remove primitives stay ignorant of ephemerality.
const ephemeralMarkerPrefix = "# POSTERN-EPHEMERAL: "

// ErrEphemeralConcurrent is returned when UpsertEphemeral finds an existing
// ephemeral block for the same device whose pid is still live.
type ErrEphemeralConcurrent struct {
	Device string
	Pid    int
	Opened time.Time
	Port   int
}

func (e *ErrEphemeralConcurrent) Error() string {
	opened := e.Opened.Format(time.RFC3339)
	if e.Port > 0 {
		return fmt.Sprintf(
			"sshconf: tunnel for device %s already open at port %d (pid %d, opened %s); close it before opening a new one",
			e.Device, e.Port, e.Pid, opened)
	}
	return fmt.Sprintf(
		"sshconf: ephemeral tunnel stanza for device %s already present (pid %d, opened %s); close it before opening a new one",
		e.Device, e.Pid, opened)
}

// ErrEphemeralCollidesWithPersistent is returned when UpsertEphemeral finds
// a Postern-managed block at the requested device id that is NOT ephemeral
// — the tunnel path namespaces ephemeral blocks under "<device>.tunnel" so
// anything at that name must have been authored by the engineer.
var ErrEphemeralCollidesWithPersistent = errors.New(
	"sshconf: refusing to clobber a persistent (non-ephemeral) ssh.conf stanza")

// pidAlive reports whether pid maps to a live process. POSIX uses the
// zero-signal check; ESRCH / os.ErrProcessDone → dead, EPERM → treated as
// alive (running tunnel owned by another uid). Windows zero-signal is
// unreliable, hence the --reap escape hatch on `postern tunnel`.
var pidAlive = defaultPidAlive

func defaultPidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone) {
			return false
		}
		return true
	}
	return true
}

// UpsertEphemeral writes a Postern-managed Host block tagged with a
// "# POSTERN-EPHEMERAL: pid=<pid> opened=<rfc3339>" sentinel.
//
// Fails with *ErrEphemeralConcurrent if an ephemeral block for the same
// device already exists with a live pid, or
// ErrEphemeralCollidesWithPersistent if the existing block isn't ephemeral.
func (w *Writer) UpsertEphemeral(s Stanza, pid int, opened time.Time) error {
	if err := validateDevice(s.Device); err != nil {
		return err
	}
	if pid <= 0 {
		return errors.New("sshconf: UpsertEphemeral pid must be positive")
	}

	existing, err := w.readExisting()
	if err != nil {
		return err
	}

	begin := markerPrefix + s.Device
	end := markerSuffix + s.Device
	priorBlock, hasPrior := extractBlock(existing, begin, end)

	if hasPrior {
		prior, isEphemeral := parseEphemeralFields(priorBlock)
		if !isEphemeral {
			return fmt.Errorf("%w: device %q", ErrEphemeralCollidesWithPersistent, s.Device)
		}
		if pidAlive(prior.pid) {
			return &ErrEphemeralConcurrent{
				Device: s.Device,
				Pid:    prior.pid,
				Opened: prior.opened,
				Port:   s.Port,
			}
		}
	}

	rendered, err := renderStanza(s)
	if err != nil {
		return err
	}

	rendered = injectEphemeralSentinel(rendered, s.Device, pid, opened)

	updated := replaceOrAppendStanza(existing, s.Device, rendered)
	return w.write(updated)
}

// RemoveEphemeral drops the ephemeral Host block for device. No-op if the
// block is absent or persistent. There is no restore semantic — persistent
// stanzas at the un-suffixed name are never touched by the tunnel path.
func (w *Writer) RemoveEphemeral(device string) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	existing, err := w.readExisting()
	if err != nil {
		return err
	}

	begin := markerPrefix + device
	end := markerSuffix + device

	block, ok := extractBlock(existing, begin, end)
	if !ok {
		return nil
	}
	if _, isEphemeral := parseEphemeralFields(block); !isEphemeral {
		return nil
	}

	updated, removed := dropStanza(existing, device)
	if !removed {
		return nil
	}
	return w.write(updated)
}

// ReapStaleEphemeral drops every ephemeral block whose pid is no longer
// live, returning the reaped device ids in file order. Per-block failures
// are logged and skipped — propagating would brick every subsequent
// `postern tunnel` invocation, including --reap. Returned err covers only
// a file-read failure that prevents reading anything.
func (w *Writer) ReapStaleEphemeral() ([]string, error) {
	existing, err := w.readExisting()
	if err != nil {
		return nil, err
	}
	if existing == "" {
		return nil, nil
	}

	candidates := collectEphemeralCandidates(existing)
	if len(candidates) == 0 {
		return nil, nil
	}

	reaped := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if pidAlive(c.pid) {
			continue
		}
		if err := w.RemoveEphemeral(c.device); err != nil {
			slog.Default().Warn("sshconf: skipping stale ephemeral stanza that could not be reaped; manual edit may be required",
				"device", c.device,
				"path", w.path,
				"err", err,
			)
			continue
		}
		reaped = append(reaped, c.device)
	}
	return reaped, nil
}

// Has reports whether a Postern-managed Host block for device exists
// (persistent or ephemeral).
func (w *Writer) Has(device string) (bool, error) {
	if err := validateDevice(device); err != nil {
		return false, err
	}
	existing, err := w.readExisting()
	if err != nil {
		return false, err
	}
	begin := markerPrefix + device
	return indexLineStart(existing, begin) >= 0, nil
}

// LookupUser returns the User directive from the Postern-managed Host block
// for device, used by tunnel-open to inherit the engineer's add-host User
// choice into the suffixed "<device>.tunnel" stanza. Returns
// ("", false, nil) when the block or User directive is absent.
func (w *Writer) LookupUser(device string) (string, bool, error) {
	if err := validateDevice(device); err != nil {
		return "", false, err
	}

	existing, err := w.readExisting()
	if err != nil {
		return "", false, err
	}

	begin := markerPrefix + device
	end := markerSuffix + device
	block, ok := extractBlock(existing, begin, end)
	if !ok {
		return "", false, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// renderStanza always emits canonical "User " capitalization, so a
		// case-sensitive match is sufficient for our own stanzas.
		const prefix = "User "
		if strings.HasPrefix(line, prefix) {
			user := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if user == "" {
				return "", false, nil
			}
			return user, true, nil
		}
	}

	return "", false, nil
}

// ephemeralFields is the parsed POSTERN-EPHEMERAL sentinel.
type ephemeralFields struct {
	pid    int
	opened time.Time
}

// parseEphemeralFields scans block for the ephemeral sentinel. Returns
// (zero, false) for a persistent block.
func parseEphemeralFields(block string) (ephemeralFields, bool) {
	var out ephemeralFields
	found := false
	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ephemeralMarkerPrefix) {
			rest := strings.TrimPrefix(line, ephemeralMarkerPrefix)
			out = parseEphemeralKeyValues(rest)
			found = true
		}
	}
	return out, found
}

// parseEphemeralKeyValues extracts pid=<int> and opened=<rfc3339>. Missing
// or unparseable fields default to zero; pid<=0 is treated as dead by
// pidAlive.
func parseEphemeralKeyValues(payload string) ephemeralFields {
	var out ephemeralFields
	for _, tok := range strings.Fields(payload) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			switch k {
			case "pid":
				if n, err := strconv.Atoi(v); err == nil {
					out.pid = n
				}
			case "opened":
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					out.opened = t
				}
			}
		}
	}
	return out
}

type ephemeralCandidate struct {
	device string
	pid    int
}

// collectEphemeralCandidates walks the file's BEGIN markers and emits
// (device, pid) tuples for every ephemeral block in appearance order.
func collectEphemeralCandidates(existing string) []ephemeralCandidate {
	var out []ephemeralCandidate
	scanner := bufio.NewScanner(strings.NewReader(existing))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var (
		inBlock   bool
		curDevice string
		curPid    int
		curIsEph  bool
	)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, markerPrefix) {
			inBlock = true
			curDevice = strings.TrimPrefix(line, markerPrefix)
			curPid = 0
			curIsEph = false
			continue
		}
		if strings.HasPrefix(line, markerSuffix) {
			if inBlock && curIsEph {
				out = append(out, ephemeralCandidate{device: curDevice, pid: curPid})
			}
			inBlock = false
			curDevice = ""
			curPid = 0
			curIsEph = false
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(line, ephemeralMarkerPrefix) {
			curIsEph = true
			fields := parseEphemeralKeyValues(strings.TrimPrefix(line, ephemeralMarkerPrefix))
			curPid = fields.pid
		}
	}
	return out
}

// extractBlock returns the rendered text from BEGIN through END (inclusive)
// for the block whose markers exactly name begin / end. Returns
// ("", false) if absent or the END marker is missing.
func extractBlock(existing, begin, end string) (string, bool) {
	beginIdx := indexLineStart(existing, begin)
	if beginIdx < 0 {
		return "", false
	}
	endStart := indexLineStart(existing[beginIdx:], end)
	if endStart < 0 {
		return "", false
	}
	endAbs := beginIdx + endStart
	endLineEnd := indexOfNewline(existing, endAbs)
	return existing[beginIdx:endLineEnd], true
}

// injectEphemeralSentinel inserts the POSTERN-EPHEMERAL line right after the
// BEGIN marker. Keeping the sentinel inside BEGIN/END lets Upsert/Remove
// stay ignorant of ephemerality.
func injectEphemeralSentinel(rendered, device string, pid int, opened time.Time) string {
	beginLine := markerPrefix + device + "\n"
	idx := strings.Index(rendered, beginLine)
	if idx < 0 {
		// renderStanza always emits BEGIN first; defensive fallback
		// returns the input unchanged.
		return rendered
	}
	insertAt := idx + len(beginLine)

	sentinel := fmt.Sprintf("%spid=%d opened=%s\n", ephemeralMarkerPrefix, pid, opened.UTC().Format(time.RFC3339))

	return rendered[:insertAt] + sentinel + rendered[insertAt:]
}
