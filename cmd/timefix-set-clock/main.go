// Command timefix-set-clock is the privileged setter for the timefix path.
// Input surface is a single positional integer (unix seconds) → one
// clock_settime syscall + a best-effort RTC_SET_TIME ioctl. No stdin, no
// env-derived input, no flags. The minimal surface is what makes carrying
// CAP_SYS_TIME safe: a verifier bug bounds to "set clock to attacker's
// value," not root escalation. Widening the input surface requires
// explicit architectural sign-off.
//
// Exit codes (a stable wire contract):
//
//	0 success (kernel clock set; RTC may or may not have been written)
//	1 wrong arg count
//	2 non-integer or out-of-range timestamp
//	3 clock_settime syscall failure
//
// RTC ioctl failure is intentionally exit 0: the kernel clock is the
// load-bearing action and is already advanced. RTC-less devices re-drift
// on reboot and re-recover on the next timefix.
//
// Build tag `no_rtc` compiles in a silent no-op setRTC for images where
// the RTC ioctl path is off the table (no /dev/rtc0, xattr-stripped FS).
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// Sanity-range bounds for the timestamp. Identical to the verifier's bound
// so the chain rejects garbage consistently; the setter checks this
// independently so its input validation does not depend on an unprivileged
// predecessor.
var (
	tsMinBound = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	tsMaxBound = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// Exit codes are operator-visible; do not reorder.
const (
	exitSuccess          = 0
	exitWrongArgCount    = 1
	exitBadTimestamp     = 2
	exitClockSettimeFail = 3
)

// deps groups syscall seams for test substitution.
type deps struct {
	Args   []string
	Stderr io.Writer

	// SetKernelClock advances CLOCK_REALTIME (wraps unix.ClockSettime).
	SetKernelClock func(unixSec int64) error

	// SetRTC writes the time to /dev/rtc0 via RTC_SET_TIME ioctl.
	// Failures are fail-tolerant (see package doc).
	SetRTC func(t time.Time) error
}

func main() {
	d := deps{
		Args:           os.Args,
		Stderr:         os.Stderr,
		SetKernelClock: setKernelClock,
		SetRTC:         setRTC,
	}
	os.Exit(run(d))
}

// run is the testable entrypoint, returning an exit code. clock_settime
// failure short-circuits before the RTC write — neither clock can be
// trusted, continuing is meaningless.
func run(d deps) int {
	if len(d.Args) != 2 {
		fmt.Fprintf(d.Stderr, "timefix-set-clock: expected exactly one positional integer arg, got %d\n", len(d.Args)-1)
		return exitWrongArgCount
	}

	ts, err := strconv.ParseInt(d.Args[1], 10, 64)
	if err != nil {
		fmt.Fprintf(d.Stderr, "timefix-set-clock: parse timestamp %q: %v\n", d.Args[1], err)
		return exitBadTimestamp
	}

	target := time.Unix(ts, 0).UTC()
	if target.Before(tsMinBound) || !target.Before(tsMaxBound) {
		fmt.Fprintf(d.Stderr, "timefix-set-clock: timestamp %d (%s) out of [2024-01-01, 2099-01-01) bound\n", ts, target.Format(time.RFC3339))
		return exitBadTimestamp
	}

	if err := d.SetKernelClock(ts); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-set-clock: clock_settime: %v\n", err)
		return exitClockSettimeFail
	}

	// RTC failure is fail-tolerant: hiding the kernel-clock success
	// behind an RTC failure makes the engineer's SSH session close
	// non-zero for no benefit — the kernel clock is already advanced.
	if err := d.SetRTC(target); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-set-clock: RTC update failed (kernel clock was set): %v\n", err)
	}
	return exitSuccess
}
