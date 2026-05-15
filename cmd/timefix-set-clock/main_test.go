package main

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stubDeps returns a deps wired with no-op syscall stubs, a captured
// stderr buffer, and the given argv. Tests that exercise a specific
// failure mode swap one of the syscall seams after calling.
func stubDeps(args []string) (deps, *bytes.Buffer, *capturedSyscalls) {
	captured := &capturedSyscalls{}
	stderr := &bytes.Buffer{}
	d := deps{
		Args:   append([]string{"timefix-set-clock"}, args...),
		Stderr: stderr,
		SetKernelClock: func(unixSec int64) error {
			captured.kernelCalled = true
			captured.kernelArg = unixSec
			return captured.kernelErr
		},
		SetRTC: func(t time.Time) error {
			captured.rtcCalled = true
			captured.rtcArg = t
			return captured.rtcErr
		},
	}
	return d, stderr, captured
}

type capturedSyscalls struct {
	kernelCalled bool
	kernelArg    int64
	kernelErr    error

	rtcCalled bool
	rtcArg    time.Time
	rtcErr    error
}

// TestArgCountTable exercises invariant O: argv MUST contain exactly the
// program name + one positional integer arg. Zero positional args,
// multiple positional args, and flag-shaped args all map to
// exitWrongArgCount — the setter does not accept flags, so a `-v` or
// `--help` reads as "wrong arg count" before any parse attempt.
func TestArgCountTable(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no args", []string{}, exitWrongArgCount},
		{"two args", []string{"1747000000", "extra"}, exitWrongArgCount},
		{"three args", []string{"1747000000", "extra", "more"}, exitWrongArgCount},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, _, captured := stubDeps(tc.args)
			got := run(d)
			if got != tc.want {
				t.Fatalf("run exit = %d, want %d", got, tc.want)
			}
			if captured.kernelCalled {
				t.Fatal("SetKernelClock called on bad arg count; want no syscall attempt")
			}
		})
	}
}

// TestNonIntegerArg confirms a non-integer positional arg fails parse +
// maps to exitBadTimestamp without attempting any syscall.
func TestNonIntegerArg(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{"alphabetic", "abc"},
		{"float", "1747000000.5"},
		{"hex prefix", "0x1234"},
		{"empty", ""},
		{"trailing junk", "1747000000xyz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, _, captured := stubDeps([]string{tc.arg})
			got := run(d)
			if got != exitBadTimestamp {
				t.Fatalf("run exit = %d, want %d", got, exitBadTimestamp)
			}
			if captured.kernelCalled {
				t.Fatal("SetKernelClock called on parse failure; want no syscall attempt")
			}
		})
	}
}

// TestRangeBoundary asserts the LD-85 / spec §4 D11 half-open bound on
// the timestamp: inclusive lower at 2024-01-01T00:00:00Z, exclusive
// upper at 2099-01-01T00:00:00Z. Same shape the verifier uses for its
// `now` claim. The four named timestamps walk the boundaries; out-of-
// range values reject before the kernel-clock call.
func TestRangeBoundary(t *testing.T) {
	exact2024 := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	just2023 := exact2024 - 1
	exact2099 := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	year2100 := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()

	tests := []struct {
		name string
		ts   int64
		want int
	}{
		{"2023-12-31T23:59:59Z rejects", just2023, exitBadTimestamp},
		{"2024-01-01T00:00:00Z accepts (inclusive lower)", exact2024, exitSuccess},
		{"2026-05-13 mid-range accepts", time.Date(2026, time.May, 13, 12, 0, 0, 0, time.UTC).Unix(), exitSuccess},
		{"2099-01-01T00:00:00Z rejects (exclusive upper)", exact2099, exitBadTimestamp},
		{"2100-01-01T00:00:00Z rejects", year2100, exitBadTimestamp},
		{"unix epoch rejects", int64(0), exitBadTimestamp},
		{"negative rejects", int64(-1), exitBadTimestamp},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, _, captured := stubDeps([]string{int64ToArg(tc.ts)})
			got := run(d)
			if got != tc.want {
				t.Fatalf("run(%d) exit = %d, want %d", tc.ts, got, tc.want)
			}
			if tc.want == exitSuccess {
				if !captured.kernelCalled {
					t.Fatal("SetKernelClock not called on in-range timestamp")
				}
				if captured.kernelArg != tc.ts {
					t.Fatalf("SetKernelClock arg = %d, want %d", captured.kernelArg, tc.ts)
				}
				if !captured.rtcCalled {
					t.Fatal("SetRTC not called after successful kernel clock set")
				}
			} else if captured.kernelCalled {
				t.Fatal("SetKernelClock called on out-of-range timestamp; want early reject")
			}
		})
	}
}

// TestKernelClockFailureExits3AndSkipsRTC confirms that if clock_settime
// fails, the setter does NOT attempt the RTC ioctl: continuing with a
// known-wrong kernel clock is meaningless. Exit code is 3 per the
// setter's own exit-code map.
func TestKernelClockFailureExits3AndSkipsRTC(t *testing.T) {
	d, stderr, captured := stubDeps([]string{"1747000000"})
	captured.kernelErr = errors.New("simulated EPERM")
	got := run(d)
	if got != exitClockSettimeFail {
		t.Fatalf("run exit = %d, want %d", got, exitClockSettimeFail)
	}
	if !captured.kernelCalled {
		t.Fatal("SetKernelClock not called")
	}
	if captured.rtcCalled {
		t.Fatal("SetRTC called after kernel-clock failure; want skip")
	}
	if !strings.Contains(stderr.String(), "clock_settime") {
		t.Fatalf("stderr missing clock_settime context: %q", stderr.String())
	}
}

// TestRTCFailureExits0WithStderrWarning is the LD-77 regression guard:
// an RTC ioctl failure (ENODEV / ENOENT / EPERM / EACCES / device
// missing) MUST log a one-line warning to stderr and exit 0. RTC-less
// devices are a real shape; hiding the kernel-clock success behind an
// RTC failure would close the engineer's SSH session non-zero for no
// benefit.
func TestRTCFailureExits0WithStderrWarning(t *testing.T) {
	d, stderr, captured := stubDeps([]string{"1747000000"})
	captured.rtcErr = errors.New("simulated ENODEV")
	got := run(d)
	if got != exitSuccess {
		t.Fatalf("run exit = %d, want %d (RTC failure must be fail-tolerant per LD-77)", got, exitSuccess)
	}
	if !captured.kernelCalled {
		t.Fatal("SetKernelClock not called")
	}
	if !captured.rtcCalled {
		t.Fatal("SetRTC not called")
	}
	out := stderr.String()
	if !strings.Contains(out, "RTC") {
		t.Fatalf("stderr missing RTC context: %q", out)
	}
	if !strings.Contains(out, "kernel clock was set") {
		t.Fatalf("stderr missing kernel-clock-success reassurance: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stderr should be exactly one line, got %d: %q", strings.Count(out, "\n"), out)
	}
}

// TestHappyPathSilentStderr confirms the success path emits nothing on
// stderr — engineer-facing noise on success is anti-pattern.
func TestHappyPathSilentStderr(t *testing.T) {
	d, stderr, captured := stubDeps([]string{"1747000000"})
	got := run(d)
	if got != exitSuccess {
		t.Fatalf("run exit = %d, want %d (stderr=%q)", got, exitSuccess, stderr.String())
	}
	if !captured.kernelCalled || !captured.rtcCalled {
		t.Fatal("happy path did not invoke both syscalls")
	}
	if stderr.Len() != 0 {
		t.Fatalf("happy path stderr should be empty, got %q", stderr.String())
	}
	wantRTCArg := time.Unix(1747000000, 0).UTC()
	if !captured.rtcArg.Equal(wantRTCArg) {
		t.Fatalf("RTC arg = %s, want %s", captured.rtcArg.Format(time.RFC3339), wantRTCArg.Format(time.RFC3339))
	}
}

// TestStderrSingleLinePerFailure is a discipline regression guard:
// every failure-path stderr message is exactly one line. Multi-line
// dumps (stack traces, errno tables) leak attacker-useful detail and
// make on-device log analysis harder.
func TestStderrSingleLinePerFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func() deps
	}{
		{
			"wrong arg count",
			func() deps {
				d, _, _ := stubDeps([]string{})
				return d
			},
		},
		{
			"non-integer",
			func() deps {
				d, _, _ := stubDeps([]string{"abc"})
				return d
			},
		},
		{
			"out of range",
			func() deps {
				d, _, _ := stubDeps([]string{"0"})
				return d
			},
		},
		{
			"clock_settime failure",
			func() deps {
				d, _, captured := stubDeps([]string{"1747000000"})
				captured.kernelErr = errors.New("simulated failure")
				return d
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.setup()
			stderr := d.Stderr.(*bytes.Buffer)
			_ = run(d)
			out := stderr.String()
			if out == "" {
				t.Fatal("failure path emitted no stderr")
			}
			if strings.Count(out, "\n") != 1 {
				t.Fatalf("stderr should be exactly one line, got %d: %q", strings.Count(out, "\n"), out)
			}
		})
	}
}

// int64ToArg formats a signed 64-bit timestamp as the decimal string
// the setter consumes via os.Args. Same conversion the verifier
// performs in production via strconv.FormatInt.
func int64ToArg(ts int64) string {
	return strconv.FormatInt(ts, 10)
}
