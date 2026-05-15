//go:build linux

package main

import "golang.org/x/sys/unix"

// setKernelClock advances CLOCK_REALTIME via clock_settime(2). The
// process must hold CAP_SYS_TIME; the install recipe applies
// cap_sys_time+ep to this binary via `setcap`, which is what makes the
// capability effective on this otherwise-unprivileged process.
func setKernelClock(unixSec int64) error {
	ts := unix.Timespec{Sec: unixSec, Nsec: 0}
	return unix.ClockSettime(unix.CLOCK_REALTIME, &ts)
}
