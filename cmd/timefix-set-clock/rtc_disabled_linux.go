//go:build linux && no_rtc

package main

import "time"

// setRTC is a silent no-op with `-tags no_rtc`. Images that intentionally
// skip the RTC path compile this in; the kernel clock still gets set and
// the device re-recovers on the next timefix after reboot.
func setRTC(_ time.Time) error {
	return nil
}
