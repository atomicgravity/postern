//go:build linux && !no_rtc

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const rtcDevicePath = "/dev/rtc0"

// setRTC writes t to /dev/rtc0 via RTC_SET_TIME. Errors surface to run()
// which handles fail-tolerance (the kernel clock is already advanced).
// Build with `-tags no_rtc` to compile this out entirely.
func setRTC(t time.Time) error {
	fd, err := os.OpenFile(rtcDevicePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", rtcDevicePath, err)
	}
	defer fd.Close()

	// linux/rtc.h `struct rtc_time` mirrors `struct tm`: mon 0..11, year
	// since-1900, wday 0..6, yday 0..365, isdst unused. The kernel
	// ignores Wday/Yday/Isdst on SET but populating matches the contract.
	utc := t.UTC()
	rtc := unix.RTCTime{
		Sec:   int32(utc.Second()),
		Min:   int32(utc.Minute()),
		Hour:  int32(utc.Hour()),
		Mday:  int32(utc.Day()),
		Mon:   int32(utc.Month() - 1),
		Year:  int32(utc.Year() - 1900),
		Wday:  int32(utc.Weekday()),
		Yday:  int32(utc.YearDay() - 1),
		Isdst: 0,
	}
	if err := unix.IoctlSetRTCTime(int(fd.Fd()), &rtc); err != nil {
		return fmt.Errorf("ioctl RTC_SET_TIME on %s: %w", rtcDevicePath, err)
	}
	return nil
}
