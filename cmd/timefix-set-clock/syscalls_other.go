//go:build !linux

package main

import (
	"errors"
	"time"
)

// errUnsupportedPlatform is returned by both syscall stubs on non-Linux.
// The cross-platform build exists so the pure-Go parser/validator are
// exercised by developer macOS hosts and CI; production on-device binaries
// are goreleaser-built linux/amd64 + linux/arm64 only.
var errUnsupportedPlatform = errors.New("timefix-set-clock: kernel clock + RTC writes are Linux-only")

func setKernelClock(unixSec int64) error {
	return errUnsupportedPlatform
}

func setRTC(t time.Time) error {
	return errUnsupportedPlatform
}
