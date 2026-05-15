// Package version exposes the build-stamp variables overridden via -ldflags
// at release time; see the release process in DESIGN.md for how these are
// populated.
package version

// These values are intentionally plain variables so release builds can replace
// them with -ldflags without changing the CLI wiring.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
