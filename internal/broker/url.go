package broker

import (
	"net/url"
	"strings"
)

// IsHTTPSOrLoopback returns true for https:// URLs or any-scheme localhost
// / 127.0.0.1 / [::1] URLs (loopback exception is the local-dev escape
// hatch). Applied at both broker and CLI boundaries against the same
// definition so a YAML the broker would reject can't be silently accepted
// by the CLI — that asymmetry would expose the OAuth flow over plaintext
// before any broker round-trip.
func IsHTTPSOrLoopback(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
