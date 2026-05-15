// Package logging is a tiny helper that wires the broker and CLI binaries to a
// shared slog configuration. Each cmd/* main.go calls Configure() once at
// startup; from there, packages reach for slog.Default() rather than carrying
// a logger as a dependency.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// EnvLogLevel is the env var consulted for the slog handler's minimum level.
// Same name across cmd/broker, cmd/broker-lambda, and cmd/postern so engineers
// and operators set one variable.
const EnvLogLevel = "POSTERN_LOG_LEVEL"

// Configure installs a JSON slog handler on os.Stderr at the level resolved
// from $POSTERN_LOG_LEVEL (debug, info, warn, error; unset/unknown → info).
func Configure() {
	level := parseLevel(os.Getenv(EnvLogLevel))
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
