package logger

import (
	"log/slog"
	"os"
	"strings"
)

var (
	globalLevel = new(slog.LevelVar)
	defaultOpts = &slog.HandlerOptions{
		Level: globalLevel,
	}
)

func init() {
	// Default to Info level until Init is called
	globalLevel.Set(slog.LevelInfo)

	// Use TextHandler for human-friendly output, similar to standard log.
	// We can easily switch to JSONHandler here if needed for production.
	handler := slog.NewTextHandler(os.Stdout, defaultOpts)
	slog.SetDefault(slog.New(handler))
}

// Init initializes the default slog logger with the specified level.
// levelStr can be "debug", "info", "warn", "warning", or "error".
// If levelStr is empty or unrecognized, it defaults to "info".
func Init(levelStr string) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	globalLevel.Set(level)
}

func IsDebugEnabled() bool {
	return globalLevel.Level() == slog.LevelDebug
}

// Sub returns a logger with a "component" attribute.
func Sub(component string) *slog.Logger {
	return slog.Default().With("component", component)
}
