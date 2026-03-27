package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestSubLoggerLevelUpdate(t *testing.T) {
	// Setup a buffer to capture output
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: globalLevel})
	slog.SetDefault(slog.New(handler))

	// Create a sub-logger (similar to pLog in dynamic_proxy.go)
	subLogger := Sub("TEST")

	// Initially it should be Info level (from init)
	globalLevel.Set(slog.LevelInfo)
	subLogger.Debug("this debug message should be hidden")
	if buf.Len() > 0 {
		t.Errorf("expected no output for debug message at Info level, got: %s", buf.String())
	}
	buf.Reset()

	subLogger.Info("this info message should be shown")
	if !strings.Contains(buf.String(), "this info message should be shown") {
		t.Errorf("expected info message to be shown, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "component=TEST") {
		t.Errorf("expected component=TEST attribute, got: %s", buf.String())
	}
	buf.Reset()

	// Now update to Debug level via Init (simulated)
	Init("debug")
	subLogger.Debug("this debug message should now be shown")
	if !strings.Contains(buf.String(), "this debug message should now be shown") {
		t.Errorf("expected debug message to be shown after Init(debug), got: %s", buf.String())
	}
	buf.Reset()
}
