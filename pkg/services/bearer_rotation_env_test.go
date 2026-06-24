package services

import (
	"testing"
	"time"
)

// TestBearerRotateOnGetEnabled covers ADR 0022 §4: rotation is gated by
// I2SIG_BEARER_ROTATE_ON_GET and defaults to false (unset).
func TestBearerRotateOnGetEnabled(t *testing.T) {
	tests := []struct {
		val  string
		want bool
		set  bool
	}{
		{set: false, want: false}, // unset -> default false
		{val: "", want: false, set: true},
		{val: "false", want: false, set: true},
		{val: "true", want: true, set: true},
		{val: "TRUE", want: true, set: true},
		{val: "1", want: true, set: true},
		{val: "enabled", want: true, set: true},
		{val: "yes", want: true, set: true},
		{val: "nonsense", want: false, set: true},
	}
	for _, tt := range tests {
		name := "unset"
		if tt.set {
			name = "=" + tt.val
		}
		t.Run(name, func(t *testing.T) {
			if tt.set {
				t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", tt.val)
			} else {
				t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "")
			}
			if got := BearerRotateOnGetEnabled(); got != tt.want {
				t.Errorf("BearerRotateOnGetEnabled(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// TestBearerRotateGrace covers ADR 0022 §2: grace defaults to 1h; "0" means
// immediate; invalid falls back to the default.
func TestBearerRotateGrace(t *testing.T) {
	tests := []struct {
		val  string
		want time.Duration
		set  bool
	}{
		{set: false, want: time.Hour},
		{val: "", want: time.Hour, set: true},
		{val: "0", want: 0, set: true},
		{val: "30m", want: 30 * time.Minute, set: true},
		{val: "2h", want: 2 * time.Hour, set: true},
		{val: "garbage", want: time.Hour, set: true},
		{val: "-5m", want: time.Hour, set: true}, // negative falls back to default
	}
	for _, tt := range tests {
		name := "unset"
		if tt.set {
			name = "=" + tt.val
		}
		t.Run(name, func(t *testing.T) {
			if tt.set {
				t.Setenv("I2SIG_BEARER_ROTATE_GRACE", tt.val)
			} else {
				t.Setenv("I2SIG_BEARER_ROTATE_GRACE", "")
			}
			if got := BearerRotateGrace(); got != tt.want {
				t.Errorf("BearerRotateGrace(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}
