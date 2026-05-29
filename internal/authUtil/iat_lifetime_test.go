package authUtil

import (
	"testing"
	"time"
)

// TestIatLifetimeDefault verifies that without I2SIG_IAT_LIFETIME the minted IAT
// expires in ~24h (not the old hard-coded 90 days).
func TestIatLifetimeDefault(t *testing.T) {
	t.Setenv("I2SIG_IAT_LIFETIME", "")

	token, err := auth.IssueProjectIat(nil)
	if err != nil {
		t.Fatalf("IssueProjectIat failed: %v", err)
	}
	eat, err := auth.ParseAuthToken(token)
	if err != nil {
		t.Fatalf("ParseAuthToken failed: %v", err)
	}
	ttl := time.Until(eat.ExpiresAt.Time)
	if ttl < 23*time.Hour || ttl > 25*time.Hour {
		t.Fatalf("expected default IAT lifetime ~24h, got %s", ttl)
	}
}

// TestIatLifetimeConfigured verifies I2SIG_IAT_LIFETIME overrides the default.
func TestIatLifetimeConfigured(t *testing.T) {
	t.Setenv("I2SIG_IAT_LIFETIME", "1h")

	token, err := auth.IssueProjectIat(nil)
	if err != nil {
		t.Fatalf("IssueProjectIat failed: %v", err)
	}
	eat, err := auth.ParseAuthToken(token)
	if err != nil {
		t.Fatalf("ParseAuthToken failed: %v", err)
	}
	ttl := time.Until(eat.ExpiresAt.Time)
	if ttl < 50*time.Minute || ttl > 70*time.Minute {
		t.Fatalf("expected configured IAT lifetime ~1h, got %s", ttl)
	}
}
