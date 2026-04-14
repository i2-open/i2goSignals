package authSupport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GenerateClusterToken generates an HMAC-based token for internal cluster communication.
// The token includes a timestamp to prevent long-term replay attacks.
func GenerateClusterToken(secret string, sid, mode string) string {
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%d:%s:%s", timestamp, sid, mode)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	// Return a token that contains both the timestamp and the signature
	token := fmt.Sprintf("%d:%s", timestamp, signature)
	return base64.StdEncoding.EncodeToString([]byte(token))
}

// ValidateClusterToken validates an HMAC-based token for internal cluster communication.
func ValidateClusterToken(secret string, tokenB64 string, sid, mode string, maxDrift time.Duration) bool {
	if secret == "" {
		return false
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return false
	}
	token := string(tokenBytes)
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return false
	}
	timestampStr, signature := parts[0], parts[1]
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}

	// Check for clock drift
	now := time.Now().Unix()
	drift := now - timestamp
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > maxDrift {
		return false
	}

	// Recompute HMAC
	expectedPayload := fmt.Sprintf("%d:%s:%s", timestamp, sid, mode)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(expectedPayload))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}
