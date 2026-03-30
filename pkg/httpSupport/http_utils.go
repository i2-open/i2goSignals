package httpSupport

import (
	"net/http"
	"strings"
)

func HandleRespClose(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// EnsureBearerPrefix ensures that the token string has exactly one "Bearer " prefix.
// It case-insensitively strips any existing "Bearer" prefixes and extra whitespace.
// If the resulting token is empty, it returns an empty string.
func EnsureBearerPrefix(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}

	// Repeatedly strip "bearer" (case-insensitive) from the start
	for {
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "bearer") {
			token = strings.TrimSpace(token[len("bearer"):])
		} else {
			break
		}
	}

	if token == "" {
		return ""
	}
	return "Bearer " + token
}
