package services

import (
	"errors"
	"os"
	"strings"
)

// kidSidecarSuffix names the file next to a saved key PEM that holds the kid
// the server returned for it (spec #114): <pemPath>.kid.
const kidSidecarSuffix = ".kid"

// WriteKidSidecar saves kid to <pemPath>.kid (kid only, trailing newline) next
// to the PEM, so a consumer of the PEM file knows the key's kid. An empty kid
// (a server that sent no KeyIdHeader) leaves no sidecar: a stale one from an
// earlier key is removed, and the consumer falls back to kid = issuer.
func WriteKidSidecar(pemPath, kid string, perm os.FileMode) error {
	sidecar := pemPath + kidSidecarSuffix
	if kid == "" {
		if err := os.Remove(sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(sidecar, []byte(kid+"\n"), perm)
}

// ReadKidSidecar returns the kid saved next to pemPath by WriteKidSidecar, or
// "" when there is no sidecar.
func ReadKidSidecar(pemPath string) (string, error) {
	b, err := os.ReadFile(pemPath + kidSidecarSuffix)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
