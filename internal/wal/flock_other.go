//go:build !unix

package wal

import (
	"fmt"
	"os"
)

// lockDir on platforms without flock only creates the marker file; a second
// process is not prevented from opening the directory.
func lockDir(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open lock %s: %w", path, err)
	}
	return f, nil
}

func unlockDir(f *os.File) error { return f.Close() }
