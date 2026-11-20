//go:build unix

package wal

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockDir takes an exclusive, non-blocking flock on path so two processes
// never write the same WAL directory (the guard the bbolt file lock gave).
func lockDir(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("wal: %s is locked by another process", path)
		}
		return nil, fmt.Errorf("wal: lock %s: %w", path, err)
	}
	return f, nil
}

func unlockDir(f *os.File) error {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return f.Close()
}
