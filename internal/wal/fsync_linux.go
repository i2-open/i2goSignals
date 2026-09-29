//go:build linux

package wal

import (
	"os"
	"syscall"
)

// fdatasync flushes the file's data and the metadata needed to read it back
// (its size), which is all a record needs; fsync would also flush the
// timestamps.
func fdatasync(f *os.File) error {
	return syscall.Fdatasync(int(f.Fd()))
}
