//go:build !linux

package wal

import "os"

// fdatasync falls back to File.Sync where the platform has no fdatasync
// (on darwin that is F_FULLFSYNC, a full flush to the platter).
func fdatasync(f *os.File) error {
	return f.Sync()
}
