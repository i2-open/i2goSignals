// Package wal is the opt-in node-local write-ahead log behind
// I2SIG_STORE_WAL=local (ADR 0045). In local mode the router acknowledges a
// SET once it is fsynced here, and a drain worker moves it to the shared
// store (MongoDB) afterwards. The default ("majority") never opens a WAL, so
// the ADR 0038 majority contract is unchanged unless an operator opts in.
package wal

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	// EnvMode selects the ingest durability mode: "majority" (default) or "local".
	EnvMode = "I2SIG_STORE_WAL"
	// EnvDir is the directory holding the local WAL file (local mode only).
	EnvDir = "I2SIG_STORE_WAL_DIR"
	// DefaultDir is used when EnvDir is unset; relative to the working directory.
	DefaultDir = "data/wal"
	// FileName is the WAL file inside the WAL directory.
	FileName = "ingest.wal"
)

// Mode is the ingest durability mode.
type Mode string

const (
	// ModeMajority acknowledges after a majority-committed store write (ADR 0038). Default.
	ModeMajority Mode = "majority"
	// ModeLocal acknowledges after a local fsync to the WAL (ADR 0045).
	ModeLocal Mode = "local"
)

// ErrClosed is returned by operations on a closed Log.
var ErrClosed = errors.New("wal: closed")

// ParseMode parses an I2SIG_STORE_WAL value. Empty means majority. Matching
// is case-insensitive; any other value is an error so a typo can never
// silently change the durability contract.
func ParseMode(v string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", string(ModeMajority):
		return ModeMajority, nil
	case string(ModeLocal):
		return ModeLocal, nil
	default:
		return "", fmt.Errorf("%s: unknown value %q (want %q or %q)", EnvMode, v, ModeMajority, ModeLocal)
	}
}

// ModeFromEnv reads and parses EnvMode.
func ModeFromEnv() (Mode, error) {
	return ParseMode(os.Getenv(EnvMode))
}

// DirFromEnv returns EnvDir, or DefaultDir when unset.
func DirFromEnv() string {
	if d := strings.TrimSpace(os.Getenv(EnvDir)); d != "" {
		return d
	}
	return DefaultDir
}

// Entry is one durable WAL record.
type Entry struct {
	Seq  uint64
	Data []byte
}

// Log is an append-only, fsync-on-append local log.
type Log interface {
	// Append durably writes the batch as consecutive entries and returns the
	// sequence number of the last one. It returns only after the data is
	// fsynced; concurrent Appends are group-committed.
	Append(batch [][]byte) (uint64, error)
	// ReadFrom returns up to limit entries with Seq >= seq, in order.
	// Entries whose checksum fails (a torn write) are skipped.
	ReadFrom(seq uint64, limit int) ([]Entry, error)
	// Truncate removes every entry with Seq <= seq.
	Truncate(seq uint64) error
	// Depth is the number of entries currently held.
	Depth() int
	// Close releases the log and its file lock.
	Close() error
}
