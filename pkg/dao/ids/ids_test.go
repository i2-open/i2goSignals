package ids

import (
	"encoding/hex"
	"regexp"
	"sync"
	"testing"
	"uuid"
)

// canonicalUUID matches the 8-4-4-4-12 lowercase-hex form RFC 9562 §4 defines.
var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// assertRFC9562 checks the two structural fields RFC 9562 §4.1/§4.2 pin: the
// version nibble in octet 6 and the two-bit variant prefix in octet 8. They are
// what distinguishes a real v4/v7 from an arbitrary 128-bit blob, so a format
// test that skips them proves nothing.
func assertRFC9562(t *testing.T, s string, wantVersion byte) {
	t.Helper()
	if !canonicalUUID.MatchString(s) {
		t.Fatalf("not a canonical lowercase UUID string: %q", s)
	}
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", s, err)
	}
	if got := u[6] >> 4; got != wantVersion {
		t.Errorf("version = %d, want %d (%q)", got, wantVersion, s)
	}
	if got := u[8] >> 6; got != 0b10 {
		t.Errorf("variant bits = %#b, want 0b10 (%q)", got, s)
	}
}

func TestNewObjectIDFormat(t *testing.T) {
	for i := 0; i < 1000; i++ {
		id := NewObjectID()
		if len(id) != 24 {
			t.Fatalf("length = %d, want 24: %q", len(id), id)
		}
		b, err := hex.DecodeString(id)
		if err != nil {
			t.Fatalf("not lowercase hex: %q: %v", id, err)
		}
		if len(b) != 12 {
			t.Fatalf("decoded length = %d, want 12: %q", len(b), id)
		}
	}
}

func TestNewV7Format(t *testing.T) {
	for i := 0; i < 1000; i++ {
		assertRFC9562(t, NewV7(), 7)
	}
}

func TestNewSecretFormat(t *testing.T) {
	for i := 0; i < 1000; i++ {
		assertRFC9562(t, NewSecret(), 4)
	}
}

// TestNewV7Monotonic pins the property that makes v7 the right shape for stream
// ids and jtis: 10k consecutive mints sort into mint order. The canonical string
// is big-endian lowercase hex with dashes at fixed offsets and a constant version
// nibble, so lexicographic string order is byte order -- callers may sort the
// strings directly without decoding them.
func TestNewV7Monotonic(t *testing.T) {
	const n = 10_000
	prev := NewV7()
	for i := 1; i < n; i++ {
		next := NewV7()
		if next <= prev {
			t.Fatalf("mint %d not strictly increasing: %q followed by %q", i, prev, next)
		}
		prev = next
	}
}

// TestUniqueUnderConcurrency mints from many goroutines at once because that is
// how the server actually calls these: v7 in particular serialises on a shared
// timestamp counter, so a collision or a data race would only ever show up under
// parallel load. Run with -race for the second half of the guarantee.
func TestUniqueUnderConcurrency(t *testing.T) {
	const (
		goroutines = 16
		perRoutine = 500
	)
	for _, tc := range []struct {
		name string
		mint func() string
	}{
		{"NewObjectID", NewObjectID},
		{"NewV7", NewV7},
		{"NewSecret", NewSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu   sync.Mutex
				seen = make(map[string]struct{}, goroutines*perRoutine)
				wg   sync.WaitGroup
			)
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					local := make([]string, 0, perRoutine)
					for i := 0; i < perRoutine; i++ {
						local = append(local, tc.mint())
					}
					mu.Lock()
					defer mu.Unlock()
					for _, id := range local {
						if _, dup := seen[id]; dup {
							t.Errorf("duplicate id %q", id)
						}
						seen[id] = struct{}{}
					}
				}()
			}
			wg.Wait()
			if len(seen) != goroutines*perRoutine {
				t.Errorf("unique ids = %d, want %d", len(seen), goroutines*perRoutine)
			}
		})
	}
}
