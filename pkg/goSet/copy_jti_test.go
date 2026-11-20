package goSet

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestDeriveCopyJti(t *testing.T) {
	const sid = "65f0c0ffee0000000000abcd"
	v7 := "01923456-789a-7bcd-8ef0-123456789abc"
	v8 := "01923456-789a-8bcd-8ef0-123456789abc"
	v4 := "01923456-789a-4bcd-8ef0-123456789abc"

	tests := []struct {
		name       string
		inbound    string
		keepPrefix bool
	}{
		{"version 7 keeps prefix", v7, true},
		{"version 8 keeps prefix", v8, true},
		{"uppercase version 7 keeps prefix", strings.ToUpper(v7), true},
		{"version 4 hashed", v4, false},
		{"non-UUID input hashed", "not-a-uuid-jti", false},
		{"empty input hashed", "", false},
		{"uuid without dashes hashed", strings.ReplaceAll(v7, "-", ""), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveCopyJti(sid, tc.inbound)
			if again := DeriveCopyJti(sid, tc.inbound); again != got {
				t.Fatalf("not deterministic: %s vs %s", got, again)
			}
			if len(got) != 36 || got != strings.ToLower(got) {
				t.Fatalf("not canonical lowercase: %q", got)
			}
			u, ok := parseCanonicalUUID(got)
			if !ok {
				t.Fatalf("not a canonical UUID: %q", got)
			}
			if u[6]>>4 != 8 {
				t.Errorf("version nibble = %x, want 8", u[6]>>4)
			}
			if u[8]&0xc0 != 0x80 {
				t.Errorf("variant bits = %b, want 10", u[8]>>6)
			}
			h := sha256.Sum256([]byte(copyJtiDomain + "\x00" + sid + "\x00" + tc.inbound))
			if tc.keepPrefix {
				in, _ := parseCanonicalUUID(tc.inbound)
				if got[0:13] != strings.ToLower(tc.inbound[0:13]) {
					t.Errorf("prefix not kept: got %s inbound %s", got, tc.inbound)
				}
				if u[6]&0x0f != in[6]&0x0f || u[7] != in[7] {
					t.Errorf("rand_a bits not kept")
				}
			} else {
				var want [16]byte
				copy(want[:], h[0:16])
				want[6] = (want[6] & 0x0f) | 0x80
				want[8] = (want[8] & 0x3f) | 0x80
				if got != formatUUID(want) {
					t.Errorf("got %s want %s", got, formatUUID(want))
				}
			}
			// bytes 8.. always come from the hash
			if u[9] != h[9] || u[15] != h[15] {
				t.Errorf("tail not from hash")
			}
		})
	}

	if DeriveCopyJti(sid, v7) == DeriveCopyJti("other", v7) {
		t.Error("different streams yield the same copy jti")
	}
	if DeriveCopyJti(sid, v7) == v7 {
		t.Error("copy jti equals inbound jti")
	}
	// a copy of a copy keeps sorting with the original (multi-hop)
	hop2 := DeriveCopyJti("next", DeriveCopyJti(sid, v7))
	if hop2[0:13] != v7[0:13] {
		t.Errorf("second hop lost the timestamp prefix: %s", hop2)
	}
}
