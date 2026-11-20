package dao

import (
	"reflect"
	"testing"
)

func TestStreamsByJti(t *testing.T) {
	got := StreamsByJti(map[string][]PendingRef{
		"s2": {{Jti: "a", AckJti: "a2"}, {Jti: "b"}, {Jti: "a", AckJti: "ignored"}},
		"s1": {{Jti: "a"}},
	})
	want := map[string][]StreamPending{
		"a": {{StreamID: "s1", Ref: PendingRef{Jti: "a", AckJti: "a"}}, {StreamID: "s2", Ref: PendingRef{Jti: "a", AckJti: "a2"}}},
		"b": {{StreamID: "s2", Ref: PendingRef{Jti: "b", AckJti: "b"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("StreamsByJti = %v, want %v", got, want)
	}
	if StreamsByJti(nil) != nil {
		t.Fatal("an empty pending map must invert to nil")
	}
}
