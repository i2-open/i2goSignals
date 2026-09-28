package dao

import (
	"reflect"
	"testing"
)

func TestStreamsByJti(t *testing.T) {
	got := StreamsByJti(map[string][]string{
		"s2": {"a", "b", "a"},
		"s1": {"a"},
	})
	want := map[string][]string{"a": {"s1", "s2"}, "b": {"s2"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("StreamsByJti = %v, want %v", got, want)
	}
	if StreamsByJti(nil) != nil {
		t.Fatal("an empty pending map must invert to nil")
	}
}
