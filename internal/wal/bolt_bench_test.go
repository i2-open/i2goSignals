package wal

import (
	"sync"
	"testing"
)

// BenchmarkBoltAppend16 is 16 concurrent single-record appends per op.
func BenchmarkBoltAppend16(b *testing.B) {
	l, err := OpenBolt(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	payload := make([]byte, 1024)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		for c := 0; c < 16; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := l.Append([][]byte{payload}); err != nil {
					b.Error(err)
				}
			}()
		}
		wg.Wait()
	}
}

// BenchmarkBoltAppendSerial is one single-record append (one commit) per op.
func BenchmarkBoltAppendSerial(b *testing.B) {
	l, err := OpenBolt(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	payload := make([]byte, 1024)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := l.Append([][]byte{payload}); err != nil {
			b.Fatal(err)
		}
	}
}
