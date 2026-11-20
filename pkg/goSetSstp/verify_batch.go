package goSetSstp

import (
	"runtime"
	"sort"
	"sync"
)

// VerifiedBatchEntry is the outcome of VerifySET for one SET of a batch. Err
// is nil when Verified is populated.
type VerifiedBatchEntry struct {
	JTI      string
	Raw      string
	Verified VerifiedSET
	Err      error
}

// VerifyAll verifies every SET in sets, keyed by the JTI the sender used, and
// returns one entry per SET in a deterministic order (ascending JTI) so the
// caller's acks and setErrs do not depend on map iteration.
//
// Signature verification dominates the cost of an inbound batch, and it is
// CPU-bound with no shared state, so the SETs are spread over parallelism
// goroutines. parallelism <= 0 selects GOMAXPROCS; it is capped by the batch
// size, and a batch of one is verified on the calling goroutine.
func VerifyAll(sets map[string]string, config VerifyConfig, parallelism int) []VerifiedBatchEntry {
	entries := make([]VerifiedBatchEntry, 0, len(sets))
	for jti, raw := range sets {
		entries = append(entries, VerifiedBatchEntry{JTI: jti, Raw: raw})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].JTI < entries[j].JTI })

	if parallelism <= 0 {
		parallelism = runtime.GOMAXPROCS(0)
	}
	if parallelism > len(entries) {
		parallelism = len(entries)
	}
	if parallelism <= 1 {
		for i := range entries {
			entries[i].Verified, entries[i].Err = VerifySET(entries[i].Raw, config)
		}
		return entries
	}

	next := make(chan int, len(entries))
	for i := range entries {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	wg.Add(parallelism)
	for w := 0; w < parallelism; w++ {
		go func() {
			defer wg.Done()
			for i := range next {
				entries[i].Verified, entries[i].Err = VerifySET(entries[i].Raw, config)
			}
		}()
	}
	wg.Wait()
	return entries
}
