package mongo

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestOneTripBulkWriteCarriesMajority asserts the one-trip events+pending
// bulkWrite requests majority+journal explicitly (#332): a client bulkWrite
// takes the client's write concern, and the client carries none.
func TestOneTripBulkWriteCarriesMajority(t *testing.T) {
	var got options.ClientBulkWriteOptions
	for _, apply := range oneTripBulkWriteOptions().List() {
		if err := apply(&got); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	wc := got.WriteConcern
	if wc == nil || wc.W != "majority" || wc.Journal == nil || !*wc.Journal {
		t.Errorf("want w:majority j:true, got %+v", wc)
	}
	if got.Ordered == nil || !*got.Ordered {
		t.Error("one-trip bulkWrite must stay ordered (ADR 0043)")
	}
}

func TestEventStoreWriteConcernIsFresh(t *testing.T) {
	a := EventStoreWriteConcern()
	a.W = 1
	if b := EventStoreWriteConcern(); b.W != "majority" {
		t.Errorf("EventStoreWriteConcern shares state: got W=%v", b.W)
	}
}

// TestAckBulkWriteIsW1Unordered asserts the one-trip ack bulkWrite (#359)
// runs unordered at w:1: a duplicate copy insert must never stop the
// conditional state update, and an ack is post-persistence.
func TestAckBulkWriteIsW1Unordered(t *testing.T) {
	var got options.ClientBulkWriteOptions
	for _, apply := range ackBulkWriteOptions().List() {
		if err := apply(&got); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	if wc := got.WriteConcern; wc == nil || wc.W != 1 {
		t.Errorf("want w:1, got %+v", got.WriteConcern)
	}
	if got.Ordered == nil || *got.Ordered {
		t.Error("ack bulkWrite must be unordered")
	}
}
