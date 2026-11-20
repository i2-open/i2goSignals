package mongo_provider

import (
	"reflect"
	"testing"
	"unsafe"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// collectionWriteConcern reads the write concern a collection handle was
// constructed with. The v2 driver has no public getter, so the test reads the
// unexported field; it is test-only and fails loudly if the field moves.
func collectionWriteConcern(t *testing.T, col *mongo.Collection) *writeconcern.WriteConcern {
	t.Helper()
	if col == nil {
		t.Fatal("collection handle is nil")
	}
	f := reflect.ValueOf(col).Elem().FieldByName("writeConcern")
	if !f.IsValid() {
		t.Fatal("mongo.Collection has no writeConcern field; driver layout changed")
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(*writeconcern.WriteConcern)
}

func isMajorityJournaled(wc *writeconcern.WriteConcern) bool {
	return wc != nil && wc.W == "majority" && wc.Journal != nil && *wc.Journal
}

func isW1(wc *writeconcern.WriteConcern) bool {
	return wc != nil && wc.W == 1 && wc.Journal == nil
}

// TestCollectionWriteConcerns asserts every collection handle the provider
// opens carries its explicit per-collection write concern (#332), with no
// client-level concern to fall back on.
func TestCollectionWriteConcerns(t *testing.T) {
	// Connect is lazy in the v2 driver: no server is contacted here.
	client, err := mongo.Connect(options.Client().ApplyURI(clientURIForTest))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(t.Context()) }()

	m := &MongoProvider{}
	m.ssefDb = client.Database("wc_test")
	m.openCollections()

	majority := map[string]*mongo.Collection{
		CDbEvents:     m.eventCol,
		CDbDeliveries: m.deliveriesCol,
		CDbLeases:     m.leaseCol,
	}
	w1 := map[string]*mongo.Collection{
		CDbStreamCfg:      m.streamCol,
		CDbKeys:           m.keyCol,
		CDbClients:        m.clientCol,
		CDbServers:        m.serverCol,
		CDbNodes:          m.nodeCol,
		CDbTokens:         m.tokenCol,
		CDbSubjectFilters: m.subjectFilterCol,
	}
	for name, col := range majority {
		if wc := collectionWriteConcern(t, col); !isMajorityJournaled(wc) {
			t.Errorf("%s: want w:majority j:true, got %+v", name, wc)
		}
	}
	for name, col := range w1 {
		if wc := collectionWriteConcern(t, col); !isW1(wc) {
			t.Errorf("%s: want w:1, got %+v", name, wc)
		}
	}
	if got, want := len(majority)+len(w1), len(collectionWriteConcerns); got != want {
		t.Errorf("test covers %d collections, table has %d", got, want)
	}
	for name, col := range majority {
		if col.Name() != name {
			t.Errorf("handle for %s is named %s", name, col.Name())
		}
	}
	for name, col := range w1 {
		if col.Name() != name {
			t.Errorf("handle for %s is named %s", name, col.Name())
		}
	}
}

// TestClientOptionsCarryNoWriteConcern asserts the write concern moved off the
// client (#332): a client-level concern would be inherited by any handle or
// client bulkWrite that forgot to set its own.
func TestClientOptionsCarryNoWriteConcern(t *testing.T) {
	opts := mongoClientOptions(clientURIForTest)
	if opts.WriteConcern != nil {
		t.Errorf("client options carry write concern %+v; want none", opts.WriteConcern)
	}
}

const clientURIForTest = "mongodb://127.0.0.1:1"
