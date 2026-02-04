package memory

import (
	"context"
	"strings"
	"sync"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type KeyDAOMemory struct {
	mu   sync.RWMutex
	keys map[string][]*interfaces.JwkKeyRec // iss -> list of keys
}

func NewKeyDAO() interfaces.KeyDAO {
	return &KeyDAOMemory{
		keys: make(map[string][]*interfaces.JwkKeyRec),
	}
}

func (d *KeyDAOMemory) Insert(_ context.Context, keyRec *interfaces.JwkKeyRec) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if keyRec.Id.IsZero() {
		keyRec.Id = bson.NewObjectID()
	}

	d.keys[keyRec.Iss] = append(d.keys[keyRec.Iss], keyRec)
	return nil
}

func (d *KeyDAOMemory) FindByIssuer(_ context.Context, issuer string) ([]*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	recs, ok := d.keys[issuer]
	if !ok {
		return []*interfaces.JwkKeyRec{}, nil
	}

	// Return copies
	result := make([]*interfaces.JwkKeyRec, len(recs))
	for i, rec := range recs {
		keyRec := *rec
		result[i] = &keyRec
	}
	return result, nil
}

func (d *KeyDAOMemory) FindLatestByIssuer(_ context.Context, issuer string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	recs, ok := d.keys[issuer]
	if !ok || len(recs) == 0 {
		return nil, interfaces.ErrKeyNotFound
	}

	// Newest key is the last one in the slice
	rec := recs[len(recs)-1]
	if len(rec.KeyBytes) == 0 {
		return nil, interfaces.ErrKeyNotFound
	}

	keyRec := *rec
	return &keyRec, nil
}

func (d *KeyDAOMemory) DeleteByIssuer(_ context.Context, issuer string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.keys[issuer]; !ok {
		return interfaces.ErrKeyNotFound
	}

	delete(d.keys, issuer)
	return nil
}

func (d *KeyDAOMemory) ListIssuers(_ context.Context) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	issuers := make([]string, 0, len(d.keys))
	for iss := range d.keys {
		if !strings.HasPrefix(iss, "receiver_") {
			issuers = append(issuers, iss)
		}
	}

	return issuers, nil
}

func (d *KeyDAOMemory) InsertReceiverKey(_ context.Context, streamID string, audience string, jwksUri string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	keyPairRec := &interfaces.JwkKeyRec{
		Id:              bson.NewObjectID(),
		Aud:             audience,
		StreamId:        streamID,
		ReceiverJwksUrl: jwksUri,
	}

	key := "receiver_" + streamID
	d.keys[key] = append(d.keys[key], keyPairRec)
	return nil
}

func (d *KeyDAOMemory) FindReceiverKeyByStreamID(_ context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if recs, ok := d.keys["receiver_"+streamID]; ok && len(recs) > 0 {
		keyRec := *recs[len(recs)-1]
		return &keyRec, nil
	}
	return nil, nil
}

func (d *KeyDAOMemory) GetState() map[string][]*interfaces.JwkKeyRec {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make(map[string][]*interfaces.JwkKeyRec)
	for k, v := range d.keys {
		recs := make([]*interfaces.JwkKeyRec, len(v))
		for i, r := range v {
			copyRec := *r
			recs[i] = &copyRec
		}
		res[k] = recs
	}
	return res
}

func (d *KeyDAOMemory) SetState(state map[string][]*interfaces.JwkKeyRec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = state
}
