package memory

import (
	"context"
	"errors"
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

func (d *KeyDAOMemory) Insert(ctx context.Context, keyRec *interfaces.JwkKeyRec) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if keyRec.Id.IsZero() {
		keyRec.Id = bson.NewObjectID()
	}

	d.keys[keyRec.Iss] = append(d.keys[keyRec.Iss], keyRec)
	return nil
}

func (d *KeyDAOMemory) FindByIssuer(ctx context.Context, issuer string) ([]*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	recs, ok := d.keys[issuer]
	if !ok {
		return []*interfaces.JwkKeyRec{}, nil
	}

	// Return copies
	result := make([]*interfaces.JwkKeyRec, len(recs))
	for i, rec := range recs {
		copy := *rec
		result[i] = &copy
	}
	return result, nil
}

func (d *KeyDAOMemory) FindLatestByIssuer(ctx context.Context, issuer string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	recs, ok := d.keys[issuer]
	if !ok || len(recs) == 0 {
		return nil, errors.New("no key found for: " + issuer)
	}

	// Newest key is the last one in the slice
	rec := recs[len(recs)-1]
	if len(rec.KeyBytes) == 0 {
		return nil, errors.New("no key found for: " + issuer)
	}

	copy := *rec
	return &copy, nil
}

func (d *KeyDAOMemory) DeleteByIssuer(ctx context.Context, issuer string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.keys[issuer]; !ok {
		return errors.New("issuer not found")
	}

	delete(d.keys, issuer)
	return nil
}

func (d *KeyDAOMemory) ListIssuers(ctx context.Context) ([]string, error) {
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

func (d *KeyDAOMemory) InsertReceiverKey(ctx context.Context, streamID string, audience string, jwksUri string) error {
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

func (d *KeyDAOMemory) FindReceiverKeyByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if recs, ok := d.keys["receiver_"+streamID]; ok && len(recs) > 0 {
		copy := *recs[len(recs)-1]
		return &copy, nil
	}
	return nil, nil
}
