package memory

import (
	"context"
	"sync"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// KeyDAOMemory uses a simpler mutex-based approach because it stores
// slices of keys per keyName, which doesn't fit well with StateManager
type KeyDAOMemory struct {
	mu   sync.RWMutex
	keys map[string]*interfaces.JwkKeyRec // kid -> key
}

func NewKeyDAO() interfaces.KeyDAO {
	return &KeyDAOMemory{
		keys: make(map[string]*interfaces.JwkKeyRec),
	}
}

func (d *KeyDAOMemory) Insert(_ context.Context, keyRec *interfaces.JwkKeyRec) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if keyRec.Id.IsZero() {
		keyRec.Id = bson.NewObjectID()
	}

	if keyRec.Kid == "" {
		if keyRec.KeyName != "" {
			keyRec.Kid = keyRec.KeyName
		} else {
			keyRec.Kid = keyRec.Id.Hex()
		}
	}

	d.keys[keyRec.Kid] = keyRec
	return nil
}

func (d *KeyDAOMemory) FindByKid(_ context.Context, kid string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rec, ok := d.keys[kid]
	if !ok {
		return nil, interfaces.ErrKeyNotFound
	}

	keyRec := *rec
	return &keyRec, nil
}

func (d *KeyDAOMemory) FindByKeyName(_ context.Context, keyName string) ([]*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*interfaces.JwkKeyRec
	for _, rec := range d.keys {
		if rec.KeyName == keyName {
			keyRec := *rec
			result = append(result, &keyRec)
		}
	}
	return result, nil
}

func (d *KeyDAOMemory) FindLatestByKeyName(_ context.Context, keyName string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var latest *interfaces.JwkKeyRec
	for _, rec := range d.keys {
		if rec.KeyName == keyName {
			if latest == nil || rec.Id.Hex() > latest.Id.Hex() {
				latest = rec
			}
		}
	}

	if latest == nil {
		return nil, interfaces.ErrKeyNotFound
	}

	keyRec := *latest
	return &keyRec, nil
}

func (d *KeyDAOMemory) FindByStreamID(_ context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, rec := range d.keys {
		if rec.StreamId == streamID {
			keyRec := *rec
			return &keyRec, nil
		}
	}
	return nil, nil
}

func (d *KeyDAOMemory) DeleteByKid(_ context.Context, kid string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.keys[kid]; !ok {
		return interfaces.ErrKeyNotFound
	}

	delete(d.keys, kid)
	return nil
}

func (d *KeyDAOMemory) DeleteByKeyName(_ context.Context, keyName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	deleted := false
	for kid, rec := range d.keys {
		if rec.KeyName == keyName {
			delete(d.keys, kid)
			deleted = true
		}
	}

	if !deleted {
		return interfaces.ErrKeyNotFound
	}
	return nil
}

func (d *KeyDAOMemory) ListKids(_ context.Context) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	kids := make([]string, 0, len(d.keys))
	for kid := range d.keys {
		kids = append(kids, kid)
	}

	return kids, nil
}

func (d *KeyDAOMemory) ListKeyNames(_ context.Context) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	namesMap := make(map[string]struct{})
	for _, rec := range d.keys {
		if rec.KeyName != "" {
			namesMap[rec.KeyName] = struct{}{}
		}
	}

	names := make([]string, 0, len(namesMap))
	for name := range namesMap {
		names = append(names, name)
	}

	return names, nil
}

func (d *KeyDAOMemory) KeySummary(ctx context.Context, kid string) (*interfaces.KeySummary, error) {
	rec, err := d.FindByKid(ctx, kid)
	if err != nil {
		return nil, err
	}
	summary := rec.ToSummary()
	return &summary, nil
}

func (d *KeyDAOMemory) ListSummaries(_ context.Context) ([]interfaces.KeySummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	summaries := make([]interfaces.KeySummary, 0, len(d.keys))
	for _, rec := range d.keys {
		summaries = append(summaries, rec.ToSummary())
	}
	return summaries, nil
}

func (d *KeyDAOMemory) GetState() map[string]*interfaces.JwkKeyRec {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make(map[string]*interfaces.JwkKeyRec)
	for k, v := range d.keys {
		copyRec := *v
		res[k] = &copyRec
	}
	return res
}

func (d *KeyDAOMemory) SetState(state map[string]*interfaces.JwkKeyRec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = state
}
