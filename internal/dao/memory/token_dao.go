package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

type TokenDAOMemory struct {
	mu     sync.RWMutex
	tokens map[string]*model.TokenRecord
}

func NewTokenDAO() interfaces.TokenDAO {
	return &TokenDAOMemory{
		tokens: make(map[string]*model.TokenRecord),
	}
}

func (d *TokenDAOMemory) Insert(ctx context.Context, record *model.TokenRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens[record.JTI] = record
	return nil
}

func (d *TokenDAOMemory) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	record, ok := d.tokens[jti]
	if !ok {
		return nil, errors.New("token not found")
	}
	return record, nil
}

func (d *TokenDAOMemory) Revoke(ctx context.Context, jti string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	record, ok := d.tokens[jti]
	if !ok {
		return errors.New("token not found")
	}
	record.RevokedAt = time.Now().UTC()
	return nil
}

func (d *TokenDAOMemory) RecordRedemption(ctx context.Context, jti string, ip string, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	record, ok := d.tokens[jti]
	if !ok {
		return errors.New("token not found")
	}
	record.RedemptionCount++
	record.LastRedemptionIP = ip
	record.LastRedemptionAt = at
	return nil
}

func (d *TokenDAOMemory) DeleteExpired(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	for jti, record := range d.tokens {
		if !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(now) {
			delete(d.tokens, jti)
		}
	}
	return nil
}

func (d *TokenDAOMemory) FindByProjectID(ctx context.Context, projectID string) ([]*model.TokenRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var results []*model.TokenRecord
	for _, record := range d.tokens {
		if record.ProjectID == projectID {
			results = append(results, record)
		}
	}
	return results, nil
}

func (d *TokenDAOMemory) FindByClientID(ctx context.Context, clientID string) ([]*model.TokenRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var results []*model.TokenRecord
	for _, record := range d.tokens {
		if record.ClientID == clientID {
			results = append(results, record)
		}
	}
	return results, nil
}

func (d *TokenDAOMemory) FindAll(ctx context.Context) ([]*model.TokenRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	results := make([]*model.TokenRecord, 0, len(d.tokens))
	for _, record := range d.tokens {
		results = append(results, record)
	}
	return results, nil
}
