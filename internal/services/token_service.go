package services

import (
	"context"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

type TokenService struct {
	dao interfaces.TokenDAO
}

func NewTokenService(dao interfaces.TokenDAO) *TokenService {
	return &TokenService{dao: dao}
}

func (s *TokenService) TrackToken(ctx context.Context, claims *authSupport.EventAuthToken, parent string, tokenPurpose string) error {
	iat := time.Now()
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Time
	}
	exp := time.Time{}
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}

	record := &model.TokenRecord{
		JTI:       claims.ID,
		ClientID:  claims.ClientId,
		Subject:   claims.Subject,
		ProjectID: claims.ProjectId,
		Type:      tokenPurpose,
		Scopes:    claims.Roles,
		IssuedAt:  iat,
		ExpiresAt: exp,
		Parent:    parent,
	}
	return s.dao.Insert(ctx, record)
}

// RecordRedemption captures a token redemption (ADR 0007): it bumps the
// redemption count and records the last-redemption IP and time.
func (s *TokenService) RecordRedemption(ctx context.Context, jti string, ip string, at time.Time) error {
	return s.dao.RecordRedemption(ctx, jti, ip, at)
}

func (s *TokenService) IsRevoked(ctx context.Context, jti string) (bool, error) {
	record, err := s.dao.FindByJTI(ctx, jti)
	if err != nil {
		if err.Error() == "token not found" {
			return false, nil // Not found means not tracked or already expired/deleted
		}
		return false, err
	}
	return !record.RevokedAt.IsZero(), nil
}

func (s *TokenService) RevokeToken(ctx context.Context, jti string) error {
	return s.dao.Revoke(ctx, jti)
}

func (s *TokenService) IntrospectToken(ctx context.Context, jti string) (*model.IntrospectionResponse, error) {
	record, err := s.dao.FindByJTI(ctx, jti)
	if err != nil {
		if err.Error() == "token not found" {
			return &model.IntrospectionResponse{Active: false}, nil
		}
		return nil, err
	}
	scope := ""
	if record.Scopes != nil {
		scope = strings.Join(record.Scopes, ",")
	}

	active := record.RevokedAt.IsZero() && (record.ExpiresAt.IsZero() || record.ExpiresAt.After(time.Now()))

	return &model.IntrospectionResponse{
		Active:    active,
		ClientID:  record.ClientID,
		Subject:   record.Subject,
		Type:      record.Type,
		Scope:     scope,
		ProjectID: record.ProjectID,
		Exp:       record.ExpiresAt.Unix(),
		Iat:       record.IssuedAt.Unix(),
		Jti:       record.JTI,

		Parent:           record.Parent,
		LastRedemptionIP: record.LastRedemptionIP,
		RedemptionCount:  record.RedemptionCount,
		LastRedemptionAt: redemptionUnix(record.LastRedemptionAt),
	}, nil
}

// redemptionUnix returns the Unix timestamp for t, or 0 when t is the zero
// time, so a never-redeemed token reports 0 (and is omitted) rather than a
// large negative epoch.
func redemptionUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s *TokenService) ListByProject(ctx context.Context, projectID string) ([]*model.TokenRecord, error) {
	return s.dao.FindByProjectID(ctx, projectID)
}

func (s *TokenService) ListByClient(ctx context.Context, clientID string) ([]*model.TokenRecord, error) {
	return s.dao.FindByClientID(ctx, clientID)
}
