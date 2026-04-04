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

func (s *TokenService) TrackToken(ctx context.Context, claims *authSupport.EventAuthToken, tokenPurpose string) error {
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
	}
	return s.dao.Insert(ctx, record)
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
	}, nil
}

func (s *TokenService) ListByProject(ctx context.Context, projectID string) ([]*model.TokenRecord, error) {
	return s.dao.FindByProjectID(ctx, projectID)
}

func (s *TokenService) ListByClient(ctx context.Context, clientID string) ([]*model.TokenRecord, error) {
	return s.dao.FindByClientID(ctx, clientID)
}
