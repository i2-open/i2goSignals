package services

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type TokenServiceTestSuite struct {
	suite.Suite
	service *TokenService
}

func (s *TokenServiceTestSuite) SetupTest() {
	dao := memory.NewTokenDAO()
	s.service = NewTokenService(dao)
}

func (s *TokenServiceTestSuite) TestTokenLifecycle() {
	ctx := context.Background()
	jti := "test-jti"
	claims := &authSupport.EventAuthToken{
		ProjectId: "test-project",
		ClientId:  "test-client",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// 1. Track
	err := s.service.TrackToken(ctx, claims, "", model.TokenTypeStream)
	s.NoError(err)

	// 2. IsRevoked (should be false)
	revoked, err := s.service.IsRevoked(ctx, jti)
	s.NoError(err)
	s.False(revoked)

	// 3. Introspect (should be active)
	resp, err := s.service.IntrospectToken(ctx, jti)
	s.NoError(err)
	s.True(resp.Active)
	s.Equal(jti, resp.Jti)
	s.Equal("test-project", resp.ProjectID)
	s.Equal("test-client", resp.ClientID)

	// 4. Revoke
	err = s.service.RevokeToken(ctx, jti)
	s.NoError(err)

	// 5. IsRevoked (should be true)
	revoked, err = s.service.IsRevoked(ctx, jti)
	s.NoError(err)
	s.True(revoked)

	// 6. Introspect (should be inactive)
	resp, err = s.service.IntrospectToken(ctx, jti)
	s.NoError(err)
	s.False(resp.Active)
}

func (s *TokenServiceTestSuite) TestListByProjectAndClient() {
	ctx := context.Background()

	_ = s.service.TrackToken(ctx, &authSupport.EventAuthToken{
		ProjectId:        "p1",
		ClientId:         "c1",
		RegisteredClaims: jwt.RegisteredClaims{ID: "j1"},
	}, "", model.TokenTypeStream)
	_ = s.service.TrackToken(ctx, &authSupport.EventAuthToken{
		ProjectId:        "p1",
		ClientId:         "c2",
		RegisteredClaims: jwt.RegisteredClaims{ID: "j2"},
	}, "", model.TokenTypeStream)
	_ = s.service.TrackToken(ctx, &authSupport.EventAuthToken{
		ProjectId:        "p2",
		ClientId:         "c1",
		RegisteredClaims: jwt.RegisteredClaims{ID: "j3"},
	}, "", model.TokenTypeStream)

	// List by Project p1
	tokens, err := s.service.ListByProject(ctx, "p1")
	s.NoError(err)
	s.Len(tokens, 2)

	// List by Client c1
	tokens, err = s.service.ListByClient(ctx, "c1")
	s.NoError(err)
	s.Len(tokens, 2)
}

func (s *TokenServiceTestSuite) TestRecordRedemption() {
	ctx := context.Background()
	jti := "iat-redeem"
	err := s.service.TrackToken(ctx, &authSupport.EventAuthToken{
		ProjectId:        "p1",
		RegisteredClaims: jwt.RegisteredClaims{ID: jti},
	}, "", model.TokenTypeIAT)
	s.NoError(err)

	at := time.Now().UTC()
	err = s.service.RecordRedemption(ctx, jti, "192.0.2.10", at)
	s.NoError(err)

	rec, err := s.service.dao.FindByJTI(ctx, jti)
	s.NoError(err)
	s.Equal(int64(1), rec.RedemptionCount)
	s.Equal("192.0.2.10", rec.LastRedemptionIP)
	s.WithinDuration(at, rec.LastRedemptionAt, time.Second)
}

func TestTokenServiceSuite(t *testing.T) {
	suite.Run(t, new(TokenServiceTestSuite))
}
