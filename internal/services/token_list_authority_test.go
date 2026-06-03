package services

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type TokenListAuthorityTestSuite struct {
	suite.Suite
	service   *TokenService
	streamDAO interfaces.StreamDAO
}

func (s *TokenListAuthorityTestSuite) SetupTest() {
	tokenDAO := memory.NewTokenDAO()
	streamDAO := memory.NewStreamDAO()
	s.service = NewTokenService(tokenDAO)
	s.service.SetStreamDAO(streamDAO)
	s.streamDAO = streamDAO
}

func (s *TokenListAuthorityTestSuite) track(jti, projectID, clientID, tokenType, streamID string) {
	claims := &authSupport.EventAuthToken{
		ProjectId: projectID,
		ClientId:  clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	if streamID != "" {
		claims.StreamIds = []string{streamID}
	}
	s.NoError(s.service.TrackToken(context.Background(), claims, "", tokenType))
}

func (s *TokenListAuthorityTestSuite) seedStream(hexID, projectID, ip string) {
	oid, err := bson.ObjectIDFromHex(hexID)
	s.NoError(err)
	rec := &model.StreamStateRecord{
		Id:        oid,
		ProjectId: projectID,
		RemoteAddress: &model.RemoteIP{
			IP:       ip,
			Protocol: "https",
		},
	}
	rec.StreamConfiguration.Id = hexID
	s.NoError(s.streamDAO.Create(context.Background(), rec))
}

// nonAdmin builds a locally-issued, project-confined caller (stream scope).
func nonAdmin(projectID string) *authUtil.AuthContext {
	return localScoped(projectID, authSupport.ScopeStreamMgmt)
}

// localScoped builds a locally-issued caller (an EAT) with the given roles.
func localScoped(projectID string, roles ...string) *authUtil.AuthContext {
	return &authUtil.AuthContext{
		ProjectId: projectID,
		Eat:       &authSupport.EventAuthToken{ProjectId: projectID, Roles: roles},
	}
}

// oauthScoped builds an OAuth/STS-validated caller. Such callers carry no local
// EAT or ProjectId — their authority is only the scope set granted by the
// trusted authorization server (issue #144).
func oauthScoped(grantedScopes ...string) *authUtil.AuthContext {
	return &authUtil.AuthContext{
		IsOAuthClient: true,
		GrantedScopes: grantedScopes,
	}
}

func (s *TokenListAuthorityTestSuite) TestNonAdminSeesOnlyOwnProject() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p2", "c2", model.TokenTypeIAT, "")

	rows, err := s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 1)
	s.Equal("p1", rows[0].ProjectID)
}

func (s *TokenListAuthorityTestSuite) TestAdminSeesAllProjects() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p2", "c2", model.TokenTypeIAT, "")

	admin := localScoped("p1", authSupport.ScopeStreamAdmin)
	rows, err := s.service.ListForAuthority(ctx, admin, TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 2)
}

func (s *TokenListAuthorityTestSuite) TestRootSeesAllProjects() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p2", "c2", model.TokenTypeIAT, "")

	root := localScoped("", authSupport.ScopeRoot)
	rows, err := s.service.ListForAuthority(ctx, root, TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 2)
}

// TestOAuthAdminSeesAllProjects is the regression test for the PRD-128 bug: an
// admin token obtained via STS/OAuth exchange validates through the OAuth path,
// which carries no local EAT or ProjectId. It must still be treated as
// unrestricted (see all projects) on the strength of its granted "admin" scope.
func (s *TokenListAuthorityTestSuite) TestOAuthAdminSeesAllProjects() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p2", "c2", model.TokenTypeIAT, "")

	rows, err := s.service.ListForAuthority(ctx, oauthScoped(authSupport.ScopeStreamAdmin), TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 2)
}

// TestOAuthNonAdminSeesNothing: an OAuth caller without admin scope carries no
// ProjectId, so it must fail closed (see nothing) rather than leak the
// empty-project bucket.
func (s *TokenListAuthorityTestSuite) TestOAuthNonAdminSeesNothing() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")

	rows, err := s.service.ListForAuthority(ctx, oauthScoped(authSupport.ScopeStreamMgmt), TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 0)
}

// TestOAuthForeignRootDoesNotSeeAll guards issue #144: a foreign realm role
// literally named "root" must NOT confer the cluster super-power. Only an
// "admin" grant unlocks the unrestricted view for OAuth callers.
func (s *TokenListAuthorityTestSuite) TestOAuthForeignRootDoesNotSeeAll() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p2", "c2", model.TokenTypeIAT, "")

	rows, err := s.service.ListForAuthority(ctx, oauthScoped(authSupport.ScopeRoot), TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 0)
}

func (s *TokenListAuthorityTestSuite) TestTypeFilter() {
	ctx := context.Background()
	s.track("j1", "p1", "c1", model.TokenTypeIAT, "")
	s.track("j2", "p1", "c1", model.TokenTypeStream, "")

	iat := model.TokenTypeIAT
	rows, err := s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{Type: iat})
	s.NoError(err)
	s.Len(rows, 1)
	s.Equal("j1", rows[0].JTI)
}

func (s *TokenListAuthorityTestSuite) TestActiveFilter() {
	ctx := context.Background()
	s.track("active", "p1", "c1", model.TokenTypeIAT, "")
	s.track("revoked", "p1", "c1", model.TokenTypeIAT, "")
	s.NoError(s.service.RevokeToken(ctx, "revoked"))

	yes := true
	rows, err := s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{Active: &yes})
	s.NoError(err)
	s.Len(rows, 1)
	s.Equal("active", rows[0].JTI)

	no := false
	rows, err = s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{Active: &no})
	s.NoError(err)
	s.Len(rows, 1)
	s.Equal("revoked", rows[0].JTI)
}

func (s *TokenListAuthorityTestSuite) TestFiltersCompose() {
	ctx := context.Background()
	s.track("iat-active", "p1", "c1", model.TokenTypeIAT, "")
	s.track("stream-active", "p1", "c1", model.TokenTypeStream, "")
	s.track("iat-revoked", "p1", "c1", model.TokenTypeIAT, "")
	s.NoError(s.service.RevokeToken(ctx, "iat-revoked"))

	yes := true
	rows, err := s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{Type: model.TokenTypeIAT, Active: &yes})
	s.NoError(err)
	s.Len(rows, 1)
	s.Equal("iat-active", rows[0].JTI)
}

func (s *TokenListAuthorityTestSuite) TestStreamRowJoinsLastSeenIP() {
	ctx := context.Background()
	hexID := bson.NewObjectID().Hex()
	s.seedStream(hexID, "p1", "203.0.113.7")
	s.track("stream-tok", "p1", "c1", model.TokenTypeStream, hexID)
	s.track("iat-tok", "p1", "c1", model.TokenTypeIAT, "")

	rows, err := s.service.ListForAuthority(ctx, nonAdmin("p1"), TokenListFilters{})
	s.NoError(err)
	s.Len(rows, 2)

	byJTI := map[string]*model.TokenListEntry{}
	for _, r := range rows {
		byJTI[r.JTI] = r
	}
	s.Equal("203.0.113.7", byJTI["stream-tok"].LastSeenIP, "stream row should join the stream's last-seen IP")
	s.Equal("", byJTI["iat-tok"].LastSeenIP, "IAT row should have no joined IP")
}

func TestTokenListAuthoritySuite(t *testing.T) {
	suite.Run(t, new(TokenListAuthorityTestSuite))
}

// TestProjectScope locks the single source of truth for caller visibility,
// covering both the locally-issued (EAT) and OAuth/STS (granted-scope) paths.
func TestProjectScope(t *testing.T) {
	cases := []struct {
		name             string
		authCtx          *authUtil.AuthContext
		wantUnrestricted bool
		wantProjectID    string
	}{
		{"nil", nil, false, ""},
		{"local admin", localScoped("p1", authSupport.ScopeStreamAdmin), true, ""},
		{"local root", localScoped("", authSupport.ScopeRoot), true, ""},
		{"local stream confined", localScoped("p1", authSupport.ScopeStreamMgmt), false, "p1"},
		{"oauth admin", oauthScoped(authSupport.ScopeStreamAdmin), true, ""},
		{"oauth stream", oauthScoped(authSupport.ScopeStreamMgmt), false, ""},
		{"oauth foreign root (#144)", oauthScoped(authSupport.ScopeRoot), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			unrestricted, projectID := ProjectScope(c.authCtx)
			if unrestricted != c.wantUnrestricted || projectID != c.wantProjectID {
				t.Fatalf("ProjectScope() = (%v, %q), want (%v, %q)",
					unrestricted, projectID, c.wantUnrestricted, c.wantProjectID)
			}
		})
	}
}
