package services

import (
	"context"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var tokenLog = logger.Sub("TOKEN_SVC")

// tokenListCap bounds the caller-scoped list to avoid unbounded responses.
// There is no pagination in this slice; if the cap is hit, the overflow is
// dropped and logged (cap-and-log, never a silent truncation).
const tokenListCap = 1000

type TokenService struct {
	dao       interfaces.TokenDAO
	streamDAO interfaces.StreamDAO
}

func NewTokenService(dao interfaces.TokenDAO) *TokenService {
	return &TokenService{dao: dao}
}

// SetStreamDAO supplies the stream store used to join the last-seen IP onto
// STREAM-typed token rows. When unset, stream rows simply omit LastSeenIP.
func (s *TokenService) SetStreamDAO(dao interfaces.StreamDAO) {
	s.streamDAO = dao
}

// TokenListFilters are the optional, composable filters for the caller-scoped
// token list. An empty filter matches everything in scope.
type TokenListFilters struct {
	// Type filters by token purpose (model.TokenTypeIAT or TokenTypeStream).
	// Empty means all types.
	Type string
	// Active, when set, filters by liveness: true keeps non-revoked,
	// non-expired tokens; false keeps revoked-or-expired tokens.
	Active *bool
}

// ProjectScope derives the project visibility for a caller from its
// AuthContext, never from a client-supplied query parameter. admin/root
// callers are unrestricted (see all projects); every other caller is confined
// to its own AuthContext.ProjectId. This is the shared scoping derivation that
// the single-token endpoints (revoke/introspect) reuse.
//
// Returns (unrestricted, confinedProjectID).
func ProjectScope(authCtx *authSupport.EventAuthToken) (bool, string) {
	if authCtx == nil {
		return false, ""
	}
	if authCtx.IsScopeMatch([]string{authSupport.ScopeRoot, authSupport.ScopeStreamAdmin}) {
		return true, ""
	}
	return false, authCtx.ProjectId
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

	// For STREAM-typed tokens, capture the stream id (join key) so the list
	// endpoint can later read the stream's live RemoteAddress. The IP itself is
	// never copied onto the token record.
	streamID := ""
	if tokenPurpose == model.TokenTypeStream && len(claims.StreamIds) > 0 {
		streamID = claims.StreamIds[0]
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
		StreamID:  streamID,
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

// FindByJTI returns the tracked token record for a JTI, or (nil, nil) when no
// record is tracked. It is used by the single-token project guard to read the
// target token's project before authorizing a revoke/introspect. A
// not-found-by-JTI is a non-error (nil record) so callers can apply RFC 7009
// always-200 semantics without leaking existence.
func (s *TokenService) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
	record, err := s.dao.FindByJTI(ctx, jti)
	if err != nil {
		if err.Error() == "token not found" {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
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

// ListForAuthority returns an enriched, caller-scoped token inventory. Project
// scope is derived from the AuthContext (admin/root see all; others see only
// their own project) via ProjectScope — never from a client-supplied query
// param. The type and active filters compose. STREAM-typed rows are joined to
// the stream's live RemoteAddress (last-seen IP); the IP is not stored on the
// token. The result is capped (cap-and-log) since there is no pagination here.
func (s *TokenService) ListForAuthority(ctx context.Context, authCtx *authSupport.EventAuthToken, filters TokenListFilters) ([]*model.TokenListEntry, error) {
	unrestricted, projectID := ProjectScope(authCtx)

	var records []*model.TokenRecord
	var err error
	if unrestricted {
		records, err = s.dao.FindAll(ctx)
	} else {
		records, err = s.dao.FindByProjectID(ctx, projectID)
	}
	if err != nil {
		return nil, err
	}

	ipByStream := s.streamIPIndex(ctx, unrestricted, projectID)

	entries := make([]*model.TokenListEntry, 0, len(records))
	for _, rec := range records {
		if !matchesFilters(rec, filters) {
			continue
		}
		entry := &model.TokenListEntry{TokenRecord: rec}
		if rec.Type == model.TokenTypeStream && rec.StreamID != "" {
			entry.LastSeenIP = ipByStream[rec.StreamID]
		}
		entries = append(entries, entry)
		if len(entries) >= tokenListCap {
			break
		}
	}

	if len(records) > len(entries) && len(entries) >= tokenListCap {
		tokenLog.Warn("Token list capped; results truncated (no pagination)",
			"cap", tokenListCap, "matched_or_more", len(records), "returned", len(entries))
	}

	return entries, nil
}

// streamIPIndex builds a stream-id -> last-seen-IP lookup for the streams in
// scope. Returns an empty map when no stream store is wired.
func (s *TokenService) streamIPIndex(ctx context.Context, unrestricted bool, projectID string) map[string]string {
	index := map[string]string{}
	if s.streamDAO == nil {
		return index
	}
	var streams []model.StreamStateRecord
	var err error
	if unrestricted {
		streams, err = s.streamDAO.List(ctx)
	} else {
		streams, err = s.streamDAO.FindByProjectID(ctx, projectID)
	}
	if err != nil {
		tokenLog.Warn("Could not load streams for last-seen IP join", "error", err)
		return index
	}
	for i := range streams {
		st := streams[i]
		if st.RemoteAddress != nil && st.RemoteAddress.IP != "" {
			index[st.StreamConfiguration.Id] = st.RemoteAddress.IP
		}
	}
	return index
}

// matchesFilters reports whether a record satisfies the (composed) filters.
func matchesFilters(rec *model.TokenRecord, filters TokenListFilters) bool {
	if filters.Type != "" && rec.Type != filters.Type {
		return false
	}
	if filters.Active != nil {
		active := rec.RevokedAt.IsZero() && (rec.ExpiresAt.IsZero() || rec.ExpiresAt.After(time.Now()))
		if active != *filters.Active {
			return false
		}
	}
	return true
}
