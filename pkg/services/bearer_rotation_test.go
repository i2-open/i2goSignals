package services

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// rotateTestRig wires a StreamService against a real local AuthIssuer (so minted
// bearers validate against the local key) plus a TokenService that both tracks
// issuance and serves as the deferred-revoker for rotation.
type rotateTestRig struct {
	svc       *StreamService
	issuer    *authSupport.AuthIssuer
	tokenSvc  *TokenService
	streamDAO *memory.StreamDAOMemory
}

func newRotateRig(t *testing.T) *rotateTestRig {
	t.Helper()
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	tokenSvc := NewTokenService(memory.NewTokenDAO())
	keyService := NewKeyService(keyDAO, "http://tx.example", tokenSvc, nil)
	if err := keyService.InitializeTokenKey(context.Background(), "http://tx.example"); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	svc := NewStreamService(streamDAO, keyService, "http://tx.example", StreamServiceConfig{})
	baseUrl, _ := url.Parse("http://tx.example")
	svc.SetBaseUrl(baseUrl)
	return &rotateTestRig{
		svc:       svc,
		issuer:    keyService.GetAuthIssuer(),
		tokenSvc:  tokenSvc,
		streamDAO: streamDAO.(*memory.StreamDAOMemory),
	}
}

// createPollStream creates a poll-delivery stream and returns the SID and the
// minted (live) authorization header it carries.
func (rig *rotateTestRig) createPollStream(t *testing.T, projectID string) (sid string, bearer string) {
	t.Helper()
	req := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:             []string{"http://rx.example"},
			EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
			},
		},
	}
	cfg, err := rig.svc.CreateStream(context.Background(), req, projectID, nil)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if cfg.Delivery == nil || cfg.Delivery.PollTransmitMethod == nil {
		t.Fatalf("expected poll delivery, got %+v", cfg.Delivery)
	}
	return cfg.Id, cfg.Delivery.PollTransmitMethod.AuthorizationHeader
}

// eatFor parses the raw "Bearer <jwt>" header into the validated local EAT.
func (rig *rotateTestRig) eatFor(t *testing.T, header string) *authSupport.EventAuthToken {
	t.Helper()
	tok := strings.TrimPrefix(header, "Bearer ")
	eat, err := rig.issuer.ParseAuthToken(tok)
	if err != nil {
		t.Fatalf("ParseAuthToken: %v", err)
	}
	return eat
}

func bearerOf(rec *model.StreamStateRecord) string {
	if rec == nil || rec.Delivery == nil || rec.Delivery.PollTransmitMethod == nil {
		return ""
	}
	return rec.Delivery.PollTransmitMethod.AuthorizationHeader
}

// TestRotationFiresOnExactMatch covers ADR 0022 §1: presenting the stream's
// current bearer rotates it — a new bearer is persisted and returned, and it
// differs from the old.
func TestRotationFiresOnExactMatch(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")
	eat := rig.eatFor(t, live)

	rec, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, eat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if !didRotate {
		t.Fatal("expected rotation to fire on exact bearer match")
	}
	newBearer := bearerOf(rec)
	if newBearer == "" || newBearer == live {
		t.Errorf("expected a fresh bearer, got %q (old %q)", newBearer, live)
	}
	// Persisted: a fresh read carries the new bearer.
	stored, _ := rig.svc.GetStreamState(context.Background(), sid)
	if bearerOf(stored) != newBearer {
		t.Errorf("new bearer not persisted: stored %q want %q", bearerOf(stored), newBearer)
	}
}

// TestNoRotationForMgmtToken covers ADR 0022 §1: a management/admin caller (no
// matching bearer; empty-StreamIds wildcard EAT) never rotates.
func TestNoRotationForMgmtToken(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")

	// A management token: not the stream bearer, empty StreamIds (project-wide).
	mgmtEat := &authSupport.EventAuthToken{ProjectId: "proj-a", Roles: []string{authSupport.ScopeStreamMgmt}}
	rec, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, "Bearer some-mgmt-token", mgmtEat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if didRotate {
		t.Error("management token must not rotate")
	}
	if bearerOf(rec) != live {
		t.Errorf("bearer changed under a mgmt read: %q", bearerOf(rec))
	}
}

// TestNoRotationWhenDisabled covers ADR 0022 §4: with the gate off, even an
// exact bearer match does not rotate.
func TestNoRotationWhenDisabled(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "false")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")
	eat := rig.eatFor(t, live)

	rec, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, eat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if didRotate {
		t.Error("rotation must not fire when I2SIG_BEARER_ROTATE_ON_GET is off")
	}
	if bearerOf(rec) != live {
		t.Errorf("bearer changed while gate off: %q", bearerOf(rec))
	}
}

// TestStreamBindingGuard covers ADR 0022 §1 Guard B: a presented EAT whose
// StreamIds do NOT contain the stream being read must not rotate, even on a
// string match.
func TestStreamBindingGuard(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")

	// An EAT bound to a DIFFERENT stream id, even if the raw value matches.
	wrongEat := &authSupport.EventAuthToken{ProjectId: "proj-a", StreamIds: []string{"some-other-sid"}, Roles: []string{authSupport.ScopeEventDelivery}}
	_, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, wrongEat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if didRotate {
		t.Error("rotation must not fire when the EAT is bound to a different stream")
	}
}

// TestIssuerRoleGuard covers ADR 0022 §1 Guard A: a peer-supplied outbound
// credential this server did not mint never rotates, even on an exact string
// match. We simulate by storing a non-local bearer string and presenting it.
func TestIssuerRoleGuard(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")
	eat := rig.eatFor(t, live)

	// Overwrite the stored bearer with a foreign (non-locally-minted) value, but
	// keep the SAME (locally valid) EAT presented. The stored value does not parse
	// as a local token, so the issuer-role guard must veto rotation.
	stored, _ := rig.svc.GetStreamState(context.Background(), sid)
	stored.Delivery.PollTransmitMethod.AuthorizationHeader = "Bearer peer-supplied-opaque-token"
	if err := rig.streamDAO.Update(context.Background(), stored); err != nil {
		t.Fatalf("Update: %v", err)
	}

	_, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, "Bearer peer-supplied-opaque-token", eat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if didRotate {
		t.Error("rotation must not fire for a credential this server did not mint")
	}
}

// TestDeferredRevocationOldBearerValidInWindow covers ADR 0022 §2: after
// rotation the OLD bearer's token is future-revoked (still valid now), and a GET
// presenting the OLD bearer in the window returns the SAME current bearer
// without minting a third credential (idempotent re-read).
func TestDeferredRevocationOldBearerValidInWindow(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	t.Setenv("I2SIG_BEARER_ROTATE_GRACE", "1h")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")
	oldEat := rig.eatFor(t, live)

	// First GET with the live bearer rotates.
	rec1, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, oldEat, rig.tokenSvc)
	if err != nil || !didRotate {
		t.Fatalf("first rotation: didRotate=%v err=%v", didRotate, err)
	}
	newBearer := bearerOf(rec1)

	// Old bearer still validates during the grace window.
	revoked, err := rig.tokenSvc.IsRevoked(context.Background(), oldEat.ID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("old bearer should still be valid during the grace window")
	}

	// Re-read presenting the OLD bearer returns the SAME current bearer, revealed
	// live (lost-response recovery), without minting a third credential.
	rec2, reveal2, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, oldEat, rig.tokenSvc)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !reveal2 {
		t.Error("lost-response re-read must reveal the current live bearer")
	}
	if bearerOf(rec2) != newBearer {
		t.Errorf("re-read returned %q, want the current bearer %q", bearerOf(rec2), newBearer)
	}
	// No third credential minted: the stored bearer is still the one from the first rotation.
	stored, _ := rig.svc.GetStreamState(context.Background(), sid)
	if bearerOf(stored) != newBearer {
		t.Errorf("re-read minted a third credential: stored %q want %q", bearerOf(stored), newBearer)
	}
}

// TestSstpResponderBearerRotates covers ADR 0022 §1 uniform application to the
// SSTP responder side: presenting the responder's current server-minted pair
// bearer rotates SstpMethod.AuthorizationHeader, persists the new value, and
// defers revocation of the old. (Initiator-side self-rotation is out of scope.)
func TestSstpResponderBearerRotates(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")

	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	tokenSvc := NewTokenService(memory.NewTokenDAO())
	keyService := NewKeyService(keyDAO, "https://local.example", tokenSvc, nil)
	if err := keyService.InitializeTokenKey(context.Background(), "https://local.example"); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	svc := NewStreamService(streamDAO, keyService, "https://local.example", StreamServiceConfig{})
	baseUrl, _ := url.Parse("https://local.example")
	svc.SetBaseUrl(baseUrl)

	rec, err := svc.CreateSstpPair(context.Background(), responderBootstrap(), "proj-1", nil)
	if err != nil {
		t.Fatalf("CreateSstpPair: %v", err)
	}
	live := rec.SstpMethod.AuthorizationHeader
	if !strings.HasPrefix(live, "Bearer ") {
		t.Fatalf("expected a minted responder bearer, got %q", live)
	}

	// The pair bearer is bound to [txSid (== PairId), rxSid (inbound SID)].
	eat := keyService.GetAuthIssuer()
	parsed, err := eat.ParseAuthToken(strings.TrimPrefix(live, "Bearer "))
	if err != nil {
		t.Fatalf("ParseAuthToken: %v", err)
	}

	rotated, reveal, err := svc.RotateBearerOnGet(context.Background(), rec.PairId, live, parsed, tokenSvc)
	if err != nil {
		t.Fatalf("RotateBearerOnGet: %v", err)
	}
	if !reveal {
		t.Fatal("SSTP responder bearer should rotate (reveal live) on exact match")
	}
	if rotated.SstpMethod.AuthorizationHeader == live || rotated.SstpMethod.AuthorizationHeader == "" {
		t.Errorf("SSTP bearer not rotated: %q (old %q)", rotated.SstpMethod.AuthorizationHeader, live)
	}
	// Old responder pair token scheduled for deferred revocation.
	storedRec, _ := tokenSvc.FindByJTI(context.Background(), parsed.ID)
	if storedRec == nil || storedRec.RevokedAt.IsZero() {
		t.Error("old responder bearer should be scheduled for revocation")
	}
}

// TestImmediateRevocationGraceZero covers ADR 0022 §2: grace=0 revokes the old
// bearer at once.
func TestImmediateRevocationGraceZero(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	t.Setenv("I2SIG_BEARER_ROTATE_GRACE", "0")
	rig := newRotateRig(t)
	sid, live := rig.createPollStream(t, "proj-a")
	oldEat := rig.eatFor(t, live)

	_, didRotate, err := rig.svc.RotateBearerOnGet(context.Background(), sid, live, oldEat, rig.tokenSvc)
	if err != nil || !didRotate {
		t.Fatalf("rotation: didRotate=%v err=%v", didRotate, err)
	}
	revoked, err := rig.tokenSvc.IsRevoked(context.Background(), oldEat.ID)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("with grace=0 the old bearer must be revoked immediately")
	}
	// sanity: the revoked_at is at or before now
	if rec, _ := rig.tokenSvc.FindByJTI(context.Background(), oldEat.ID); rec != nil && rec.RevokedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("grace=0 should not future-date revoked_at: %v", rec.RevokedAt)
	}
}
