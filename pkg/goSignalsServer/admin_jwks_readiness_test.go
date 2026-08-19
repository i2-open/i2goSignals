// Package goSignalsServer_test — see admin_surface_test.go for why this is an
// EXTERNAL test package. This file covers the ADR 0033 readiness overlay on the
// admin stream-state routes (ADR 0027).
package goSignalsServer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSignalsServer"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// unreachableJwksUrl is a port nothing listens on, so resolving it fails with
// "connection refused" — the transient class GH #264 is about.
const unreachableJwksUrl = "http://127.0.0.1:1/jwks.json"

// readinessFixture builds the admin surface over in-memory DAOs and hands back
// the StreamService so a test can drive the receiver cache directly.
type readinessAdminFixture struct {
	surface       *goSignalsServer.AdminSurface
	streamService *services.StreamService
	streamDAO     dao.StreamDAO
	auth          *authSupport.AuthIssuer
}

func newReadinessAdminFixture(t *testing.T) *readinessAdminFixture {
	t.Helper()
	ctx := context.Background()

	keyService := services.NewKeyService(memory.NewKeyDAO(), testDefaultIssuer, nil, nil)
	if err := keyService.InitializeTokenKey(ctx, testDefaultIssuer); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	streamDAO := memory.NewStreamDAO()
	streamService := services.NewStreamService(streamDAO, keyService, testDefaultIssuer, services.StreamServiceConfig{})
	base, _ := url.Parse("https://gateway.example")

	surface := goSignalsServer.NewAdminSurface(goSignalsServer.AdminSurfaceConfig{
		StreamService:        streamService,
		KeyService:           keyService,
		ServerService:        services.NewServerService(memory.NewServerDAO()),
		TokenService:         services.NewTokenService(memory.NewTokenDAO()),
		SubjectFilterService: services.NewSubjectFilterService(memory.NewSubjectFilterDAO()),
		Auth:                 keyService.GetAuthIssuer(),
		DefaultIssuer:        testDefaultIssuer,
		BaseURL:              base,
		Sink:                 &recordingSink{},
	})

	return &readinessAdminFixture{
		surface:       surface,
		streamService: streamService,
		streamDAO:     streamDAO,
		auth:          keyService.GetAuthIssuer(),
	}
}

func (f *readinessAdminFixture) bearer(t *testing.T, projectId string) string {
	t.Helper()
	client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{projectId}}
	tok, err := f.auth.IssueStreamClientToken(client, projectId, true, "")
	if err != nil {
		t.Fatalf("IssueStreamClientToken: %v", err)
	}
	return tok
}

// receiverRecord is a ReceivePush receiver stream with an explicit issuer JWKS
// URL — the shape that "expects verification material" (ADR 0033).
func receiverRecord(projectId, jwksUrl string) *model.StreamStateRecord {
	id := bson.NewObjectID()
	return &model.StreamStateRecord{
		Id:        id,
		ProjectId: projectId,
		StreamConfiguration: model.StreamConfiguration{
			Id:            id.Hex(),
			Iss:           "https://tx.example",
			IssuerJWKSUrl: jwksUrl,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
		Status: model.StreamStateEnabled,
	}
}

// TestAdminStreamState_OverlaysJwksReadiness is the operator-visibility half of
// GH #264. A stream whose issuer JWKS endpoint is unreachable keeps reporting
// status "enabled" — ADR 0033 deliberately keeps stream Status out of it, and
// the SSF-defined status response gains nothing — so readiness has to reach the
// operator somewhere else. The admin stream-state routes (ADR 0027) are that
// place, and they source their records from the DAO and never consult the
// receiver cache: without an explicit overlay the field is always absent.
func TestAdminStreamState_OverlaysJwksReadiness(t *testing.T) {
	const projectId = "proj-readiness"
	f := newReadinessAdminFixture(t)
	ctx := context.Background()

	rec := receiverRecord(projectId, unreachableJwksUrl)
	if err := f.streamDAO.Create(ctx, rec); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	sid := rec.StreamConfiguration.Id

	// Populate the receiver cache the way a startup preload would, against a
	// JWKS endpoint that refuses connections.
	f.streamService.LoadReceiverStreams(ctx)
	if jwks := f.streamService.GetIssuerJwksForReceiver(ctx, sid); jwks != nil {
		t.Fatal("precondition: the unreachable endpoint must leave the direction unresolved")
	}

	router := mountAdmin(f.surface)

	t.Run("GET /states", func(t *testing.T) {
		rr := doJSON(t, router, http.MethodGet, "/states", f.bearer(t, projectId), nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		var states []model.StreamStateRecord
		if err := json.Unmarshal(rr.Body.Bytes(), &states); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *model.StreamStateRecord
		for i := range states {
			if states[i].StreamConfiguration.Id == sid {
				found = &states[i]
			}
		}
		if found == nil {
			t.Fatalf("stream %s missing from /states: %s", sid, rr.Body.String())
		}
		if found.Status != model.StreamStateEnabled {
			t.Errorf("status = %q; ADR 0033 keeps Status out of this — it must stay enabled", found.Status)
		}
		if found.JwksReadiness == nil {
			t.Fatal("/states must overlay node-local JWKS readiness (ADR 0033); it sources records from the DAO, which never carries it")
		}
		if found.JwksReadiness.State != model.JwksReadinessUnresolved {
			t.Errorf("readiness = %q, want %q", found.JwksReadiness.State, model.JwksReadinessUnresolved)
		}
		if found.JwksReadiness.LastError == "" {
			t.Error("an unresolved direction must carry the last error")
		}
		if found.JwksReadiness.NextRetryAt == nil {
			t.Error("an unresolved direction must publish when the next retry is due")
		}
	})

	t.Run("GET /state", func(t *testing.T) {
		rr := doJSON(t, router, http.MethodGet, "/state?stream_id="+sid, f.bearer(t, projectId), nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		var state model.StreamStateRecord
		if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if state.JwksReadiness == nil {
			t.Fatal("/state must overlay node-local JWKS readiness (ADR 0033)")
		}
		if state.JwksReadiness.State != model.JwksReadinessUnresolved {
			t.Errorf("readiness = %q, want %q", state.JwksReadiness.State, model.JwksReadinessUnresolved)
		}
	})
}

// TestAdminStreamState_NotConfiguredReadiness: a receive direction with no
// issuer JWKS URL is a valid resting state, not a fault. It must report
// not-configured so an operator is not sent chasing a non-existent outage.
func TestAdminStreamState_NotConfiguredReadiness(t *testing.T) {
	const projectId = "proj-not-configured"
	f := newReadinessAdminFixture(t)
	ctx := context.Background()

	rec := receiverRecord(projectId, "")
	rec.StreamConfiguration.Iss = testDefaultIssuer
	if err := f.streamDAO.Create(ctx, rec); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	f.streamService.GetIssuerJwksForReceiver(ctx, rec.StreamConfiguration.Id)

	router := mountAdmin(f.surface)
	rr := doJSON(t, router, http.MethodGet, "/state?stream_id="+rec.StreamConfiguration.Id, f.bearer(t, projectId), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	var state model.StreamStateRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if state.JwksReadiness == nil {
		t.Fatal("/state must overlay readiness for every receive direction")
	}
	if state.JwksReadiness.State != model.JwksReadinessNotConfigured {
		t.Errorf("readiness = %q, want %q", state.JwksReadiness.State, model.JwksReadinessNotConfigured)
	}
}
