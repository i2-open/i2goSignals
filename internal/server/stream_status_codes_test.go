package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #305: the stream-management handlers choose 404 / 400 / 500 from
// interfaces.ErrNotFound and services.ErrInvalidRequest, never from error text.
// 404 means only that no such stream exists; a store failure is a 500; an update
// the stream cannot accept is a 400 carrying the rejection's text.

const unknownSid = "no-such-stream"

// errStoreDown is the failure failingStreamDAO reports: a store that could not
// answer, which is not the same as a stream that does not exist.
var errStoreDown = errors.New("stream store unavailable")

// errServerStoreDown is the failure failingServerDAO reports: a server store
// that could not answer, which is not the same as an alias naming no server.
var errServerStoreDown = errors.New("server store unavailable")

// failingServerDAO is a server store whose alias lookups fail.
type failingServerDAO struct {
	interfaces.ServerDAO
}

func (d *failingServerDAO) FindByAlias(context.Context, string) (*model.Server, error) {
	return nil, errServerStoreDown
}

// failingStreamDAO is a memory stream store that fails on purpose. Lookups fail
// while failFind is set, and whole-record writes while failUpdate is set, so a
// test can break the read a handler starts with or only the write it ends with.
type failingStreamDAO struct {
	interfaces.StreamDAO
	failFind   bool
	failUpdate bool
}

func (d *failingStreamDAO) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	if d.failFind {
		return nil, errStoreDown
	}
	return d.StreamDAO.FindByID(ctx, id)
}

func (d *failingStreamDAO) FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	if d.failFind {
		return nil, errStoreDown
	}
	return d.StreamDAO.FindByInboundSID(ctx, sid)
}

func (d *failingStreamDAO) Update(ctx context.Context, state *model.StreamStateRecord) error {
	if d.failUpdate {
		return errStoreDown
	}
	return d.StreamDAO.Update(ctx, state)
}

// withStreamDAO swaps app's stream service for one over dao, keeping the key
// service, so the stream records the test persists live in dao.
func (a *statusRefreshApp) withStreamDAO(dao interfaces.StreamDAO) {
	a.StreamService = services.NewStreamService(dao, a.KeyService, "DEFAULT", services.StreamServiceConfig{})
}

func (a *statusRefreshApp) getStatusRecorder(t *testing.T, bearer, sid string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/status?stream_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	GetStatusHandler(a, rr, req)
	return rr
}

func (a *statusRefreshApp) deleteStream(t *testing.T, bearer, sid string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/stream?stream_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamDeleteHandler(a, rr, req)
	return rr
}

func (a *statusRefreshApp) createStream(t *testing.T, bearer string, rec model.StreamStateRecord) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(rec)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/stream", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamCreateHandler(a, rr, req)
	return rr
}

func (a *statusRefreshApp) updateStream(t *testing.T, method, bearer, sid string, patch model.StreamStateRecord) *httptest.ResponseRecorder {
	t.Helper()
	sa := &routerOnlyApp{SignalsApplication: a.SignalsApplication, router: a.router}
	body, err := json.Marshal(patch)
	require.NoError(t, err)
	req := httptest.NewRequest(method, "/stream?stream_id="+sid, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamUpdateHandler(sa, rr, req)
	return rr
}

// assertStreamHandlerCodes drives every handler #305 names at sid and expects
// each to answer want.
func assertStreamHandlerCodes(t *testing.T, app *statusRefreshApp, sid string, want int) {
	t.Helper()
	bearer := app.adminBearer(t)
	patch := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Description: "edit"}}

	rr := app.postStatus(t, bearer, sid, model.StreamStatePause, "maintenance")
	assert.Equal(t, want, rr.Code, "POST /status: %s", rr.Body.String())
	rr = app.getStatusRecorder(t, bearer, sid)
	assert.Equal(t, want, rr.Code, "GET /status: %s", rr.Body.String())
	rr = app.updateStream(t, http.MethodPut, bearer, sid, patch)
	assert.Equal(t, want, rr.Code, "PUT /stream: %s", rr.Body.String())
	rr = app.updateStream(t, http.MethodPatch, bearer, sid, patch)
	assert.Equal(t, want, rr.Code, "PATCH /stream: %s", rr.Body.String())
	rr = app.deleteStream(t, bearer, sid)
	assert.Equal(t, want, rr.Code, "DELETE /stream: %s", rr.Body.String())
}

func TestStreamHandlers_UnknownSidIs404(t *testing.T) {
	app := newStatusRefreshApp(t)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")

	assertStreamHandlerCodes(t, app, unknownSid, http.StatusNotFound)
}

// TestStreamHandlers_StoreFailureIs500 proves a store that cannot answer is a
// server fault, not a missing stream, on every handler that looks the stream up.
func TestStreamHandlers_StoreFailureIs500(t *testing.T) {
	app := newStatusRefreshApp(t)
	dao := &failingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	app.withStreamDAO(dao)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")
	dao.failFind = true

	assertStreamHandlerCodes(t, app, statusPlainSid, http.StatusInternalServerError)
}

// TestStreamUpdate_StoreFailureDuringWriteIs500: the stream exists and the
// update is acceptable, but the store fails to write it.
func TestStreamUpdate_StoreFailureDuringWriteIs500(t *testing.T) {
	app := newStatusRefreshApp(t)
	dao := &failingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	app.withStreamDAO(dao)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")
	dao.failUpdate = true

	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		rr := app.updateStream(t, method, app.adminBearer(t), statusPlainSid, model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{Description: "edit"},
		})
		assert.Equal(t, http.StatusInternalServerError, rr.Code, "%s /stream: %s", method, rr.Body.String())
	}
	assert.Empty(t, app.router.updated, "a failed write must not refresh the router")
}

// TestStreamUpdate_RejectionIs400WithItsText: an update the stream cannot accept
// is the caller's to fix, so it is a 400 whose body carries the rejection, never
// a 404 that claims the stream does not exist.
func TestStreamUpdate_RejectionIs400WithItsText(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pair  bool
		patch model.StreamStateRecord
		text  string
	}{
		{
			name: "delivery method change",
			patch: model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
				Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: "https://receiver.example/events",
				}},
			}},
			text: services.ErrorInvalidDeliveryMethod,
		},
		{
			name:  "invalid signing_alg",
			patch: model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{SigningAlg: "HS256"}},
			text:  "invalid signing_alg",
		},
		{
			name:  "negative subject_removal_grace_seconds",
			patch: model.StreamStateRecord{SubjectRemovalGraceSeconds: -1},
			text:  "invalid subject_removal_grace_seconds",
		},
		{
			name:  "invalid event_source",
			patch: model.StreamStateRecord{EventSource: &model.EventSource{Type: model.EventSourceExplicit}},
			text:  "invalid event_source",
		},
		{
			name:  "sstp event_source",
			pair:  true,
			patch: model.StreamStateRecord{EventSource: &model.EventSource{Type: model.EventSourceDirect}},
			text:  "sstp event_source is immutable",
		},
		{
			name:  "sstp role",
			pair:  true,
			patch: model.StreamStateRecord{SstpMethod: &model.SstpMethod{Role: model.SstpRoleResponder}},
			text:  "sstp role is immutable",
		},
		{
			name:  "sstp endpoint_url",
			pair:  true,
			patch: model.StreamStateRecord{SstpMethod: &model.SstpMethod{EndpointUrl: "https://other.example/sstp/other"}},
			text:  "sstp endpoint_url is immutable",
		},
		{
			name:  "sstp peer_pair_id",
			pair:  true,
			patch: model.StreamStateRecord{SstpMethod: &model.SstpMethod{PeerPairId: "other-peer-pair"}},
			text:  "sstp peer_pair_id is immutable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			sid := statusPlainSid
			if tc.pair {
				persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")
				sid = statusPairTxSid
			} else {
				persistStatusPlain(t, app, model.StreamStateEnabled, "")
			}

			for _, method := range []string{http.MethodPut, http.MethodPatch} {
				rr := app.updateStream(t, method, app.adminBearer(t), sid, tc.patch)
				require.Equal(t, http.StatusBadRequest, rr.Code, "%s /stream: %s", method, rr.Body.String())
				assert.Contains(t, rr.Body.String(), tc.text, "%s /stream", method)
			}
			assert.Empty(t, app.router.updated, "a rejected update must not refresh the router")
		})
	}
}

// TestStreamSave_SubjectFilterModeOutcomes: on stream create and update, a
// subject_filter_mode the stream's upstream cannot serve is the caller's
// configuration to fix, so it is a 400 carrying the rejection. A receiver store,
// server store or upstream that could not answer is a server fault, so it stays
// a 500 — except on a LOCAL stream, which does not relay and so is saved even
// when its upstream could not be checked. Neither is ever a 404: no stream is
// missing. The cases with a production resolver locate the source transmitter
// from a receiver stream that names it by tx_alias or only by iss. A save that
// succeeds is a 200 on update and a 201 on create.
func TestStreamSave_SubjectFilterModeOutcomes(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	receiverIss := func(id, iss string) model.StreamStateRecord {
		var rx model.StreamStateRecord
		rx.StreamConfiguration.Id = id
		rx.StreamConfiguration.Iss = iss
		return rx
	}
	receiver := func(id string) model.StreamStateRecord { return receiverIss(id, "DEFAULT") }
	receiverAlias := func(id, alias, iss string) model.StreamStateRecord {
		rx := receiverIss(id, iss)
		rx.StreamConfiguration.TxAlias = &alias
		return rx
	}
	noServers := services.NewDefaultUpstreamResolver(services.NewServerService(memory.NewServerDAO()))
	serverStoreDown := services.NewDefaultUpstreamResolver(services.NewServerService(&failingServerDAO{ServerDAO: memory.NewServerDAO()}))
	noSubjectEndpoints := &services.UpstreamConn{Config: &model.TransmitterConfiguration{Issuer: "DEFAULT"}}
	// An EXPLICIT source names the receiver stream, whose iss need not match the
	// updated stream's.
	fromRx1 := &model.EventSource{Type: model.EventSourceExplicit, SourceStreamIds: []string{"rx-1"}}

	sourceTransmitter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ssf-configuration/issuer1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
			AddSubjectEndpoint:    "https://source.example/add-subject",
			RemoveSubjectEndpoint: "https://source.example/remove-subject",
		})
	}))
	t.Cleanup(sourceTransmitter.Close)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()

	for _, tc := range []struct {
		name       string
		receivers  []model.StreamStateRecord
		listErr    error
		conn       *services.UpstreamConn
		resolveErr error
		resolve    services.UpstreamResolver
		source     *model.EventSource
		mode       string
		want       int
		text       string
	}{
		{
			name: "no relay target",
			want: http.StatusBadRequest,
			text: services.ErrRelayTargetNotFound.Error(),
		},
		{
			name:      "ambiguous relay target",
			receivers: []model.StreamStateRecord{receiver("rx-1"), receiver("rx-2")},
			want:      http.StatusBadRequest,
			text:      services.ErrRelayTargetAmbiguous.Error(),
		},
		{
			name:      "upstream without subject endpoints",
			receivers: []model.StreamStateRecord{receiver("rx-1")},
			conn:      noSubjectEndpoints,
			want:      http.StatusBadRequest,
			text:      "requires an upstream that advertises add_subject_endpoint and remove_subject_endpoint",
		},
		{
			name:    "receiver store failure",
			listErr: errStoreDown,
			want:    http.StatusInternalServerError,
		},
		{
			name:       "upstream unreachable",
			receivers:  []model.StreamStateRecord{receiver("rx-1")},
			resolveErr: errors.New("cannot fetch upstream configuration"),
			want:       http.StatusInternalServerError,
		},
		{
			name:      "source transmitter discovered from the receiver's iss",
			receivers: []model.StreamStateRecord{receiverIss("rx-1", sourceTransmitter.URL+"/issuer1")},
			resolve:   services.NewDefaultUpstreamResolver(nil),
			source:    fromRx1,
			want:      http.StatusOK,
		},
		{
			name:      "receiver with nothing to discover its transmitter from",
			receivers: []model.StreamStateRecord{receiverIss("rx-1", "")},
			resolve:   services.NewDefaultUpstreamResolver(nil),
			source:    fromRx1,
			want:      http.StatusBadRequest,
			text:      "no tx_alias, tx_well_known_url or iss",
		},
		{
			name:      "tx_alias naming no registered server, with nothing else to discover from",
			receivers: []model.StreamStateRecord{receiverAlias("rx-1", "unregistered", "")},
			resolve:   noServers,
			source:    fromRx1,
			want:      http.StatusBadRequest,
			text:      `tx_alias "unregistered" names no registered server, and there is no tx_well_known_url or iss`,
		},
		{
			name:      "tx_alias naming no registered server, source transmitter unreachable at its iss",
			receivers: []model.StreamStateRecord{receiverAlias("rx-1", "unregistered", gone.URL)},
			resolve:   noServers,
			source:    fromRx1,
			want:      http.StatusInternalServerError,
		},
		{
			name:      "server store failure resolving tx_alias, with nothing else to discover from",
			receivers: []model.StreamStateRecord{receiverAlias("rx-1", "source-server", "")},
			resolve:   serverStoreDown,
			source:    fromRx1,
			want:      http.StatusInternalServerError,
		},
		{
			name:      "source transmitter unreachable at its iss",
			receivers: []model.StreamStateRecord{receiverIss("rx-1", gone.URL)},
			resolve:   services.NewDefaultUpstreamResolver(nil),
			source:    fromRx1,
			want:      http.StatusInternalServerError,
		},
		{
			name:    "LOCAL with a receiver store failure",
			listErr: errStoreDown,
			mode:    model.SubjectFilterModeLocal,
			want:    http.StatusOK,
		},
		{
			name:      "LOCAL whose source transmitter is unreachable at its iss",
			receivers: []model.StreamStateRecord{receiverIss("rx-1", gone.URL)},
			resolve:   services.NewDefaultUpstreamResolver(nil),
			source:    fromRx1,
			mode:      model.SubjectFilterModeLocal,
			want:      http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStatusPlain(t, app, model.StreamStateEnabled, "")
			resolve := tc.resolve
			if resolve == nil {
				resolve = func(context.Context, *model.StreamStateRecord) (*services.UpstreamConn, error) {
					return tc.conn, tc.resolveErr
				}
			}
			app.StreamService.SetSubjectRelayService(services.NewSubjectRelayService(
				func(context.Context) ([]model.StreamStateRecord, error) { return tc.receivers, tc.listErr },
				nil, nil, resolve,
			))
			source := tc.source
			if source == nil {
				source = &model.EventSource{Type: model.EventSourceAudience}
			}
			mode := tc.mode
			if mode == "" {
				mode = model.SubjectFilterModePassthru
			}
			patch := model.StreamStateRecord{
				SubjectFilterMode: mode,
				EventSource:       source,
			}

			for _, method := range []string{http.MethodPut, http.MethodPatch} {
				rr := app.updateStream(t, method, app.adminBearer(t), statusPlainSid, patch)
				require.Equal(t, tc.want, rr.Code, "%s /stream: %s", method, rr.Body.String())
				if tc.text != "" {
					assert.Contains(t, rr.Body.String(), tc.text, "%s /stream", method)
				}
			}

			create := *statusPlainRecord("DEFAULT", "", "")
			create.StreamConfiguration.Id = ""
			create.SubjectFilterMode = mode
			create.EventSource = source
			wantCreate := tc.want
			if wantCreate == http.StatusOK {
				wantCreate = http.StatusCreated
			}
			rr := app.createStream(t, app.adminBearer(t), create)
			require.Equal(t, wantCreate, rr.Code, "POST /stream: %s", rr.Body.String())
			if tc.text != "" {
				assert.Contains(t, rr.Body.String(), tc.text, "POST /stream")
			}

			if tc.want == http.StatusOK {
				assert.NotEmpty(t, app.router.updated, "an accepted save must refresh the router")
			} else {
				assert.Empty(t, app.router.updated, "a refused save must not refresh the router")
			}
		})
	}
}
