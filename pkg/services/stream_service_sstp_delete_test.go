package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deletePeer stands in for a remote node's SSF surface during pair-delete
// cascade: a well-known endpoint and a stream-config endpoint that records
// DELETE calls and can be toggled to fail.
type deletePeer struct {
	ts          *httptest.Server
	deleteCalls int32
	failDelete  bool
}

func newDeletePeer(t *testing.T, failDelete bool) *deletePeer {
	t.Helper()
	dp := &deletePeer{failDelete: failDelete}
	mux := http.NewServeMux()
	var streamEndpoint string
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := model.TransmitterConfiguration{
			Issuer:                "https://peer.example",
			ConfigurationEndpoint: streamEndpoint,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&dp.deleteCalls, 1)
			if dp.failDelete {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected", http.StatusMethodNotAllowed)
	})
	dp.ts = httptest.NewServer(mux)
	streamEndpoint = dp.ts.URL + "/streams"
	t.Cleanup(dp.ts.Close)
	return dp
}

func deletePeerServer(host string) *model.Server {
	token := "peer-token"
	return &model.Server{
		Alias:       "peer-node",
		Type:        model.ServerTypeGosignals,
		Host:        host,
		ClientToken: &token,
		ProjectId:   "proj-1",
	}
}

// TestDeleteSstpPair_NoCascadeRemovesLocalOnly: without cascade_peer the local
// row is removed and no peer call is made. (Q37)
func TestDeleteSstpPair_NoCascadeRemovesLocalOnly(t *testing.T) {
	svc, rec := createdPair(t)
	peer := newDeletePeer(t, false)
	srv := deletePeerServer(peer.ts.URL)

	outcome, err := svc.DeleteSstpPair(context.Background(), rec.PairId, false, srv)
	require.NoError(t, err)
	assert.True(t, outcome.LocalDeleted)
	assert.False(t, outcome.PeerAttempted)

	_, err = svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.Error(t, err, "local row must be gone")
	assert.EqualValues(t, 0, atomic.LoadInt32(&peer.deleteCalls), "no peer call without cascade_peer")
}

// pairWithPeerPairId creates a responder pair and seeds a known PeerPairId so the
// cascade delete has a target.
func pairWithPeerPairId(t *testing.T, svc *StreamService, rec *model.StreamStateRecord) {
	t.Helper()
	rec.SstpMethod.PeerPairId = "peer-pair-target"
	require.NoError(t, svc.streamDAO.Update(context.Background(), rec))
}

// TestDeleteSstpPair_CascadeSuccess: cascade_peer=true with a reachable peer
// deletes locally and on the peer; the outcome is not a partial failure (→ 200).
// (Q37)
func TestDeleteSstpPair_CascadeSuccess(t *testing.T) {
	svc, rec := createdPair(t)
	pairWithPeerPairId(t, svc, &rec)
	peer := newDeletePeer(t, false)
	srv := deletePeerServer(peer.ts.URL)

	outcome, err := svc.DeleteSstpPair(context.Background(), rec.PairId, true, srv)
	require.NoError(t, err)
	assert.True(t, outcome.LocalDeleted)
	assert.True(t, outcome.PeerAttempted)
	assert.True(t, outcome.PeerDeleted)
	assert.False(t, outcome.PartialFailure())
	assert.EqualValues(t, 1, atomic.LoadInt32(&peer.deleteCalls))

	_, err = svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.Error(t, err, "local row must be gone")
}

// TestDeleteSstpPair_CascadePeerFailureIsPartial: local succeeds but the peer
// call fails — outcome.PartialFailure() is true (→ 207 Multi-Status) and the
// local row is still removed. (Q37, ADR 0020)
func TestDeleteSstpPair_CascadePeerFailureIsPartial(t *testing.T) {
	svc, rec := createdPair(t)
	pairWithPeerPairId(t, svc, &rec)
	peer := newDeletePeer(t, true) // peer returns 500
	srv := deletePeerServer(peer.ts.URL)

	outcome, err := svc.DeleteSstpPair(context.Background(), rec.PairId, true, srv)
	require.NoError(t, err, "local delete must still succeed despite peer failure")
	assert.True(t, outcome.LocalDeleted)
	assert.True(t, outcome.PeerAttempted)
	assert.False(t, outcome.PeerDeleted)
	assert.NotEmpty(t, outcome.PeerError)
	assert.True(t, outcome.PartialFailure())

	_, err = svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.Error(t, err, "local row must be gone even when peer cleanup failed")
}

// TestDeleteSstpPair_UnknownSidIsErrNotFound (#305): a SID that names no pair is
// reported as interfaces.ErrNotFound, the sentinel the HTTP layer maps to 404.
func TestDeleteSstpPair_UnknownSidIsErrNotFound(t *testing.T) {
	svc, _ := createdPair(t)

	outcome, err := svc.DeleteSstpPair(context.Background(), "no-such-pair", false, nil)
	assert.ErrorIs(t, err, interfaces.ErrNotFound)
	assert.False(t, outcome.LocalDeleted)
}

// errLookupStoreDown is the failure lookupFailingStreamDAO reports: a store that
// could not answer, which is not the same as a stream that does not exist.
var errLookupStoreDown = errors.New("stream store unavailable")

// lookupFailingStreamDAO is a memory stream store whose SID lookups fail on
// purpose: FindByID while failByID is set, FindByInboundSID while failByInbound
// is set. Everything else passes straight through (#305).
type lookupFailingStreamDAO struct {
	interfaces.StreamDAO
	failByID      bool
	failByInbound bool
}

func (d *lookupFailingStreamDAO) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	if d.failByID {
		return nil, errLookupStoreDown
	}
	return d.StreamDAO.FindByID(ctx, id)
}

func (d *lookupFailingStreamDAO) FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	if d.failByInbound {
		return nil, errLookupStoreDown
	}
	return d.StreamDAO.FindByInboundSID(ctx, sid)
}

const (
	lookupPairTxSid = "lookup-pair-tx"
	lookupPairRxSid = "lookup-pair-rx"
)

// lookupFailingPair stores an SSTP pair in a lookupFailingStreamDAO, with every
// lookup working until the test breaks one.
func lookupFailingPair(t *testing.T) (*StreamService, *lookupFailingStreamDAO) {
	t.Helper()
	dao := &lookupFailingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	svc := NewStreamService(dao, nil, "https://local.example", StreamServiceConfig{})
	rec := &model.StreamStateRecord{
		ProjectId: "proj-1",
		PairId:    lookupPairTxSid,
		StreamConfiguration: model.StreamConfiguration{
			Id:       lookupPairTxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       lookupPairRxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{Role: model.SstpRoleInitiator},
		Status:     model.StreamStateEnabled,
	}
	require.NoError(t, svc.PersistStreamStateRecord(context.Background(), rec))
	return svc, dao
}

// TestDeleteSstpPair_StoreFailureIsNotErrNotFound (#305): a lookup that fails
// for a reason other than not-found leaves the pair's existence unknown, so the
// store error is returned as itself, never as ErrNotFound (a 404), and nothing
// is deleted.
func TestDeleteSstpPair_StoreFailureIsNotErrNotFound(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		sid                     string
		failByID, failByInbound bool
	}{
		{name: "both lookups fail", sid: lookupPairTxSid, failByID: true, failByInbound: true},
		{name: "id lookup fails", sid: lookupPairTxSid, failByID: true},
		{name: "inbound lookup fails for the rx SID", sid: lookupPairRxSid, failByInbound: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, dao := lookupFailingPair(t)
			dao.failByID, dao.failByInbound = tc.failByID, tc.failByInbound

			outcome, err := svc.DeleteSstpPair(context.Background(), tc.sid, false, nil)
			assert.ErrorIs(t, err, errLookupStoreDown)
			assert.NotErrorIs(t, err, interfaces.ErrNotFound)
			assert.False(t, outcome.LocalDeleted)

			dao.failByID, dao.failByInbound = false, false
			_, err = svc.GetStreamStateByPairId(context.Background(), lookupPairTxSid)
			assert.NoError(t, err, "a failed lookup must delete nothing")
		})
	}
}
