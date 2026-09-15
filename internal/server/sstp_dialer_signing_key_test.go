package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #312, SSTP dialing end: a pair that cannot sign what it would send
// takes the key-unavailable pause and sends nothing. The key check resumes it
// when the key is back, and the dial loop then delivers; otherwise the pair is
// disabled once the retry limit has passed.

const dialKeyIssuer = "https://sstp-dial-key.example"

// ackingPeer is an SSTP responder that acks every SET it receives.
type ackingPeer struct {
	mu       sync.Mutex
	received []string
}

func (p *ackingPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg goSetSstp.Message
	_ = json.NewDecoder(r.Body).Decode(&msg)
	resp := goSetSstp.Message{}
	p.mu.Lock()
	for jti := range msg.Sets {
		p.received = append(p.received, jti)
		resp.Ack = append(resp.Ack, jti)
	}
	p.mu.Unlock()
	w.Header().Set("Content-Type", goSetSstp.ContentType)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *ackingPeer) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.received...)
}

type dialKeyNode struct {
	persistence *dbProviders.Persistence
	router      eventRouter.EventRouter
	peer        *ackingPeer
	pairId      string
	txSid       string
}

// newDialKeyNode wires a router and an SSTP dialer the way StartServer does,
// with an initiator pair signing as dialKeyIssuer that dials an acking peer. The
// issuer's key is suspended and one event is queued before the pair is handed
// to the router, so the dial loop's first cycle has something it cannot sign.
func newDialKeyNode(t *testing.T, retryLimit int) *dialKeyNode {
	t.Helper()
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "100ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", strconv.Itoa(retryLimit))
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	ctx := context.Background()
	persistence, err := dbProviders.OpenPersistence("memorydb:", "sstp-dial-key-"+t.Name())
	require.NoError(t, err)
	_, err = persistence.KeyService.CreateKeyPair(ctx, dialKeyIssuer, "sig", "")
	require.NoError(t, err)

	peer := &ackingPeer{}
	peerSrv := httptest.NewServer(peer)
	t.Cleanup(peerSrv.Close)

	dialer := NewSstpDialer(persistence.Coordinator, "node-dial-key", nil, SstpDialerConfig{
		BaseDelay:  20 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
		Jitter:     func() time.Duration { return 0 },
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	})
	router := eventRouter.NewRouter(eventRouter.RouterDeps{
		StreamService:   persistence.StreamService,
		KeyService:      persistence.KeyService,
		EventService:    persistence.EventService,
		Coordinator:     persistence.Coordinator,
		SstpDialerHooks: dialer,
	}, "node-dial-key")
	dialer.Bind(router.(eventRouter.SstpOutbound))
	t.Cleanup(router.Shutdown)

	pairId := ids.NewObjectID()
	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        pairId,
			Iss:       dialKeyIssuer,
			Aud:       []string{"https://peer.example"},
			RouteMode: model.RouteModePublish,
		},
		SstpInbound: &model.StreamConfiguration{
			Id:        ids.NewObjectID(),
			Iss:       "https://peer.example",
			Aud:       []string{dialKeyIssuer},
			RouteMode: model.RouteModeImport,
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleInitiator, EndpointUrl: peerSrv.URL, AuthorizationHeader: "Bearer peer-token"},
		PairId:        pairId,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, persistence.StreamService.PersistStreamStateRecord(ctx, rec))

	_, _, err = persistence.KeyService.SetKeyStatus(ctx, dialKeyIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	token := goSet.CreateSet(&goSet.EventSubject{SubjectIdentifier: goSet.SubjectIdentifier{Format: "email", EmailIdentifier: goSet.EmailIdentifier{Email: "dial@example.com"}}}, dialKeyIssuer, []string{"https://peer.example"})
	token.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	_, err = persistence.EventService.AddEvent(ctx, &token, pairId, "")
	require.NoError(t, err)
	require.NoError(t, persistence.EventService.AddEventToStream(ctx, token.ID, pairId))

	stored, err := persistence.StreamService.GetStreamStateByPairId(ctx, pairId)
	require.NoError(t, err)
	router.UpdateStreamState(stored)
	t.Cleanup(func() { dialer.UnregisterPair(pairId) })

	return &dialKeyNode{persistence: persistence, router: router, peer: peer, pairId: pairId, txSid: pairId}
}

func (n *dialKeyNode) stored(t *testing.T) *model.StreamStateRecord {
	t.Helper()
	rec, err := n.persistence.StreamService.GetStreamStateByPairId(context.Background(), n.pairId)
	require.NoError(t, err)
	return rec
}

func (n *dialKeyNode) pending() []string {
	jtis, _ := n.persistence.EventService.GetEventIds(context.Background(), n.txSid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	return jtis
}

func TestSstpDialingEnd_KeyUnavailablePausesThenResumesAndDelivers(t *testing.T) {
	n := newDialKeyNode(t, 1000)
	reason := "SSTP-CLIENT: " + services.NoActiveSigningKeyReason(dialKeyIssuer, "")

	require.Eventually(t, func() bool {
		rec := n.stored(t)
		return rec.Status == model.StreamStatePause && rec.KeyUnavailableSince != nil
	}, 5*time.Second, 10*time.Millisecond, "the pair takes the key-unavailable pause")
	rec := n.stored(t)
	assert.Equal(t, reason, rec.ErrorMsg)
	assert.Equal(t, model.StreamStatePause, rec.InboundStatus, "both directions stop")
	assert.Empty(t, n.peer.got(), "nothing is sent while the key is missing")
	assert.Len(t, n.pending(), 1, "the event stays queued")

	_, _, err := n.persistence.KeyService.SetKeyStatus(context.Background(), dialKeyIssuer, "", interfaces.KeyStatusActive)
	require.NoError(t, err)
	n.router.(interface{ InvalidateIssuerKey(string) }).InvalidateIssuerKey(dialKeyIssuer)

	require.Eventually(t, func() bool {
		return len(n.peer.got()) == 1 && len(n.pending()) == 0
	}, 5*time.Second, 10*time.Millisecond, "the pair resumes and its dial loop delivers the queued event")
	rec = n.stored(t)
	assert.Equal(t, model.StreamStateEnabled, rec.Status)
	assert.Empty(t, rec.ErrorMsg)
	assert.Nil(t, rec.KeyUnavailableSince)
}

func TestSstpDialingEnd_KeyStillMissingPastTheLimitDisables(t *testing.T) {
	n := newDialKeyNode(t, 2)

	require.Eventually(t, func() bool {
		return n.stored(t).Status == model.StreamStateDisable
	}, 5*time.Second, 10*time.Millisecond, "the pair is disabled once the retry limit has passed")
	rec := n.stored(t)
	assert.Equal(t, "SSTP-CLIENT: "+services.NoActiveSigningKeyReason(dialKeyIssuer, ""), rec.ErrorMsg)
	assert.Nil(t, rec.KeyUnavailableSince)
	assert.Empty(t, n.peer.got(), "nothing was ever sent")
	assert.Len(t, n.pending(), 1, "the event is still queued")
}
