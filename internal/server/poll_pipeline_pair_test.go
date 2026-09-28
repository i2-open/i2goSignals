package server

// poll_pipeline_pair_test.go — #338 end to end: a goSignals RFC 8936 poll
// transmitter on one live server and a goSignals poll receiver on another,
// over real loopback HTTP through a proxy that adds a fixed round-trip delay.
// The receiver drains 5000 SETs at pipeline depths 1, 2 and 4; each must store
// every SET exactly once and ack each exactly once.

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

const (
	pairPipelineIss     = "https://pipeline-pair.example.com"
	pairPipelineAud     = "https://pipeline-pair-rcv.example.com"
	pairPipelineProject = "pipeline-pair-project"
	pairPipelineEvent   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	pairPipelineSets    = 5000
	// pairPipelineRTT is added to every poll by a proxy between the servers so
	// the run is round-trip bound, as a real receiver-to-transmitter link is,
	// rather than bound only by the in-process memory store.
	pairPipelineRTT = 10 * time.Millisecond
)

// latencyProxy forwards to target after holding each request for delay.
func latencyProxy(t *testing.T, target string, delay time.Duration) string {
	t.Helper()
	u, err := url.Parse(target)
	require.NoError(t, err)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.FlushInterval = -1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

type pipelinePairNode struct {
	app         *SignalsApplication
	persistence *dbProviders.Persistence
	baseURL     string
}

func bootPipelinePairNode(t *testing.T, name string) *pipelinePairNode {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", name)
	require.NoError(t, err)
	require.NoError(t, persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	if persistence.Storage != nil {
		persistence.Refresh()
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	baseURL := "http://" + listener.Addr().String()
	app := StartServer(listener.Addr().String(), persistence, baseURL+"/")
	go func() { _ = app.Server.Serve(listener) }()
	t.Cleanup(app.Shutdown)

	client := &http.Client{Timeout: 2 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	require.Eventually(t, func() bool {
		resp, e := client.Get(baseURL + "/.well-known/ssf-configuration")
		if e != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "server %s did not come up", name)
	return &pipelinePairNode{app: app, persistence: persistence, baseURL: baseURL}
}

func (n *pipelinePairNode) createStream(t *testing.T, cfg model.StreamConfiguration) *model.StreamStateRecord {
	t.Helper()
	atx := authSupport.ConvertProject(pairPipelineProject)
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, atx)
	created, err := n.persistence.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, atx.ProjectId, nil)
	require.NoError(t, err)
	state, err := n.persistence.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	return state
}

// counterSum adds up every series of vec whose stream_id label is sid.
func counterSum(t *testing.T, vec *prometheus.CounterVec, sid string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { vec.Collect(ch); close(ch) }()
	total := 0.0
	for m := range ch {
		var d dto.Metric
		require.NoError(t, m.Write(&d))
		for _, lp := range d.GetLabel() {
			if lp.GetName() == "stream_id" && lp.GetValue() == sid {
				total += d.GetCounter().GetValue()
			}
		}
	}
	return total
}

// pairPipelineSETs builds the SETs, signed with the transmitter's key for the
// issuer so the receiver verifies them against the transmitter's JWKS.
func pairPipelineSETs(t *testing.T, key crypto.Signer, kid string) ([]*goSet.SecurityEventToken, []string) {
	t.Helper()
	tokens := make([]*goSet.SecurityEventToken, 0, pairPipelineSets)
	raws := make([]string, 0, pairPipelineSets)
	for i := 0; i < pairPipelineSets; i++ {
		set := &goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       fmt.Sprintf("pair-jti-%05d", i),
				Issuer:   pairPipelineIss,
				Audience: jwt.ClaimStrings{pairPipelineAud},
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			SubjectId: &goSet.SubjectIdentifier{
				Format:                  "iss_sub",
				IssuerSubjectIdentifier: goSet.IssuerSubjectIdentifier{Issuer: "https://idp.example.com", Sub: fmt.Sprintf("user-%d", i)},
			},
			Events: map[string]any{pairPipelineEvent: map[string]any{}},
		}
		set.Kid = kid
		raw, err := set.JWS(jwt.SigningMethodRS256, key)
		require.NoError(t, err)
		tokens = append(tokens, set)
		raws = append(raws, raw)
	}
	return tokens, raws
}

// runPipelinePair loads 5000 SETs onto a poll transmit stream on node A, starts
// a poll receiver on node B at the given depth, and returns how long B took to
// drain them. It asserts exactly-once at both ends through the existing event
// counters: B's eventsIn counts only SETs stored for the first time (a
// re-received JTI is swallowed by dedup, ADR 0017), and A's eventsOut counts
// each ack the transmitter received.
func runPipelinePair(t *testing.T, depth int) time.Duration {
	t.Setenv("I2SIG_POLL_PIPELINE_DEPTH", fmt.Sprint(depth))
	a := bootPipelinePairNode(t, fmt.Sprintf("pipeline-a-%d", depth))
	b := bootPipelinePairNode(t, fmt.Sprintf("pipeline-b-%d", depth))
	_, err := a.persistence.KeyService.CreateKeyPair(context.Background(), pairPipelineIss, "sig", "")
	require.NoError(t, err)
	signer, kid, err := a.persistence.KeyService.GetPrivateKeyWithKeyname(context.Background(), pairPipelineIss)
	require.NoError(t, err)
	tokens, raws := pairPipelineSETs(t, signer, kid)

	// Node A: an ingress stream that forwards, and the poll transmit stream.
	ingress := a.createStream(t, model.StreamConfiguration{
		Iss:             pairPipelineIss,
		Aud:             []string{pairPipelineAud},
		RouteMode:       model.RouteModeForward,
		EventsRequested: []string{pairPipelineEvent},
		Delivery:        &model.OneOfStreamConfigurationDelivery{PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush}},
	})
	tx := a.createStream(t, model.StreamConfiguration{
		Iss:             pairPipelineIss,
		Aud:             []string{pairPipelineAud},
		EventsRequested: []string{pairPipelineEvent},
		Delivery:        &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
	})
	a.app.EventRouter.UpdateStreamState(tx)
	require.Contains(t, tx.EventsDelivered, pairPipelineEvent)

	for off := 0; off < len(tokens); off += 500 {
		end := min(off+500, len(tokens))
		for i, e := range a.app.EventRouter.HandleEvents(tokens[off:end], raws[off:end], ingress.StreamConfiguration.Id) {
			require.NoError(t, e, "ingest %s on the transmitter", tokens[off+i].ID)
		}
	}

	bearer, err := a.app.GetAuth().IssueStreamToken(tx.StreamConfiguration.Id, pairPipelineProject, nil)
	require.NoError(t, err)

	// Node B: the poll receiver.
	rx := b.createStream(t, model.StreamConfiguration{
		Iss:              pairPipelineIss,
		Aud:              []string{pairPipelineAud},
		EventsRequested:  []string{pairPipelineEvent},
		IssuerJWKSUrl:    a.baseURL + "/jwks/" + url.QueryEscape(pairPipelineIss),
		TxAllowPlaintext: true, // loopback transmitter (#322)
		Delivery: &model.OneOfStreamConfigurationDelivery{PollReceiveMethod: &model.PollReceiveMethod{
			Method:              model.ReceivePoll,
			EndpointUrl:         latencyProxy(t, a.baseURL, pairPipelineRTT) + "/poll/" + tx.StreamConfiguration.Id,
			AuthorizationHeader: "Bearer " + bearer,
			PollConfig:          &model.PollParameters{MaxEvents: 100, ReturnImmediately: true},
		}},
	})
	rxSid := rx.StreamConfiguration.Id
	txSid := tx.StreamConfiguration.Id

	start := time.Now()
	b.app.HandleReceiver(rx)
	require.Eventually(t, func() bool {
		return counterSum(t, b.app.Stats.EventsIn, rxSid) >= pairPipelineSets &&
			counterSum(t, a.app.Stats.EventsOut, txSid) >= pairPipelineSets
	}, 3*time.Minute, 20*time.Millisecond, "receiver did not drain the transmitter at depth %d", depth)
	elapsed := time.Since(start)

	// Let any in-flight poll land, then check nothing was stored or acked twice.
	b.app.CloseReceiver(rxSid)
	require.Equal(t, float64(pairPipelineSets), counterSum(t, b.app.Stats.EventsIn, rxSid), "every SET stored exactly once")
	require.Equal(t, float64(pairPipelineSets), counterSum(t, a.app.Stats.EventsOut, txSid), "every SET acked exactly once")
	jtis := make([]string, len(tokens))
	for i, tok := range tokens {
		jtis[i] = tok.ID
	}
	require.Len(t, b.persistence.EventService.GetEvents(context.Background(), jtis), pairPipelineSets)
	return elapsed
}

// TestPollPipelinePair_ExactlyOnce drains 5000 SETs from a goSignals poll
// transmitter at depths 1, 2 and 4. Exactly-once is asserted at each depth;
// throughput is reported, not asserted (#338).
func TestPollPipelinePair_ExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("5000-SET two-server run")
	}
	for _, depth := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			elapsed := runPipelinePair(t, depth)
			t.Logf("depth=%d drained %d SETs in %s (%.0f SETs/s)", depth, pairPipelineSets, elapsed.Round(time.Millisecond),
				float64(pairPipelineSets)/elapsed.Seconds())
		})
	}
}
