package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #310: an operator's pause or disable stops a poll receiver's polling and
// every retry; a transmitter pause is recorded as transmitter-caused and resumes
// by itself; a retrying receiver stays enabled with a reason.

// quietWindow is how long a test watches for a poll that must not happen.
const quietWindow = time.Second

// statusTx is a fake RFC8936 transmitter with an SSF status endpoint. A test
// steers what /poll and /status answer, and observes how often each is called.
type statusTx struct {
	url string

	mu       sync.Mutex
	status   model.StreamStatus
	pollCode int           // 0 answers 200 with the pending SETs
	hold     chan struct{} // while set, each poll blocks until it is closed
	entered  chan struct{} // signalled when a poll blocks on hold
	pending  map[string]string
	acked    map[string]bool
	setErrs  map[string]bool

	polls        atomic.Int32
	statusChecks atomic.Int32
}

func newStatusTx(t *testing.T) *statusTx {
	t.Helper()
	tx := &statusTx{
		status:  model.StreamStatus{Status: model.StreamStateEnabled},
		pending: map[string]string{},
		acked:   map[string]bool{},
		setErrs: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		tx.statusChecks.Add(1)
		tx.mu.Lock()
		st := tx.status
		tx.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		tx.polls.Add(1)
		var report evPollReport
		_ = json.NewDecoder(r.Body).Decode(&report)

		tx.mu.Lock()
		for _, jti := range report.Acks {
			tx.acked[jti] = true
			delete(tx.pending, jti)
		}
		for jti := range report.SetErrs {
			tx.setErrs[jti] = true
			delete(tx.pending, jti)
		}
		hold, entered, code := tx.hold, tx.entered, tx.pollCode
		sets := make(map[string]string, len(tx.pending))
		for jti, token := range tx.pending {
			sets[jti] = token
		}
		tx.mu.Unlock()

		if hold != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": sets})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	tx.url = server.URL
	return tx
}

func (tx *statusTx) setStatus(status, reason string) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.status = model.StreamStatus{Status: status, Reason: reason}
}

func (tx *statusTx) setPollCode(code int) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.pollCode = code
}

// holdPolls makes every poll block until the returned release is called, and
// waits until one poll is in flight.
func (tx *statusTx) holdPolls(t *testing.T) (release func()) {
	t.Helper()
	tx.mu.Lock()
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	tx.hold, tx.entered = hold, entered
	tx.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no poll reached the transmitter")
	}
	return func() {
		tx.mu.Lock()
		tx.hold, tx.entered = nil, nil
		tx.mu.Unlock()
		close(hold)
	}
}

func (tx *statusTx) serve(jti, token string) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.pending[jti] = token
}

func (tx *statusTx) disposition(jti string) (acked, setErr bool) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.acked[jti], tx.setErrs[jti]
}

// assertNoPoll fails if the receiver sends any poll within quietWindow.
func (tx *statusTx) assertNoPoll(t *testing.T, msg string) {
	t.Helper()
	before := tx.polls.Load()
	assert.Never(t, func() bool { return tx.polls.Load() > before }, quietWindow, 20*time.Millisecond, msg)
}

func (tx *statusTx) assertPollsResume(t *testing.T, msg string) {
	t.Helper()
	before := tx.polls.Load()
	assert.Eventually(t, func() bool { return tx.polls.Load() > before }, 5*time.Second, 20*time.Millisecond, msg)
}

// fastPollStatusEnv shortens the retry and status-check timers so the loop's
// transitions happen within a test's patience.
func fastPollStatusEnv(t *testing.T) {
	t.Setenv("I2SIG_POLL_PROBE_INTERVAL", "0.1")
	t.Setenv("I2SIG_POLL_RETRY_BASE_DELAY", "0.1")
	t.Setenv("I2SIG_POLL_RETRY_BACKOFF_FACTOR", "1.0")
	t.Setenv("I2SIG_POLL_RETRY_MAX_DELAY", "0.2")
	t.Setenv("I2SIG_POLL_AUTH_RETRY_DELAY", "0.1")
}

func newStatusTestServer(t *testing.T) *ssfInstance {
	t.Helper()
	instance, err := createServer(t, "poll_receiver_status_test", true)
	require.NoError(t, err)
	t.Cleanup(func() {
		instance.app.Shutdown()
		instance.ts.Close()
	})
	return instance
}

// createStatusReceiver creates a poll receiver against tx without starting it.
func createStatusReceiver(t *testing.T, instance *ssfInstance, tx *statusTx) string {
	t.Helper()
	created, err := instance.CreateStream(model.StreamConfiguration{
		TxAllowPlaintext: true, // httptest peers are plaintext (#322)
		Iss:              "https://status-tx.example.com",
		IssuerJWKSUrl:    tx.url + "/jwks",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: tx.url + "/poll",
				PollConfig:  &model.PollParameters{ReturnImmediately: true},
			},
		},
	}, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	return created.Id
}

func startReceiver(t *testing.T, instance *ssfInstance, sid string) {
	t.Helper()
	state, err := instance.GetStreamState(sid)
	require.NoError(t, err)
	require.NotNil(t, instance.app.HandleReceiver(state))
}

// postReceiverStatus is an operator's POST /status on the receiver.
func postReceiverStatus(t *testing.T, instance *ssfInstance, sid, status, reason string) {
	t.Helper()
	body, err := json.Marshal(model.UpdateStreamStatus{Status: status, Reason: reason})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, instance.ts.URL+"/status?stream_id="+sid, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /status %s", status)
}

func storedStatus(t *testing.T, instance *ssfInstance, sid string) *model.StreamStateRecord {
	t.Helper()
	st, err := instance.GetStreamState(sid)
	require.NoError(t, err)
	return st
}

func assertStored(t *testing.T, instance *ssfInstance, sid, status string, transmitterCaused bool) *model.StreamStateRecord {
	t.Helper()
	st := storedStatus(t, instance, sid)
	assert.Equal(t, status, st.Status, "stored status")
	assert.Equal(t, transmitterCaused, st.TransmitterCaused, "stored transmitter_caused")
	return st
}

func eventuallyStored(t *testing.T, instance *ssfInstance, sid string, msg string, cond func(*model.StreamStateRecord) bool) {
	t.Helper()
	require.Eventually(t, func() bool {
		st, err := instance.GetStreamState(sid)
		return err == nil && cond(st)
	}, 5*time.Second, 20*time.Millisecond, msg)
}

// TestPollReceiver_OperatorStatusStopsPolling: an operator pause or disable made
// during a long poll lets that poll complete, sends no further poll, and is not
// overwritten; re-enabling resumes polling.
func TestPollReceiver_OperatorStatusStopsPolling(t *testing.T) {
	for _, status := range []string{model.StreamStatePause, model.StreamStateDisable} {
		t.Run(status, func(t *testing.T) {
			fastPollStatusEnv(t)
			instance := newStatusTestServer(t)
			tx := newStatusTx(t)
			sid := createStatusReceiver(t, instance, tx)
			startReceiver(t, instance, sid)

			release := tx.holdPolls(t)
			postReceiverStatus(t, instance, sid, status, "operator "+status)
			release()

			tx.assertNoPoll(t, "no poll may follow an operator "+status)
			st := assertStored(t, instance, sid, status, false)
			assert.Equal(t, "operator "+status, st.ErrorMsg, "the completed poll must not overwrite the operator's status")

			postReceiverStatus(t, instance, sid, model.StreamStateEnabled, "")
			tx.assertPollsResume(t, "re-enabling must resume polling")
			assertStored(t, instance, sid, model.StreamStateEnabled, false)
		})
	}
}

// TestPollReceiver_BackgroundSyncKeepsAdministrativePause: the background
// InitializeReceivers sync must not revive an operator-paused receiver.
func TestPollReceiver_BackgroundSyncKeepsAdministrativePause(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	sid := createStatusReceiver(t, instance, tx)
	startReceiver(t, instance, sid)
	tx.assertPollsResume(t, "the receiver must be polling")

	postReceiverStatus(t, instance, sid, model.StreamStatePause, "operator pause")
	tx.assertNoPoll(t, "an operator pause stops polling")

	instance.app.InitializeReceivers()
	tx.assertNoPoll(t, "the background sync must not restart an administratively paused receiver")
	assertStored(t, instance, sid, model.StreamStatePause, false)
}

// TestPollReceiver_RetryIsNotAPause: a receiver retrying connection errors stays
// enabled with a reason, and an operator pause then stops every retry and poll
// and survives the transmitter becoming reachable.
func TestPollReceiver_RetryIsNotAPause(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	tx.setPollCode(http.StatusServiceUnavailable)
	sid := createStatusReceiver(t, instance, tx)
	startReceiver(t, instance, sid)

	eventuallyStored(t, instance, sid, "a retrying receiver is enabled with a reason", func(st *model.StreamStateRecord) bool {
		return st.Status == model.StreamStateEnabled && strings.Contains(st.ErrorMsg, "retry being attempted")
	})
	st := storedStatus(t, instance, sid)
	assert.False(t, st.TransmitterCaused)

	postReceiverStatus(t, instance, sid, model.StreamStatePause, "operator pause")
	time.Sleep(500 * time.Millisecond) // let a retry already under way finish
	tx.setPollCode(0)

	tx.assertNoPoll(t, "no retry or poll may follow an operator pause")
	st = assertStored(t, instance, sid, model.StreamStatePause, false)
	assert.Equal(t, "operator pause", st.ErrorMsg)
}

// TestPollReceiver_TransmitterPauseResumesByItself: a transmitter pause is stored
// as transmitter-caused and stops polling; the receiver resumes by itself once
// the transmitter reports enabled.
func TestPollReceiver_TransmitterPauseResumesByItself(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	tx.setStatus(model.StreamStatePause, "maintenance")
	sid := createStatusReceiver(t, instance, tx)
	startReceiver(t, instance, sid)

	eventuallyStored(t, instance, sid, "a transmitter pause is stored as transmitter-caused", func(st *model.StreamStateRecord) bool {
		return st.Status == model.StreamStatePause && st.TransmitterCaused &&
			st.ErrorMsg == "Transmitter stream is paused: maintenance"
	})
	tx.assertNoPoll(t, "a transmitter-paused receiver does not poll")

	tx.setStatus(model.StreamStateEnabled, "")
	tx.assertPollsResume(t, "the receiver resumes by itself when the transmitter re-enables")
	st := assertStored(t, instance, sid, model.StreamStateEnabled, false)
	assert.Empty(t, st.ErrorMsg)
}

// TestPollReceiver_TransmitterPauseSurvivesRestart: a receiver stored as
// transmitter-paused and started fresh (a node restart or lease takeover) waits
// on the transmitter and resumes by itself.
func TestPollReceiver_TransmitterPauseSurvivesRestart(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	tx.setStatus(model.StreamStatePause, "maintenance")
	sid := createStatusReceiver(t, instance, tx)
	instance.streamSvc().UpdateTransmitterCausedStatus(t.Context(), sid, model.StreamStatePause, "Transmitter stream is paused: maintenance")

	startReceiver(t, instance, sid)
	require.Eventually(t, func() bool { return tx.statusChecks.Load() > 0 }, 5*time.Second, 20*time.Millisecond,
		"a fresh loop on a transmitter-caused pause checks the transmitter")
	tx.assertNoPoll(t, "it does not poll while the transmitter is still paused")

	tx.setStatus(model.StreamStateEnabled, "")
	tx.assertPollsResume(t, "it resumes by itself once the transmitter reports enabled")
	assertStored(t, instance, sid, model.StreamStateEnabled, false)
}

// TestPollReceiver_OperatorPauseWhileTransmitterPaused: an operator pause made
// while waiting on a paused transmitter clears the flag and is not resumed when
// the transmitter re-enables.
func TestPollReceiver_OperatorPauseWhileTransmitterPaused(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	tx.setStatus(model.StreamStatePause, "maintenance")
	sid := createStatusReceiver(t, instance, tx)
	startReceiver(t, instance, sid)
	eventuallyStored(t, instance, sid, "transmitter-paused", func(st *model.StreamStateRecord) bool {
		return st.Status == model.StreamStatePause && st.TransmitterCaused
	})

	postReceiverStatus(t, instance, sid, model.StreamStatePause, "operator pause")
	assertStored(t, instance, sid, model.StreamStatePause, false)
	time.Sleep(300 * time.Millisecond) // let the next status recheck see it

	tx.setStatus(model.StreamStateEnabled, "")
	tx.assertNoPoll(t, "an operator pause is not resumed by the transmitter re-enabling")
	st := assertStored(t, instance, sid, model.StreamStatePause, false)
	assert.Equal(t, "operator pause", st.ErrorMsg)
}

// TestPollReceiver_TransmitterDisableNeedsOperator: a transmitter disable is
// stored as transmitter-caused and stops the receiver; only an operator
// re-enable, which clears the flag, resumes it.
func TestPollReceiver_TransmitterDisableNeedsOperator(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)
	tx.setStatus(model.StreamStateDisable, "retired")
	sid := createStatusReceiver(t, instance, tx)
	startReceiver(t, instance, sid)

	eventuallyStored(t, instance, sid, "a transmitter disable is stored as transmitter-caused", func(st *model.StreamStateRecord) bool {
		return st.Status == model.StreamStateDisable && st.TransmitterCaused &&
			st.ErrorMsg == "Transmitter stream is disabled: retired"
	})
	tx.assertNoPoll(t, "a transmitter-disabled receiver does not poll")

	tx.setStatus(model.StreamStateEnabled, "")
	tx.assertNoPoll(t, "a transmitter disable does not resume by itself")

	postReceiverStatus(t, instance, sid, model.StreamStateEnabled, "")
	assertStored(t, instance, sid, model.StreamStateEnabled, false)
	tx.assertPollsResume(t, "an operator re-enable resumes polling")
}

// liveJwksServer serves the public half of key under kid.
func liveJwksServer(t *testing.T, kid string, key *rsa.PrivateKey) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signingOnlyJWKSBytes(t, kid, &key.PublicKey))
	}))
	t.Cleanup(server.Close)
	return server.URL + "/jwks.json"
}

func liveSignedSet(t *testing.T, key *rsa.PrivateKey, kid, iss, streamId string) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, iss, []string{evAudience})
	set.Kid = kid
	set.SubjectId = &goSet.SubjectIdentifier{Format: "opaque", OpaqueIdentifier: goSet.OpaqueIdentifier{Id: streamId}}
	evValidPayload(&set)
	signed, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, signed
}

// TestPollReceiver_LiveJwksPickup (moved from #308): patching iss and
// issuerJWKSUrl on a running poll receiver makes the next poll verify against
// the new JWKS, without restarting the poll loop.
func TestPollReceiver_LiveJwksPickup(t *testing.T) {
	fastPollStatusEnv(t)
	instance := newStatusTestServer(t)
	tx := newStatusTx(t)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const issA, issB = "https://issuer-a.example.com", "https://issuer-b.example.com"
	jwksA, jwksB := liveJwksServer(t, "kid-a", keyA), liveJwksServer(t, "kid-b", keyB)

	created, err := instance.CreateStream(model.StreamConfiguration{
		TxAllowPlaintext: true, // httptest peers are plaintext (#322)
		Iss:              issA,
		Aud:              []string{evAudience},
		IssuerJWKSUrl:    jwksA,
		EventsRequested:  []string{"*"},
		RouteMode:        model.RouteModeImport,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: tx.url + "/poll",
				PollConfig:  &model.PollParameters{ReturnImmediately: true},
			},
		},
	}, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	sid := created.Id
	startReceiver(t, instance, sid)

	jtiA, tokenA := liveSignedSet(t, keyA, "kid-a", issA, sid)
	tx.serve(jtiA, tokenA)
	require.Eventually(t, func() bool { acked, _ := tx.disposition(jtiA); return acked }, 10*time.Second, 20*time.Millisecond,
		"a SET signed by the configured issuer's key is acked")
	checksBefore := tx.statusChecks.Load()

	patch := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Iss: issB, IssuerJWKSUrl: jwksB}}
	body, err := json.Marshal(patch)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, instance.ts.URL+"/stream?stream_id="+sid, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT /stream")

	jtiB, tokenB := liveSignedSet(t, keyB, "kid-b", issB, sid)
	tx.serve(jtiB, tokenB)
	require.Eventually(t, func() bool {
		acked, setErr := tx.disposition(jtiB)
		return acked || setErr
	}, 10*time.Second, 20*time.Millisecond, "the receiver must dispose of the SET signed by the new issuer")
	acked, setErr := tx.disposition(jtiB)
	assert.True(t, acked, "the next poll verifies against the patched JWKS and issuer")
	assert.False(t, setErr, "the SET must not be rejected against the old JWKS")
	assert.Equal(t, checksBefore, tx.statusChecks.Load(),
		"the loop was not restarted: a restart re-checks the transmitter status at lease acquisition")
}
