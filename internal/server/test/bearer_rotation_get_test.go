package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/require"
)

// rotateCreatePollStream creates a poll-transmit stream via the mgmt token and
// returns the created config (whose response carries the LIVE delivery bearer,
// ADR 0022 §3).
func rotateCreatePollStream(t *testing.T, inst *ssfInstance) model.StreamConfiguration {
	t.Helper()
	regUrl := fmt.Sprintf("http://%s/stream", inst.host)
	reg := model.StreamConfiguration{
		Aud:       []string{"rotate-test"},
		RouteMode: model.RouteModePublish,
		Delivery:  &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
	}
	b, _ := json.Marshal(reg)
	req, _ := http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inst.streamMgmtToken)
	resp, err := inst.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var cfg model.StreamConfiguration
	require.NoError(t, json.Unmarshal(body, &cfg))
	require.NotEmpty(t, cfg.Delivery.PollTransmitMethod.AuthorizationHeader, "create response must carry the live bearer")
	return cfg
}

func getStreamConfig(t *testing.T, inst *ssfInstance, sid, authHeader string) (int, model.StreamConfiguration) {
	t.Helper()
	url := fmt.Sprintf("http://%s/stream?stream_id=%s", inst.host, sid)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err := inst.client.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var cfg model.StreamConfiguration
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(body, &cfg))
	}
	return resp.StatusCode, cfg
}

// TestStateListingsMaskBearer covers ADR 0022 §3: the admin "state listings"
// read surfaces (/states list and /state single) mask every credential — these
// return the full StreamStateRecord, which must never surface a live bearer.
func TestStateListingsMaskBearer(t *testing.T) {
	inst, err := createServer(t, "rotate-states", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	live := cfg.Delivery.PollTransmitMethod.AuthorizationHeader
	require.NotEqual(t, model.MaskedCredentialValue, live)

	// /state (single) — admin/root scope (streamMgmtToken carries admin here).
	stateUrl := fmt.Sprintf("http://%s/state?stream_id=%s", inst.host, cfg.Id)
	req, _ := http.NewRequest(http.MethodGet, stateUrl, nil)
	req.Header.Set("Authorization", "Bearer "+inst.streamMgmtToken)
	resp, err := inst.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NotContains(t, string(body), live, "/state must not leak the live bearer")
	require.Contains(t, string(body), model.MaskedCredentialValue, "/state must mask the bearer")

	// /states (list)
	statesUrl := fmt.Sprintf("http://%s/states", inst.host)
	req2, _ := http.NewRequest(http.MethodGet, statesUrl, nil)
	req2.Header.Set("Authorization", "Bearer "+inst.streamMgmtToken)
	resp2, err := inst.client.Do(req2)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	require.NotContains(t, string(body2), live, "/states must not leak the live bearer")
}

// TestMgmtReadMasksBearer covers ADR 0022 §3: an admin/mgmt GET of stream config
// returns the masking sentinel for the bearer (never the live credential), and
// does not rotate.
func TestMgmtReadMasksBearer(t *testing.T) {
	inst, err := createServer(t, "rotate-mask", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	live := cfg.Delivery.PollTransmitMethod.AuthorizationHeader

	status, got := getStreamConfig(t, inst, cfg.Id, "Bearer "+inst.streamMgmtToken)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, model.MaskedCredentialValue, got.Delivery.PollTransmitMethod.AuthorizationHeader,
		"mgmt read must mask the bearer")

	// And the stored live bearer is unchanged (no rotation on a mgmt read).
	state, err := inst.GetStreamState(cfg.Id)
	require.NoError(t, err)
	require.Equal(t, live, state.Delivery.PollTransmitMethod.AuthorizationHeader,
		"mgmt read must not rotate the stored bearer")
}

// TestHolderGetRotatesBearer covers ADR 0022 §1: a GET authenticated by the
// stream's current delivery bearer rotates it — the response carries a fresh,
// live bearer different from the old, and it is persisted. Gated on.
func TestHolderGetRotatesBearer(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	inst, err := createServer(t, "rotate-fire", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	live := cfg.Delivery.PollTransmitMethod.AuthorizationHeader

	status, got := getStreamConfig(t, inst, cfg.Id, live)
	require.Equal(t, http.StatusOK, status, "holder must be authorized to read its own stream config")
	newBearer := got.Delivery.PollTransmitMethod.AuthorizationHeader
	require.NotEmpty(t, newBearer)
	require.NotEqual(t, model.MaskedCredentialValue, newBearer, "rotation response must carry the LIVE new bearer")
	require.NotEqual(t, live, newBearer, "rotation must change the bearer")

	state, err := inst.GetStreamState(cfg.Id)
	require.NoError(t, err)
	require.Equal(t, newBearer, state.Delivery.PollTransmitMethod.AuthorizationHeader, "rotated bearer must be persisted")
}

// TestHolderGetNoRotateWhenDisabled covers ADR 0022 §4: with the gate off, a
// holder GET still reads (the carve-out), but the bearer is masked and unchanged.
func TestHolderGetNoRotateWhenDisabled(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "false")
	inst, err := createServer(t, "rotate-off", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	live := cfg.Delivery.PollTransmitMethod.AuthorizationHeader

	status, got := getStreamConfig(t, inst, cfg.Id, live)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, model.MaskedCredentialValue, got.Delivery.PollTransmitMethod.AuthorizationHeader,
		"with gate off the read is masked and no rotation occurs")

	state, err := inst.GetStreamState(cfg.Id)
	require.NoError(t, err)
	require.Equal(t, live, state.Delivery.PollTransmitMethod.AuthorizationHeader, "no rotation while gate off")
}

// TestLostResponseRereadReturnsLiveCurrentBearer covers ADR 0022 §2: a GET that
// presents the OLD (now-superseded) bearer during the grace window — the
// lost-response recovery path — returns the SAME current bearer (LIVE, not
// masked) without minting a third credential.
func TestLostResponseRereadReturnsLiveCurrentBearer(t *testing.T) {
	t.Setenv("I2SIG_BEARER_ROTATE_ON_GET", "true")
	t.Setenv("I2SIG_BEARER_ROTATE_GRACE", "1h")
	inst, err := createServer(t, "rotate-reread", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	oldLive := cfg.Delivery.PollTransmitMethod.AuthorizationHeader

	// First GET with the live bearer rotates -> new live bearer.
	status, got := getStreamConfig(t, inst, cfg.Id, oldLive)
	require.Equal(t, http.StatusOK, status)
	newBearer := got.Delivery.PollTransmitMethod.AuthorizationHeader
	require.NotEqual(t, oldLive, newBearer)
	require.NotEqual(t, model.MaskedCredentialValue, newBearer)

	// Lost-response re-read: present the OLD bearer again (still valid in-window).
	// It must return the SAME current bearer, live, and not mint a third.
	status2, got2 := getStreamConfig(t, inst, cfg.Id, oldLive)
	require.Equal(t, http.StatusOK, status2)
	require.Equal(t, newBearer, got2.Delivery.PollTransmitMethod.AuthorizationHeader,
		"lost-response re-read must return the current live bearer")

	state, err := inst.GetStreamState(cfg.Id)
	require.NoError(t, err)
	require.Equal(t, newBearer, state.Delivery.PollTransmitMethod.AuthorizationHeader,
		"re-read must not mint a third credential")
}

// TestUpdateWithSentinelLeavesCredentialUnchanged covers ADR 0022 §3: a PUT body
// echoing the masking sentinel for the bearer leaves the stored live credential
// in place (read-edit-write must not clobber it).
func TestUpdateWithSentinelLeavesCredentialUnchanged(t *testing.T) {
	inst, err := createServer(t, "rotate-update", true)
	require.NoError(t, err)
	defer inst.ts.Close()

	cfg := rotateCreatePollStream(t, inst)
	live := cfg.Delivery.PollTransmitMethod.AuthorizationHeader

	// Simulate read-edit-write: take the masked config and PUT it back with a
	// changed description but the sentinel bearer.
	update := cfg
	update.Description = "edited"
	update.Delivery = &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{
		Method:              model.DeliveryPoll,
		EndpointUrl:         cfg.Delivery.PollTransmitMethod.EndpointUrl,
		AuthorizationHeader: model.MaskedCredentialValue,
	}}
	b, _ := json.Marshal(update)
	url := fmt.Sprintf("http://%s/stream?stream_id=%s", inst.host, cfg.Id)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inst.streamMgmtToken)
	resp, err := inst.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	state, err := inst.GetStreamState(cfg.Id)
	require.NoError(t, err)
	require.Equal(t, live, state.Delivery.PollTransmitMethod.AuthorizationHeader,
		"sentinel in update body must leave the stored bearer unchanged")
}
