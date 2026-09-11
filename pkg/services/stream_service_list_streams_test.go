package services

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listFixture is a StreamService over an in-memory stream DAO, plus the DAO
// itself so a test can seed records ListStreams has to project.
func listFixture(t *testing.T) (*StreamService, dao.StreamDAO) {
	t.Helper()
	streamDAO := memory.NewStreamDAO()
	keyService := NewKeyService(memory.NewKeyDAO(), "https://local.example", nil, nil)
	require.NoError(t, keyService.InitializeTokenKey(context.Background(), "https://local.example"))
	svc := NewStreamService(streamDAO, keyService, "https://local.example", StreamServiceConfig{})
	baseUrl, err := url.Parse("https://local.example")
	require.NoError(t, err)
	svc.SetBaseUrl(baseUrl)
	return svc, streamDAO
}

// TestListStreams_SstpPairRoundTripsBothDirections is the tracer bullet for
// issue #300. An SSTP pair is two logical streams in one record — the outbound
// half inline and the inbound half under SstpInbound, each with its own status
// and error reason. ListStreams used to project each record down to its
// embedded StreamConfiguration, so every record-level field was dropped and a
// consumer could see only half of every bidirectional stream: a pair that is
// enabled outbound and paused inbound was indistinguishable from a healthy one.
//
// The bar: a pair survives ListStreams with both directions' status
// distinguishable, and with the fields that describe the pair itself intact.
func TestListStreams_SstpPairRoundTripsBothDirections(t *testing.T) {
	svc, rec := createdPair(t)
	ctx := context.Background()

	// Pause only the receive direction, naming the rx-side SID.
	svc.UpdateStreamStatus(ctx, rec.SstpInbound.Id, model.StreamStatePause, "rx throttled")

	list := svc.ListStreams(ctx)
	require.Len(t, list, 1)
	got := list[0]

	// The two directions report independently.
	assert.Equal(t, model.StreamStateEnabled, got.Status,
		"the transmit direction must still report enabled")
	assert.Empty(t, got.ErrorMsg)
	assert.Equal(t, model.StreamStatePause, got.InboundStatus,
		"the receive direction's own status must survive the projection")
	assert.Equal(t, "rx throttled", got.InboundErrorMsg,
		"the receive direction's own reason must survive the projection")

	// The pair shape itself survives.
	require.NotNil(t, got.SstpInbound, "the entire inbound direction used to be dropped")
	assert.Equal(t, rec.SstpInbound.Id, got.SstpInbound.Id)
	assert.Equal(t, model.DeliverySstpPair, got.GetType())

	// COM-0018: PairId is the on-wire SSF stream_id and SstpMethod.PeerPairId is
	// the only key that joins this node's record for the pair to the peer's.
	assert.Equal(t, rec.PairId, got.PairId)
	require.NotNil(t, got.SstpMethod)
	assert.Equal(t, rec.SstpMethod.Role, got.SstpMethod.Role)
}

// TestListStreams_NeverSurfacesCredentialMaterial pins ADR 0022 §3 on this
// surface: a listing may never emit a live bearer. Widening the projection
// widened what could leak with it — the record-level SstpMethod bearer and the
// inbound direction's credentials were not even reachable from the old return
// type. Masking works on a deep copy, so the stored record keeps its live
// values.
func TestListStreams_NeverSurfacesCredentialMaterial(t *testing.T) {
	svc, streamDAO := listFixture(t)
	ctx := context.Background()

	// Every credential slot the mask covers, each with a distinct live value so a
	// leak names the slot it came from.
	const (
		txBearer    = "Bearer live-tx-delivery-secret"
		txToken     = "live-tx-token-secret"
		inBearer    = "Bearer live-inbound-delivery-secret"
		pairBearer  = "Bearer live-pair-secret"
		maskedValue = model.MaskedCredentialValue
	)

	rec, _, _ := newSstpPairFixture(t, "")
	rec.StreamConfiguration.Delivery.PushTransmitMethod = &model.PushTransmitMethod{
		Method:              model.DeliveryPush,
		AuthorizationHeader: txBearer,
	}
	tok := txToken
	rec.StreamConfiguration.TxToken = &tok
	rec.SstpInbound.Delivery.PushReceiveMethod = &model.PushReceiveMethod{
		Method:              model.ReceivePush,
		AuthorizationHeader: inBearer,
	}
	rec.SstpMethod.AuthorizationHeader = pairBearer
	require.NoError(t, streamDAO.Create(ctx, rec))

	list := svc.ListStreams(ctx)
	require.Len(t, list, 1)
	got := list[0]

	// Serialize the way a consumer receives it: no live value may appear
	// anywhere in the payload, at any nesting depth.
	payload, err := json.Marshal(list)
	require.NoError(t, err)
	for _, secret := range []string{txBearer, txToken, inBearer, pairBearer} {
		assert.NotContains(t, string(payload), secret,
			"a live credential escaped the ListStreams projection")
	}

	// Present-but-masked, not silently dropped — an absent credential and a
	// redacted one must stay distinguishable.
	assert.Equal(t, maskedValue, got.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader)
	require.NotNil(t, got.StreamConfiguration.TxToken)
	assert.Equal(t, maskedValue, *got.StreamConfiguration.TxToken)
	assert.Equal(t, maskedValue, got.SstpInbound.Delivery.PushReceiveMethod.AuthorizationHeader)
	assert.Equal(t, maskedValue, got.SstpMethod.AuthorizationHeader)

	// The mask is a deep copy: the stored record still holds the live values.
	stored, err := streamDAO.FindByID(ctx, rec.StreamConfiguration.Id)
	require.NoError(t, err)
	assert.Equal(t, txBearer, stored.StreamConfiguration.Delivery.PushTransmitMethod.AuthorizationHeader,
		"masking must not mutate the stored record")
	assert.Equal(t, pairBearer, stored.SstpMethod.AuthorizationHeader,
		"masking must not mutate the stored record")
}

// bySid indexes a ListStreams result by the SSF stream_id of each record's
// embedded (transmit-side) configuration.
func bySid(list []model.StreamStateRecord) map[string]model.StreamStateRecord {
	out := make(map[string]model.StreamStateRecord, len(list))
	for _, rec := range list {
		out[rec.StreamConfiguration.Id] = rec
	}
	return out
}

// TestListStreams_OverlaysJwksReadinessOnReceiveDirectionsOnly pins ADR 0033 on
// this surface. Readiness is node-local and derived — it is bson:"-", so records
// come back from the DAO without it and are absent unless overlaid. It belongs
// to a RECEIVE direction, so it lands on a plain receiver's own readiness field
// and on an SSTP pair's inbound twin, and a transmit-only stream has neither.
// The two fields are mutually exclusive: neither record kind carries both.
func TestListStreams_OverlaysJwksReadinessOnReceiveDirectionsOnly(t *testing.T) {
	svc, streamDAO := listFixture(t)
	ctx := context.Background()

	const jwksUrl = "https://issuer.example/jwks.json"

	receiver := newReceiverFixture(t, model.ReceivePush, model.RouteModeImport, "readiness-receiver")
	receiver.StreamConfiguration.IssuerJWKSUrl = jwksUrl
	require.NoError(t, streamDAO.Create(ctx, receiver))

	transmitter := newReceiverFixture(t, model.DeliveryPush, model.RouteModeForward, "readiness-transmitter")
	require.NoError(t, streamDAO.Create(ctx, transmitter))

	pair, pairTxSid, _ := newSstpPairFixture(t, jwksUrl)
	require.NoError(t, streamDAO.Create(ctx, pair))

	got := bySid(svc.ListStreams(ctx))
	require.Len(t, got, 3)

	// A plain receiver reports readiness on its own receive direction. This node
	// has never resolved that URL, so it is unresolved, not ready.
	rx := got[receiver.StreamConfiguration.Id]
	require.NotNil(t, rx.JwksReadiness,
		"a receiver's readiness is absent unless ListStreams overlays it (ADR 0033)")
	assert.Equal(t, model.JwksReadinessUnresolved, rx.JwksReadiness.State)
	assert.Nil(t, rx.InboundJwksReadiness,
		"a plain receiver has no inbound twin to report on")

	// A transmit-only stream expects no verification material at all.
	tx := got[transmitter.StreamConfiguration.Id]
	assert.Nil(t, tx.JwksReadiness,
		"a transmit-only stream has no receive direction, so no readiness")
	assert.Nil(t, tx.InboundJwksReadiness)

	// An SSTP pair's cache entry is keyed by the inbound SID (ADR 0018), so the
	// pair reports readiness on the inbound twin — never on the outbound half.
	sstp := got[pairTxSid]
	require.NotNil(t, sstp.InboundJwksReadiness,
		"an SSTP pair reports readiness on its inbound twin (ADR 0033/0018)")
	assert.Equal(t, model.JwksReadinessUnresolved, sstp.InboundJwksReadiness.State)
	assert.Nil(t, sstp.JwksReadiness,
		"a pair's outbound half transmits; it must not carry readiness")
}

// fixedOrderStreamDAO hands back a known sequence from List, so a test can
// observe whether ListStreams reorders it. The in-memory DAO iterates a map and
// its order is not reproducible between calls, which is precisely why ordering
// cannot be pinned against it.
type fixedOrderStreamDAO struct {
	dao.StreamDAO
	recs []model.StreamStateRecord
}

func (d *fixedOrderStreamDAO) List(context.Context) ([]model.StreamStateRecord, error) {
	return d.recs, nil
}

// TestListStreams_PreservesDaoOrder pins the explicit negative: the projection
// reorders nothing. Ordering is the DAO's to decide, and a consumer that wants a
// different one sorts for itself. The fixture's SIDs and descriptions both
// descend, so a sort on either key would be visible.
func TestListStreams_PreservesDaoOrder(t *testing.T) {
	sids := []string{
		"cccccccccccccccccccccccc",
		"aaaaaaaaaaaaaaaaaaaaaaaa",
		"dddddddddddddddddddddddd",
		"bbbbbbbbbbbbbbbbbbbbbbbb",
	}
	descriptions := []string{"zulu", "alpha", "yankee", "bravo"}

	recs := make([]model.StreamStateRecord, 0, len(sids))
	for i, sid := range sids {
		rec := newReceiverFixture(t, model.DeliveryPush, model.RouteModeForward, descriptions[i])
		rec.StreamConfiguration.Id = sid
		rec.StreamConfiguration.Description = descriptions[i]
		recs = append(recs, *rec)
	}

	keyService := NewKeyService(memory.NewKeyDAO(), "https://local.example", nil, nil)
	require.NoError(t, keyService.InitializeTokenKey(context.Background(), "https://local.example"))
	svc := NewStreamService(&fixedOrderStreamDAO{recs: recs}, keyService, "https://local.example", StreamServiceConfig{})

	got := make([]string, 0, len(sids))
	for _, rec := range svc.ListStreams(context.Background()) {
		got = append(got, rec.StreamConfiguration.Id)
	}

	assert.Equal(t, sids, got, "ListStreams must hand back the DAO's order untouched, not a sorted one")
}

// TestListStreams_PinsWireKeyNames is the compatibility bar for the widening.
// StreamStateRecord embeds StreamConfiguration inline, so every field today's
// readers already consume stays promoted FLAT to the top level under its
// existing name and the change is purely additive on the wire — nothing moved
// into a nested object and nothing was renamed.
//
// It also pins the outbound/inbound error asymmetry, which is a real trap for a
// consumer. Go takes the FIRST json tag it finds, and ErrorMsg's first tag is
// `reason`, so the outbound error serializes as "reason" while its inbound twin
// genuinely is "inbound_error_msg". A consumer-side type that assumed a
// symmetric pair would silently read undefined on the outbound half.
func TestListStreams_PinsWireKeyNames(t *testing.T) {
	svc, streamDAO := listFixture(t)
	ctx := context.Background()

	rec, _, _ := newSstpPairFixture(t, "https://issuer.example/jwks.json")
	rec.StreamConfiguration.Description = "a populated pair"
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.EventsRequested = []string{"urn:example:event"}
	rec.StreamConfiguration.EventsDelivered = []string{"urn:example:event"}
	rec.EventSource = &model.EventSource{Type: model.EventSourceDirect}
	rec.InboundEventSource = &model.EventSource{Type: model.EventSourceAudience}
	rec.Status = model.StreamStatePause
	rec.ErrorMsg = "tx throttled"
	rec.InboundStatus = model.StreamStatePause
	rec.InboundErrorMsg = "rx throttled"
	rec.SstpMethod.PeerPairId = "peer-pair-id-123"
	require.NoError(t, streamDAO.Create(ctx, rec))

	list := svc.ListStreams(ctx)
	require.Len(t, list, 1)

	raw, err := json.Marshal(list[0])
	require.NoError(t, err)
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &keys))

	// The embedded configuration's fields stay flat at the top level, unrenamed.
	for _, name := range []string{
		"stream_id", "iss", "aud", "description", "delivery", "route_mode",
		"events_requested", "events_delivered",
	} {
		assert.Contains(t, keys, name,
			"an embedded StreamConfiguration field must stay promoted flat under its existing name")
	}
	assert.NotContains(t, keys, "events", "there is no `events` key; requested/delivered/supported are distinct")

	// Every record-level field the old projection dropped (#300).
	for _, name := range []string{
		"status", "sstp_inbound", "sstp_method", "pair_id", "event_source",
		"inbound_status", "inbound_error_msg", "inbound_event_source",
		"inbound_jwks_readiness",
	} {
		assert.Contains(t, keys, name, "a record-level field must survive the projection")
	}

	// The asymmetry, asserted on both halves at once.
	assert.Contains(t, keys, "reason", "the OUTBOUND error serializes as `reason` (Go takes the first json tag)")
	assert.NotContains(t, keys, "error_msg", "`error_msg` is the bson name, never the wire name")
	assert.JSONEq(t, `"tx throttled"`, string(keys["reason"]))
	assert.JSONEq(t, `"rx throttled"`, string(keys["inbound_error_msg"]))

	// aud is always an array, never a bare string.
	var aud []string
	require.NoError(t, json.Unmarshal(keys["aud"], &aud))
	assert.Equal(t, []string{"https://peer.example"}, aud)

	// The cross-node join key (ADR COM-0018) survives under its own name.
	var sstpMethod map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(keys["sstp_method"], &sstpMethod))
	assert.Contains(t, sstpMethod, "peer_pair_id")
	assert.JSONEq(t, `"peer-pair-id-123"`, string(sstpMethod["peer_pair_id"]))

	// The inbound direction carries the same configuration key set, nested.
	var inbound map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(keys["sstp_inbound"], &inbound))
	assert.Contains(t, inbound, "stream_id")
	assert.Contains(t, inbound, "iss")

	// Readiness reports its ADR 0033 state.
	var readiness map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(keys["inbound_jwks_readiness"], &readiness))
	assert.Contains(t, readiness, "state")
}
