package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Per-direction receive_mode on an SSTP bootstrap (issue #306, Part 1).
//
// One SstpDirection describes one logical stream and has two ends. mode is the
// transmitting end's choice (relay verbatim FW, or re-sign PB) and is read with
// == FW; the receiving end's route mode is read with == IM (import only, or
// route on). Before receive_mode both ends were written from the same word, so
// "relay verbatim, import only" could not be expressed. These pin that the
// receiving end now takes receive_mode when present, that the field crosses to
// the peer with its direction, that it is validated beside mode, echoed on the
// record, and that a bootstrap without it behaves exactly as before.

func receiveModeDirection(mode, receiveMode string) model.SstpDirection {
	return model.SstpDirection{
		Iss:         "https://alpha.example.com",
		Aud:         []string{"https://beta.example.com"},
		Mode:        mode,
		ReceiveMode: receiveMode,
	}
}

func TestValidateSstpDirectionReceiveMode(t *testing.T) {
	cases := []struct {
		name        string
		receiveMode string
		wantErr     bool
	}{
		{name: "absent", receiveMode: ""},
		{name: "IMPORT", receiveMode: model.SstpModeImport},
		{name: "FORWARD", receiveMode: model.SstpModeForward},
		{name: "PUBLISH is a transmitter choice", receiveMode: model.SstpModePublish, wantErr: true},
		{name: "case-sensitive", receiveMode: "import", wantErr: true},
		{name: "unknown", receiveMode: "BOGUS", wantErr: true},
	}
	for _, tc := range cases {
		for _, half := range []string{"primary", "inbound"} {
			t.Run(half+"/"+tc.name, func(t *testing.T) {
				err := validateSstpDirection(half, receiveModeDirection(model.SstpModeForward, tc.receiveMode))
				if !tc.wantErr {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), "invalid "+half+".receive_mode"),
					"the message must name the field and its direction, got %q", err.Error())
				assert.Contains(t, err.Error(), "IMPORT, FORWARD")
			})
		}
	}
}

// The combination the issue's table marks "no": this node relays its outbound
// verbatim and the peer only imports it; the peer re-signs its outbound and this
// node routes it on. The local receiving end (the inbound half) takes its route
// mode from receive_mode, the local transmitting end keeps mode, and each
// direction's receive_mode is echoed on the record.
func TestBuildSstpRecordTakesTheReceivingEndsRouteModeFromReceiveMode(t *testing.T) {
	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: receiveModeDirection(model.SstpModeForward, model.SstpModeImport),
		Inbound: receiveModeDirection(model.SstpModePublish, model.SstpModeForward),
	}, "", "")

	assert.Equal(t, model.RouteModeForward, rec.StreamConfiguration.RouteMode,
		"the transmitting end keeps mode; its receive_mode is the peer's")
	require.NotNil(t, rec.SstpInbound)
	assert.Equal(t, model.RouteModeForward, rec.SstpInbound.RouteMode,
		"the receiving end takes receive_mode FORWARD, not mode PUBLISH")

	assert.Equal(t, model.SstpModeImport, rec.ReceiveMode)
	assert.Equal(t, model.SstpModeForward, rec.InboundReceiveMode)
}

func TestBuildSstpRecordImportOnlyReceiveMode(t *testing.T) {
	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: receiveModeDirection(model.SstpModePublish, ""),
		Inbound: receiveModeDirection(model.SstpModeForward, model.SstpModeImport),
	}, "", "")

	require.NotNil(t, rec.SstpInbound)
	assert.Equal(t, model.RouteModeImport, rec.SstpInbound.RouteMode,
		"relay verbatim at the far end, import only here")
	assert.Empty(t, rec.ReceiveMode, "an absent primary receive_mode stores nothing")
	assert.Equal(t, model.SstpModeImport, rec.InboundReceiveMode)
}

// Absent on both halves: the receiving end mirrors mode exactly as before, and
// nothing new is stored or serialized.
func TestBuildSstpRecordWithoutReceiveModeMirrorsMode(t *testing.T) {
	for _, mode := range []string{"", model.SstpModePublish, model.SstpModeForward, model.SstpModeImport} {
		t.Run("mode="+mode, func(t *testing.T) {
			mid, pairId := pairIds(t)
			rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
				Role:    model.SstpRoleResponder,
				Primary: receiveModeDirection(mode, ""),
				Inbound: receiveModeDirection(mode, ""),
			}, "", "")

			want, ok := model.SstpModeToRouteMode(mode)
			require.True(t, ok)
			assert.Equal(t, want, rec.StreamConfiguration.RouteMode)
			assert.Equal(t, want, rec.SstpInbound.RouteMode)
			assert.Empty(t, rec.ReceiveMode)
			assert.Empty(t, rec.InboundReceiveMode)

			raw, err := json.Marshal(rec)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "receive_mode")
		})
	}
}

// The swap is whole-struct, so receive_mode crosses with its direction: what
// this node asked of the peer's receiving end for its outbound becomes the
// peer's inbound, where the peer's buildSstpRecord applies it.
func TestMirrorSstpBootstrapSwapsReceiveModeWithItsDirection(t *testing.T) {
	b := model.SstpPairBootstrap{
		Role:    model.SstpRoleInitiator,
		Primary: receiveModeDirection(model.SstpModeForward, model.SstpModeImport),
		Inbound: receiveModeDirection(model.SstpModePublish, model.SstpModeForward),
	}
	mirror := mirrorSstpBootstrap(&model.StreamStateRecord{PairId: "pair-1"}, b)

	assert.Equal(t, model.SstpModeForward, mirror.Primary.ReceiveMode)
	assert.Equal(t, model.SstpModeImport, mirror.Inbound.ReceiveMode)

	// And the peer, building its record from the mirror, lands both ends on the
	// choices this node's operator made.
	mid, pairId := pairIds(t)
	peer := (&StreamService{}).buildSstpRecord(mid, pairId, "peer-rx", "project-1", mirror, "", "")
	assert.Equal(t, model.RouteModePublish, peer.StreamConfiguration.RouteMode, "the peer re-signs what it sends here")
	assert.Equal(t, model.RouteModeImport, peer.SstpInbound.RouteMode, "the peer only imports what this node relays")
}

// A bootstrap without receive_mode must reach the peer byte-for-byte as it did
// before the field existed.
func TestMirrorSstpBootstrapWithoutReceiveModeIsByteIdentical(t *testing.T) {
	b := model.SstpPairBootstrap{
		Role:        model.SstpRoleInitiator,
		Description: "pair",
		Primary:     receiveModeDirection(model.SstpModeForward, ""),
		Inbound:     receiveModeDirection(model.SstpModeImport, ""),
	}
	raw, err := json.Marshal(mirrorSstpBootstrap(&model.StreamStateRecord{PairId: "pair-1"}, b))
	require.NoError(t, err)

	const want = `{"role":"responder","peer_pair_id":"pair-1","description":"pair",` +
		`"primary":{"iss":"https://alpha.example.com","aud":["https://beta.example.com"],"mode":"IMPORT"},` +
		`"inbound":{"iss":"https://alpha.example.com","aud":["https://beta.example.com"],"mode":"FORWARD"}}`
	assert.Equal(t, want, string(raw))
}

// Validation runs ahead of any state change: a bad receive_mode on either half
// refuses the create and writes nothing.
func TestCreateSstpPair_RejectsInvalidReceiveMode(t *testing.T) {
	for _, half := range []string{"primary", "inbound"} {
		t.Run(half, func(t *testing.T) {
			svc, _ := sstpFixture(t)
			b := responderBootstrap()
			if half == "primary" {
				b.Primary.ReceiveMode = model.SstpModePublish
			} else {
				b.Inbound.ReceiveMode = "SIDEWAYS"
			}
			_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid "+half+".receive_mode")
			assert.Empty(t, svc.ListStreams(context.Background()), "a refused bootstrap must not persist a record")
		})
	}
}

// The cascade carries receive_mode to the peer on the swapped directions, and
// the local record persists the echo so a later read returns it.
func TestCreateSstpPair_CascadesAndPersistsReceiveMode(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, false)
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := responderBootstrap()
	b.PeerServerAlias = alias
	b.Primary.Mode = model.SstpModeForward
	b.Primary.ReceiveMode = model.SstpModeImport
	b.Inbound.Mode = model.SstpModePublish
	b.Inbound.ReceiveMode = model.SstpModeForward

	rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.NoError(t, err)

	require.True(t, peer.got)
	assert.Equal(t, model.SstpModeForward, peer.lastBootstrap.Primary.ReceiveMode)
	assert.Equal(t, model.SstpModeImport, peer.lastBootstrap.Inbound.ReceiveMode)

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.SstpModeImport, got.ReceiveMode)
	assert.Equal(t, model.SstpModeForward, got.InboundReceiveMode)
	assert.Equal(t, model.RouteModeForward, got.SstpInbound.RouteMode)
}

// route_mode is patchable per side since #306 Part 2. The inbound echo states
// this node's own receiving choice, so a patch that changes that choice must
// not leave the echo saying the old one. The primary echo is the peer's choice,
// which a local patch cannot change, so it is left alone.
func TestUpdateSstpPair_InboundRouteModePatchKeepsTheReceiveModeEchoTrue(t *testing.T) {
	svc, _ := sstpFixture(t)
	ctx := context.Background()
	b := responderBootstrap()
	b.Primary.ReceiveMode = model.SstpModeForward
	b.Inbound.ReceiveMode = model.SstpModeImport
	rec, err := svc.CreateSstpPair(ctx, b, "proj-1", nil)
	require.NoError(t, err)

	_, err = svc.UpdateStream(ctx, rec.SstpInbound.Id, "proj-1", patchRouteMode(model.RouteModeForward))
	require.NoError(t, err)
	got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.RouteModeForward, got.SstpInbound.RouteMode)
	assert.Equal(t, model.SstpModeForward, got.InboundReceiveMode, "the inbound echo follows the patched route mode")
	assert.Equal(t, model.SstpModeForward, got.ReceiveMode, "the peer's choice is not this patch's to change")

	_, err = svc.UpdateStream(ctx, rec.StreamConfiguration.Id, "proj-1", patchRouteMode(model.RouteModeForward))
	require.NoError(t, err)
	got, err = svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.SstpModeForward, got.ReceiveMode, "a tx-side patch leaves the primary echo")
	assert.Equal(t, model.SstpModeForward, got.InboundReceiveMode, "a tx-side patch leaves the inbound echo")

	_, err = svc.UpdateStream(ctx, rec.SstpInbound.Id, "proj-1", patchRouteMode(model.RouteModeImport))
	require.NoError(t, err)
	got, err = svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.SstpModeImport, got.InboundReceiveMode)
}

// A pair bootstrapped without receive_mode has no echo to keep true, and a
// route_mode patch must not start serializing one.
func TestUpdateSstpPair_RouteModePatchWithoutReceiveModeAddsNoEcho(t *testing.T) {
	svc, rec := createdPair(t)
	ctx := context.Background()

	_, err := svc.UpdateStream(ctx, rec.SstpInbound.Id, "proj-1", patchRouteMode(model.RouteModeForward))
	require.NoError(t, err)
	got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.RouteModeForward, got.SstpInbound.RouteMode)
	assert.Empty(t, got.InboundReceiveMode)
	assert.Empty(t, got.ReceiveMode)
}
