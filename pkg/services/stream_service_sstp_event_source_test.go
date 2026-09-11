package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Per-direction event_source on an SSTP pair (issue #296).
//
// mode (PUBLISH/FORWARD/IMPORT) and event_source.type (DIRECT/AUDIENCE/EXPLICIT)
// are the two independent axes of ADR 0004: whether a direction re-signs, and
// where its events come from. A pair is two independent logical streams, so each
// half must answer both for itself. Before this, SstpDirection carried only mode
// and every pair direction fell through effectiveEventSourceType to DIRECT.
//
// The design question the issue left open was where the inbound half's
// descriptor is persisted, since StreamStateRecord.EventSource is record-level
// and a pair is one record. These pin the answer: the primary's descriptor is
// the record-level field (the one MatchesStream reads for egress) and the
// inbound's is the InboundEventSource twin, following the same
// InboundStatus/InboundErrorMsg/InboundJwksReadiness convention.

// pairIds mints a record id through pkg/dao/ids, the single sanctioned minting
// seam (TestDriverObjectIDConstructorIsMongoOnly fences the driver constructor
// to the Mongo DAO packages). The hex IS the PairId, per buildSstpRecord's
// aliasing invariant.
func pairIds(t *testing.T) (bson.ObjectID, string) {
	t.Helper()
	hex := ids.NewObjectID()
	oid, err := bson.ObjectIDFromHex(hex)
	require.NoError(t, err)
	return oid, hex
}

func eventSourceDirection(mode string, es *model.EventSource) model.SstpDirection {
	return model.SstpDirection{
		Iss:         "https://alpha.example.com",
		Aud:         []string{"https://beta.example.com"},
		Events:      []string{"*"},
		Mode:        mode,
		EventSource: es,
	}
}

func TestValidateSstpDirectionEventSource(t *testing.T) {
	cases := []struct {
		name    string
		es      *model.EventSource
		wantErr string // empty means the direction must be accepted
	}{
		{name: "absent descriptor is the pre-296 shape and is accepted"},
		{name: "DIRECT", es: &model.EventSource{Type: model.EventSourceDirect}},
		{name: "AUDIENCE", es: &model.EventSource{Type: model.EventSourceAudience}},
		{name: "EXPLICIT naming a source", es: &model.EventSource{
			Type:            model.EventSourceExplicit,
			SourceStreamIds: []string{"88a2e8efa5a46096c9574080"},
		}},
		{
			name:    "empty type is the silent default push and poll already accept",
			es:      &model.EventSource{},
			wantErr: "",
		},
		{
			name:    "EXPLICIT naming nothing",
			es:      &model.EventSource{Type: model.EventSourceExplicit},
			wantErr: "requires a non-empty source_stream_ids",
		},
		{
			name: "source_stream_ids on a type that has no sources to name",
			es: &model.EventSource{
				Type:            model.EventSourceAudience,
				SourceStreamIds: []string{"sid-1"},
			},
			wantErr: "only valid when type is EXPLICIT",
		},
		{
			name:    "unknown type",
			es:      &model.EventSource{Type: "BROADCAST"},
			wantErr: "must be one of DIRECT, AUDIENCE, EXPLICIT",
		},
		{
			name:    "type is case-sensitive, so a lowercased constant is unknown",
			es:      &model.EventSource{Type: "audience"},
			wantErr: "must be one of DIRECT, AUDIENCE, EXPLICIT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSstpDirection("primary", eventSourceDirection(model.SstpModePublish, tc.es))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.True(t, strings.HasPrefix(err.Error(), "primary"),
				"the message must name the direction it came from, got %q", err.Error())
		})
	}
}

// The inbound half is validated on the same terms as the primary. A bootstrap
// that is well-formed outbound and malformed inbound must still be refused.
func TestValidateSstpDirectionEventSourceNamesTheInboundHalf(t *testing.T) {
	err := validateSstpDirection("inbound", eventSourceDirection(
		model.SstpModeImport,
		&model.EventSource{Type: model.EventSourceExplicit},
	))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "inbound"), err.Error())
}

// The deployment the issue says cannot be expressed today: a FORWARD outbound
// relaying two named upstreams, and a PUBLISH inbound routed by audience. Each
// descriptor must land on the half it describes and on no other.
func TestBuildSstpRecordCarriesEachDirectionsEventSource(t *testing.T) {
	outbound := &model.EventSource{
		Type:            model.EventSourceExplicit,
		SourceStreamIds: []string{"88a2e8efa5a46096c9574080", "88a2e8efa5a46096c9574081"},
	}
	inbound := &model.EventSource{Type: model.EventSourceAudience}

	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: eventSourceDirection(model.SstpModeForward, outbound),
		Inbound: eventSourceDirection(model.SstpModePublish, inbound),
	}, "https://alpha.example.com/sstp/1", "Bearer pair")

	require.NotNil(t, rec.EventSource)
	assert.Equal(t, model.EventSourceExplicit, rec.EventSource.Type)
	assert.Equal(t, outbound.SourceStreamIds, rec.EventSource.SourceStreamIds)

	require.NotNil(t, rec.InboundEventSource)
	assert.Equal(t, model.EventSourceAudience, rec.InboundEventSource.Type)
	assert.Empty(t, rec.InboundEventSource.SourceStreamIds)

	// Both axes stay independent: the modes are not the sources.
	assert.Equal(t, model.RouteModeForward, rec.StreamConfiguration.RouteMode)
	assert.Equal(t, model.RouteModePublish, rec.SstpInbound.RouteMode)
}

// A record built from a bootstrap must not alias the request body, or a later
// mutation of the decoded request would reach into stored state.
func TestBuildSstpRecordDoesNotAliasTheRequestEventSource(t *testing.T) {
	ids := []string{"sid-1"}
	boot := model.SstpPairBootstrap{
		Role: model.SstpRoleResponder,
		Primary: eventSourceDirection(model.SstpModePublish, &model.EventSource{
			Type:            model.EventSourceExplicit,
			SourceStreamIds: ids,
		}),
		Inbound: eventSourceDirection(model.SstpModePublish, &model.EventSource{
			Type: model.EventSourceAudience,
		}),
	}

	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", boot, "", "")

	ids[0] = "mutated"
	boot.Inbound.EventSource.Type = model.EventSourceDirect

	assert.Equal(t, []string{"sid-1"}, rec.EventSource.SourceStreamIds)
	assert.Equal(t, model.EventSourceAudience, rec.InboundEventSource.Type)
}

// An absent descriptor must keep the behaviour from before the field existed:
// nothing stored, and routing resolves to DIRECT.
func TestBuildSstpRecordWithoutEventSourceKeepsTheDirectDefault(t *testing.T) {
	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: eventSourceDirection(model.SstpModePublish, nil),
		Inbound: eventSourceDirection(model.SstpModePublish, nil),
	}, "", "")

	assert.Nil(t, rec.EventSource)
	assert.Nil(t, rec.InboundEventSource)
	assert.Equal(t, model.EventSourceDirect, effectiveEventSourceType(rec))
}

// The peer cascade swaps whole directions, so a descriptor must cross with the
// direction that owns it: this node's inbound source is what the peer's primary
// routes on. A field-by-field rewrite of the mirror would drop it silently.
func TestMirrorSstpBootstrapSwapsEventSourceWithItsDirection(t *testing.T) {
	outbound := &model.EventSource{
		Type:            model.EventSourceExplicit,
		SourceStreamIds: []string{"sid-out"},
	}
	inbound := &model.EventSource{Type: model.EventSourceAudience}

	mirror := mirrorSstpBootstrap(
		&model.StreamStateRecord{PairId: "pair-1"},
		model.SstpPairBootstrap{
			Role:    model.SstpRoleInitiator,
			Primary: eventSourceDirection(model.SstpModeForward, outbound),
			Inbound: eventSourceDirection(model.SstpModePublish, inbound),
		},
	)

	require.NotNil(t, mirror.Primary.EventSource)
	assert.Equal(t, model.EventSourceAudience, mirror.Primary.EventSource.Type,
		"the peer's primary must carry what this node called its inbound")
	require.NotNil(t, mirror.Inbound.EventSource)
	assert.Equal(t, model.EventSourceExplicit, mirror.Inbound.EventSource.Type)
	assert.Equal(t, []string{"sid-out"}, mirror.Inbound.EventSource.SourceStreamIds)
}

// The issue's open question about applyEventSource. That helper drops a
// descriptor with a WARN when IsReceiver(), and an SSTP pair is transmitter and
// receiver at once. The answer is that the branch never fires: IsReceiver reads
// the primary Delivery method, which on a pair is DeliverySstp — neither
// ReceivePush nor ReceivePoll. So a pair keeps its primary descriptor, and the
// inbound twin is out of the helper's reach entirely.
func TestApplyEventSourceKeepsAnSstpPairsDescriptors(t *testing.T) {
	mid, pairId := pairIds(t)
	rec := (&StreamService{}).buildSstpRecord(mid, pairId, "rx-sid", "project-1", model.SstpPairBootstrap{
		Role:    model.SstpRoleResponder,
		Primary: eventSourceDirection(model.SstpModePublish, &model.EventSource{Type: model.EventSourceAudience}),
		Inbound: eventSourceDirection(model.SstpModePublish, &model.EventSource{Type: model.EventSourceDirect}),
	}, "", "")

	require.False(t, rec.IsReceiver(), "a pair record is not a receiver by the Delivery-method predicate")

	applyEventSource(rec, &model.EventSource{Type: model.EventSourceExplicit, SourceStreamIds: []string{"sid-9"}})

	assert.Equal(t, model.EventSourceExplicit, rec.EventSource.Type, "the primary descriptor must survive")
	require.NotNil(t, rec.InboundEventSource, "the inbound twin is not applyEventSource's to touch")
	assert.Equal(t, model.EventSourceDirect, rec.InboundEventSource.Type)
}

// The wire body from the issue, decoded as-is. This pins the JSON names on both
// halves, since the admin wizard has been sending this shape while the server
// ignored it.
func TestSstpPairBootstrapDecodesPerDirectionEventSource(t *testing.T) {
	body := []byte(`{
	  "role": "responder",
	  "primary": {
	    "iss": "https://alpha.example.com",
	    "aud": ["https://beta.example.com"],
	    "mode": "FORWARD",
	    "event_source": {
	      "type": "EXPLICIT",
	      "source_stream_ids": ["88a2e8efa5a46096c9574080"]
	    }
	  },
	  "inbound": {
	    "iss": "https://beta.example.com",
	    "aud": ["https://alpha.example.com"],
	    "mode": "PUBLISH",
	    "event_source": { "type": "AUDIENCE" }
	  }
	}`)

	require.True(t, model.IsSstpBootstrapBody(body), "the discriminator must still recognize the body")

	var boot model.SstpPairBootstrap
	require.NoError(t, json.Unmarshal(body, &boot))

	require.NotNil(t, boot.Primary.EventSource)
	assert.Equal(t, model.EventSourceExplicit, boot.Primary.EventSource.Type)
	assert.Equal(t, []string{"88a2e8efa5a46096c9574080"}, boot.Primary.EventSource.SourceStreamIds)

	require.NotNil(t, boot.Inbound.EventSource)
	assert.Equal(t, model.EventSourceAudience, boot.Inbound.EventSource.Type)
	assert.Nil(t, boot.Inbound.EventSource.SourceStreamIds)

	// A direction that omits the field decodes to nil, which is the DIRECT default.
	var bare model.SstpPairBootstrap
	require.NoError(t, json.Unmarshal([]byte(`{"role":"responder","primary":{"iss":"a"},"inbound":{"iss":"b"}}`), &bare))
	assert.Nil(t, bare.Primary.EventSource)
}
