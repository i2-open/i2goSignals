package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func sstpBatchStream(mode string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        "sstp-tx-sign",
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: mode,
		},
		PairId: "pair-sign",
	}
}

func sstpBatchEvents(n int) []*model.EventRecord {
	evs := make([]*model.EventRecord, n)
	for i := range evs {
		jti := fmt.Sprintf("jti-%d", i)
		evs[i] = &model.EventRecord{
			Jti: jti,
			Event: goSet.SecurityEventToken{
				RegisteredClaims: jwt.RegisteredClaims{ID: jti},
				Events:           map[string]interface{}{"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{}},
			},
			Original: `{"jti":"` + jti + `"}`,
		}
	}
	return evs
}

// sstpBatchSets pairs each event with a reference whose acknowledgement JTI
// is the inbound JTI.
func sstpBatchSets(events []*model.EventRecord) []eventRouter.OutboundSet {
	sets := make([]eventRouter.OutboundSet, len(events))
	for i, ev := range events {
		sets[i] = eventRouter.OutboundSet{Ref: interfaces.PendingRef{Jti: ev.Jti, AckJti: ev.Jti}, Record: ev}
	}
	return sets
}

// TestBuildSstpSets_SignsWithRefAckJti (#363): each re-signed SET carries the
// acknowledgement JTI of the reference it travels with, and the message is
// keyed by it. The sign site never derives the value.
func TestBuildSstpSets_SignsWithRefAckJti(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	require.NoError(t, err)
	stream := sstpBatchStream(model.RouteModePublish)
	events := sstpBatchEvents(3)
	sets := make([]eventRouter.OutboundSet, len(events))
	for i, ev := range events {
		sets[i] = eventRouter.OutboundSet{Ref: interfaces.PendingRef{Jti: ev.Jti, AckJti: "ack-" + ev.Jti}, Record: ev}
	}

	out, err := buildSstpSets(stream, sets, key, "kid-1", 2)
	require.NoError(t, err)
	require.Len(t, out, 3)
	for _, ev := range events {
		raw, ok := out["ack-"+ev.Jti]
		require.True(t, ok, "SET for %s keyed by its reference's AckJti", ev.Jti)
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
		require.NoError(t, err)
		require.Equal(t, "ack-"+ev.Jti, claims["jti"])
		require.Equal(t, ev.Jti, ev.Event.ID, "the stored token is not modified")
	}
}

// TestBuildSstpSets_SignsBatchAcrossPool: the initiator re-signs a whole
// outbound batch through the signing pool and every SET carries the pair's
// iss/aud and its own jti (ADR 0036).
func TestBuildSstpSets_SignsBatchAcrossPool(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	require.NoError(t, err)
	stream := sstpBatchStream(model.RouteModePublish)
	events := sstpBatchEvents(12)

	sets, err := buildSstpSets(stream, sstpBatchSets(events), key, "kid-1", 4)
	require.NoError(t, err)
	require.Len(t, sets, 12)
	for _, ev := range events {
		raw, ok := sets[ev.Jti]
		require.True(t, ok, "jti %s missing", ev.Jti)
		require.Equal(t, 3, len(strings.Split(raw, ".")), "each SET is a compact JWS")
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
		require.NoError(t, err)
		require.Equal(t, ev.Jti, claims["jti"])
		require.Equal(t, stream.StreamConfiguration.Iss, claims["iss"])
	}
}

// TestBuildSstpSets_FirstSignFailureHalts: AC 5 is preserved under the pool.
// A key RS256 cannot use fails every signature; the error names the first
// JTI in batch order and no partial set map is returned.
func TestBuildSstpSets_FirstSignFailureHalts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	require.NoError(t, err)
	stream := sstpBatchStream(model.RouteModePublish)

	sets, err := buildSstpSets(stream, sstpBatchSets(sstpBatchEvents(8)), key, "kid-1", 4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sign JTI jti-0")
	require.Nil(t, sets)
}

// TestBuildSstpSets_ForwardModeSkipsSigning: forward-mode pairs return the
// stored SET verbatim and never touch the signer.
func TestBuildSstpSets_ForwardModeSkipsSigning(t *testing.T) {
	stream := sstpBatchStream(model.RouteModeForward)
	events := sstpBatchEvents(3)

	sets, err := buildSstpSets(stream, sstpBatchSets(events), nil, "", 4)
	require.NoError(t, err)
	require.Len(t, sets, 3)
	for _, ev := range events {
		require.Equal(t, ev.Original, sets[ev.Jti])
	}
}
