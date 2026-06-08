package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createdPair builds a responder pair (no peer cascade) and returns the
// persisted record so UPDATE/DELETE tests can patch and tear it down.
func createdPair(t *testing.T) (*StreamService, model.StreamStateRecord) {
	t.Helper()
	svc, _ := sstpFixture(t)
	rec, err := svc.CreateSstpPair(context.Background(), responderBootstrap(), "proj-1", nil)
	require.NoError(t, err)
	return svc, rec
}

// TestUpdateSstpPair_RejectsImmutableRole is the tracer bullet: UPDATE on an
// SSTP pair must reject any attempt to change SstpMethod.Role with a 4xx-shaped
// error and leave the persisted record untouched. (Q35)
func TestUpdateSstpPair_RejectsImmutableRole(t *testing.T) {
	svc, rec := createdPair(t)

	patch := model.StreamStateRecord{
		SstpMethod: &model.SstpMethod{Role: model.SstpRoleInitiator},
	}
	_, err := svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role")

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.SstpRoleResponder, got.SstpMethod.Role, "role must be unchanged")
}

// TestUpdateSstpPair_RotatesAuthorizationHeader: a patch that carries only a new
// AuthorizationHeader rotates the per-pair bearer on the live record. (Q35, Q35b)
func TestUpdateSstpPair_RotatesAuthorizationHeader(t *testing.T) {
	svc, rec := createdPair(t)

	patch := model.StreamStateRecord{
		SstpMethod: &model.SstpMethod{AuthorizationHeader: "Bearer rotated-secret"},
	}
	_, err := svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.NoError(t, err)

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, "Bearer rotated-secret", got.SstpMethod.AuthorizationHeader)
	// Role and endpoint are untouched by a bearer-only patch.
	assert.Equal(t, model.SstpRoleResponder, got.SstpMethod.Role)
	assert.Equal(t, rec.SstpMethod.EndpointUrl, got.SstpMethod.EndpointUrl)
}

// TestUpdateSstpPair_PatchesIssAudPerDirection: naming the tx-side SID (PairId)
// patches the primary direction's Iss/Aud; naming the rx-side SID
// (SstpInbound.Id) patches the inbound direction's, leaving the other
// untouched. (Q35)
func TestUpdateSstpPair_PatchesIssAudPerDirection(t *testing.T) {
	t.Run("tx side patches primary", func(t *testing.T) {
		svc, rec := createdPair(t)
		patch := model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{
				Iss: "https://corrected-tx.example",
				Aud: []string{"https://new-aud.example"},
			},
		}
		_, err := svc.UpdateStream(context.Background(), rec.StreamConfiguration.Id, "proj-1", patch)
		require.NoError(t, err)

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, "https://corrected-tx.example", got.StreamConfiguration.Iss)
		assert.Equal(t, []string{"https://new-aud.example"}, got.StreamConfiguration.Aud)
		// inbound untouched
		assert.Equal(t, rec.SstpInbound.Iss, got.SstpInbound.Iss)
		assert.Equal(t, rec.SstpInbound.Aud, got.SstpInbound.Aud)
	})

	t.Run("rx side patches inbound", func(t *testing.T) {
		svc, rec := createdPair(t)
		patch := model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{
				Iss: "https://corrected-rx.example",
				Aud: []string{"https://rx-aud.example"},
			},
		}
		_, err := svc.UpdateStream(context.Background(), rec.SstpInbound.Id, "proj-1", patch)
		require.NoError(t, err)

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, "https://corrected-rx.example", got.SstpInbound.Iss)
		assert.Equal(t, []string{"https://rx-aud.example"}, got.SstpInbound.Aud)
		// primary (tx) untouched
		assert.Equal(t, rec.StreamConfiguration.Iss, got.StreamConfiguration.Iss)
	})
}

// TestUpdateSstpPair_RejectsImmutableEndpointUrl: an EndpointUrl that is already
// set cannot be repointed (Q35) — guards against accidentally aiming a live pair
// at a different peer.
func TestUpdateSstpPair_RejectsImmutableEndpointUrl(t *testing.T) {
	svc, rec := createdPair(t) // responder always has a server-derived EndpointUrl

	patch := model.StreamStateRecord{
		SstpMethod: &model.SstpMethod{EndpointUrl: "https://attacker.example/sstp/x"},
	}
	_, err := svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint_url")

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, rec.SstpMethod.EndpointUrl, got.SstpMethod.EndpointUrl)
}

// TestUpdateSstpPair_RejectsImmutablePeerPairId: a PeerPairId that is already set
// cannot be changed (Q35).
func TestUpdateSstpPair_RejectsImmutablePeerPairId(t *testing.T) {
	svc, rec := createdPair(t)
	// Seed a PeerPairId so the patch attempts a change rather than a fill-in.
	rec.SstpMethod.PeerPairId = "peer-original"
	require.NoError(t, svc.streamDAO.Update(context.Background(), &rec))

	patch := model.StreamStateRecord{
		SstpMethod: &model.SstpMethod{PeerPairId: "peer-different"},
	}
	_, err := svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "peer_pair_id")
}

// TestUpdateSstpPair_FillsInitiallyOmittedPeerConnectivity: staged rollout —
// peer connectivity learned later (EndpointUrl, PeerPairId) may be filled in via
// UPDATE while still unset. (Q35, Q35a)
func TestUpdateSstpPair_FillsInitiallyOmittedPeerConnectivity(t *testing.T) {
	svc, _ := sstpFixture(t)
	// Initiator created with no peer cascade leaves PeerPairId unset; clear the
	// operator-supplied endpoint to exercise a true fill-in.
	b := initiatorBootstrap()
	b.EndpointUrl = ""
	rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.NoError(t, err)
	require.Empty(t, rec.SstpMethod.EndpointUrl)
	require.Empty(t, rec.SstpMethod.PeerPairId)

	patch := model.StreamStateRecord{
		SstpMethod: &model.SstpMethod{
			EndpointUrl: "https://peer.example/sstp/learned",
			PeerPairId:  "peer-learned-123",
		},
	}
	_, err = svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.NoError(t, err)

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, "https://peer.example/sstp/learned", got.SstpMethod.EndpointUrl)
	assert.Equal(t, "peer-learned-123", got.SstpMethod.PeerPairId)
}

// TestUpdateSstpPair_IDsAreImmutable: a patch carrying SIDs/PairId in its
// StreamConfiguration/SstpInbound is ignored — the persisted IDs are unchanged.
// (Q35)
func TestUpdateSstpPair_IDsAreImmutable(t *testing.T) {
	svc, rec := createdPair(t)

	patch := model.StreamStateRecord{
		PairId: "forged-pair-id",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "forged-tx-sid",
			Iss: "https://still-patches.example",
		},
		SstpInbound: &model.StreamConfiguration{Id: "forged-rx-sid"},
	}
	_, err := svc.UpdateStream(context.Background(), rec.PairId, "proj-1", patch)
	require.NoError(t, err)

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, rec.PairId, got.PairId, "PairId must be immutable")
	assert.Equal(t, rec.StreamConfiguration.Id, got.StreamConfiguration.Id, "tx SID must be immutable")
	assert.Equal(t, rec.SstpInbound.Id, got.SstpInbound.Id, "rx SID must be immutable")
	// The legitimate Iss patch still applied.
	assert.Equal(t, "https://still-patches.example", got.StreamConfiguration.Iss)
}
