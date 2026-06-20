package test

import (
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pollStreamConfig returns a minimal transmitter POLL stream config with no aud,
// so CreateStream exercises the transmitter-side identity-minting path.
func pollStreamConfig() model.StreamConfiguration {
	return model.StreamConfiguration{
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}
}

// TestCreateStreamMintsOpaqueAudWhenAbsent pins ADR 0024: when a strict SSF
// receiver registers a transmitter stream without asserting aud, goSignals mints
// a stable, opaque, URI-shaped audience identifier (JTI-like) rather than echoing
// the caller's client_id/project_id. The minted aud doubles as the AUDIENCE
// routing handle slice 2 consumes, so it must be present and URI-shaped.
func TestCreateStreamMintsOpaqueAudWhenAbsent(t *testing.T) {
	instance, err := createServer(t, "stream_aud_mint_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(pollStreamConfig(), authCtx)
	require.NoError(t, err)
	require.Len(t, created.Aud, 1, "an absent aud must be minted to exactly one opaque audience")

	minted := created.Aud[0]
	assert.NotEmpty(t, minted, "the transmitter-minted aud must never be empty")
	assert.True(t, strings.Contains(minted, ":"),
		"the minted aud must be URI/URN-shaped, got %q", minted)
	// The opaque identity must NOT leak the caller's client_id or project_id
	// (ADR 0024 supersedes the old client_id/project_id default).
	assert.NotEqual(t, "client-abc123", minted,
		"the minted aud must be opaque, not the caller client_id")
	assert.NotEqual(t, instance.projectId, minted,
		"the minted aud must be opaque, not the caller project_id")
}

// TestCreateStreamMintsAudForOAuthCaller pins that the mint path does not depend
// on a local EAT: an OAuth/STS caller (no client_id) still gets a stable opaque
// audience, not a project-id echo.
func TestCreateStreamMintsAudForOAuthCaller(t *testing.T) {
	instance, err := createServer(t, "stream_aud_mint_oauth_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// ConvertProject yields an AuthContext with ProjectId set and no Eat — the
	// shape of an OAuth/STS-validated caller.
	created, err := instance.CreateStream(pollStreamConfig(), authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	require.Len(t, created.Aud, 1, "an absent aud must be minted even with no local EAT")

	minted := created.Aud[0]
	assert.NotEmpty(t, minted)
	assert.True(t, strings.Contains(minted, ":"),
		"the minted aud must be URI/URN-shaped, got %q", minted)
	assert.NotEqual(t, instance.projectId, minted,
		"the minted aud must be opaque, not the caller project_id")
}

// TestCreateStreamHonorsRequestedAud pins presence-based acceptance: a
// receiver-asserted aud (e.g. a flexible peer that supplies one) is never
// overwritten by the mint — the request wins.
func TestCreateStreamHonorsRequestedAud(t *testing.T) {
	instance, err := createServer(t, "stream_aud_honor_request_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	cfg := pollStreamConfig()
	cfg.Aud = []string{"https://rp.example.com"}

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(cfg, authCtx)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://rp.example.com"}, created.Aud,
		"a receiver-asserted aud must be preserved, not replaced by the mint")
}

// TestCreateStreamMintsIssToAdvertisedIssuer pins ADR 0024 / done-means #2:
// an absent iss is minted to the server's advertised issuer (GetDefIssuer),
// so a strict receiver's "iss == discovered issuer" check passes.
func TestCreateStreamMintsIssToAdvertisedIssuer(t *testing.T) {
	instance, err := createServer(t, "stream_iss_mint_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(pollStreamConfig(), authCtx)
	require.NoError(t, err)

	advertised := instance.app.GetDefIssuer()
	require.NotEmpty(t, advertised, "the server must advertise an issuer")
	assert.Equal(t, advertised, created.Iss,
		"the minted iss must equal the advertised issuer (SSF §8.1.1.1)")
	assert.NotEmpty(t, created.IssuerJWKSUrl,
		"jwks_uri must be derived from the minted iss so the receiver can fetch keys")
	assert.True(t, strings.Contains(created.IssuerJWKSUrl, "jwks"),
		"jwks_uri must point at the transmitter's JWKS, got %q", created.IssuerJWKSUrl)
}

// TestCreateStreamHonorsRequestedIss pins presence-based acceptance for iss: a
// caller-asserted iss is honored verbatim, not overridden by the advertised one.
func TestCreateStreamHonorsRequestedIss(t *testing.T) {
	instance, err := createServer(t, "stream_iss_honor_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	cfg := pollStreamConfig()
	cfg.Iss = "https://issuer.example.com"

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(cfg, authCtx)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", created.Iss,
		"a caller-asserted iss must be preserved, not replaced by the advertised issuer")
}

// TestCreateStreamMintedAudIsStablePersisted pins the production-wiring AC: the
// minted aud is persisted on the stream record and stable across subsequent GETs
// (it does not regenerate on read). The test drives the real StreamService
// CreateStream and GetStream/GetStreamState paths, not a fake.
func TestCreateStreamMintedAudIsStablePersisted(t *testing.T) {
	instance, err := createServer(t, "stream_aud_persist_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	authCtx := &authSupport.AuthContext{
		ProjectId: instance.projectId,
		Eat:       &authSupport.EventAuthToken{ClientId: "client-abc123", ProjectId: instance.projectId},
	}

	created, err := instance.CreateStream(pollStreamConfig(), authCtx)
	require.NoError(t, err)
	require.Len(t, created.Aud, 1)
	minted := created.Aud[0]

	// The minted aud must be persisted on the stream record (config-level).
	got, err := instance.GetStream(created.Id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{minted}, got.Aud,
		"the minted aud must be persisted on the stream and stable across GETs")

	// And again — a second read must return the identical aud (no regeneration).
	got2, err := instance.GetStream(created.Id)
	require.NoError(t, err)
	require.NotNil(t, got2)
	assert.Equal(t, []string{minted}, got2.Aud,
		"repeated GETs must return the identical minted aud")

	// The underlying persisted state record must also carry the minted aud.
	state, err := instance.GetStreamState(created.Id)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, []string{minted}, state.StreamConfiguration.Aud,
		"the minted aud must be persisted on the stream state record")
}
