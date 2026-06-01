package authUtil

import (
    "context"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// captureTracker records every TrackToken call so a test can inspect the
// persisted JTI/parent lineage without reaching into a DAO.
type captureTracker struct {
    tracked []trackedCall
}

type trackedCall struct {
    jti     string
    parent  string
    purpose string
}

func (c *captureTracker) TrackToken(_ context.Context, claims *authSupport.EventAuthToken, parent string, purpose string) error {
    c.tracked = append(c.tracked, trackedCall{jti: claims.ID, parent: parent, purpose: purpose})
    return nil
}

func (c *captureTracker) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// TestParentLineage proves Parent is the immediate parent JTI at each mint
// site: IAT is the root (empty parent); a stream-client token's parent is the
// IAT JTI; a delivery (stream) token's parent is the stream-client JTI.
func TestParentLineage(t *testing.T) {
    issuer := initMockIssuer()
    tracker := &captureTracker{}
    issuer.TokenTracker = tracker

    // IAT — root, no parent.
    _, err := issuer.IssueProjectIat(nil)
    require.NoError(t, err)
    require.Len(t, tracker.tracked, 1)
    iat := tracker.tracked[0]
    assert.Equal(t, model.TokenTypeIAT, iat.purpose)
    assert.Empty(t, iat.parent, "IAT is the lineage root and has no parent")

    // Stream-client token — parent is the IAT JTI.
    iatCtx := &AuthContext{Eat: &authSupport.EventAuthToken{}}
    iatCtx.Eat.ID = iat.jti
    _, err = issuer.IssueStreamClientToken(model.SsfClient{
        Id:         bson.NewObjectID(),
        ProjectIds: []string{"abc"},
    }, "abc", false, iat.jti)
    require.NoError(t, err)
    require.Len(t, tracker.tracked, 2)
    streamClient := tracker.tracked[1]
    assert.Equal(t, model.TokenTypeStream, streamClient.purpose)
    assert.Equal(t, iat.jti, streamClient.parent)

    // Delivery (stream) token — parent is the stream-client JTI, taken from
    // the issuing session's EAT.
    session := &AuthContext{Eat: &authSupport.EventAuthToken{}}
    session.Eat.ID = streamClient.jti
    _, err = issuer.IssueStreamToken("stream-1", "abc", session)
    require.NoError(t, err)
    require.Len(t, tracker.tracked, 3)
    delivery := tracker.tracked[2]
    assert.Equal(t, streamClient.jti, delivery.parent)
}
