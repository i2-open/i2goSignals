package server

import (
	"encoding/json"
	"net/http"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var verifyLog = logger.Sub("VERIFY")

type VerificationRequestPayload struct {
	StreamId string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

// VerificationRequest implements the SSF Stream Verification Event process as described in section 8.1.4.2.
func (sa *SignalsApplication) VerificationRequest(w http.ResponseWriter, r *http.Request) {
	verifyLog.Debug("POST VerificationRequest")
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeEventDelivery, authUtil.ScopeStreamMgmt})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	var payload VerificationRequestPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if payload.StreamId == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// The authorization token may already have a stream ID. If it does, it must match.
	if authCtx.StreamId != "" && authCtx.StreamId != payload.StreamId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check if the stream exists
	stream, err := sa.Provider.GetStream(payload.StreamId)
	if err != nil || stream == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Create the verification event
	// We need issuer and audience.
	// Issuer is stream.Iss, Audience is stream.Aud
	event := events.CreateVerifyEvent(payload.StreamId, payload.State, stream.Iss, stream.Aud)

	// Add the event to the system
	eventRec := sa.Provider.AddEvent(event, payload.StreamId, "")

	// Trigger the event on the stream
	streamObjId, err := primitive.ObjectIDFromHex(payload.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sa.Provider.AddEventToStream(eventRec.Jti, streamObjId)

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
