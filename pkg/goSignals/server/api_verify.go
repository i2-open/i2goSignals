package server

import (
	"encoding/json"
	"net/http"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var verifyLog = logger.Sub("VERIFY")

type VerificationRequestPayload struct {
	StreamId string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

// VerificationRequest implements the SSF Stream Verification Event process as described in section 8.1.4.2.
func (sa *SignalsApplication) VerificationRequest(w http.ResponseWriter, r *http.Request) {
	VerificationRequestHandler(sa, w, r)
}

func VerificationRequestHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	verifyLog.Debug("POST VerificationRequest")
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt})

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
	stream, err := sa.GetProvider().GetStream(payload.StreamId)
	if err != nil || stream == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Create the verification event
	// We need issuer and audience.
	// Issuer is stream.Iss, Audience is stream.Aud
	event := events.CreateVerifyEvent(payload.StreamId, payload.State, stream.Iss, stream.Aud)

	// Add the event to the system
	eventRec, err := sa.GetProvider().AddEvent(event, payload.StreamId, "")
	if err != nil {
		verifyLog.Error("Error adding verify event", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Trigger the event on the stream
	streamObjId, err := bson.ObjectIDFromHex(payload.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = sa.GetProvider().AddEventToStream(eventRec.Jti, streamObjId)
	if err != nil {
		verifyLog.Error("Error adding verify event to stream", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
