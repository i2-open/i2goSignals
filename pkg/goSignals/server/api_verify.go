package server

import (
	"encoding/json"
	"net/http"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var verifyLog = logger.Sub("VERIFY")

type VerificationRequestPayload struct {
	StreamId string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

// VerificationRequest handles requests to trigger a stream verification event (SSF 8.1.4.2).
//
// Inputs:
//   - Authorization (header): Token with 'event_delivery' or 'stream_mgmt' scope.
//   - Request body (JSON): VerificationRequestPayload containing stream_id and optional state.
//
// Return values:
//   - 204 No Content: Verification event successfully created and added to the stream.
//
// Errors:
//   - 400 Bad Request: Missing stream ID or malformed request body.
//   - 401/403: Unauthorized access or stream ID mismatch.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Database error during event creation or assignment.
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

	// Create the verification event scoped to the requested stream's iss/aud and submit it directly
	// via the operational-event path (point-to-point, bypasses StreamEventMatch).
	event := events.CreateVerifyEvent(payload.StreamId, payload.State, stream.Iss, stream.Aud)
	if _, err := sa.GetEventRouter().SubmitOperationalEvent(payload.StreamId, event, ""); err != nil {
		verifyLog.Error("Error submitting verify event", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
