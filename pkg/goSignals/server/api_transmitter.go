package server

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// PollEvents implements the server side of RFC8936 Poll-based delivery of SET Tokens
// PollEvents handles requests for SETs via HTTP Poll (RFC8936).
//
// Inputs:
//   - id (path): The stream ID.
//   - Authorization (header): Token with 'event_delivery' scope.
//   - Request body (JSON): Poll parameters (maxEvents, returnImmediately, etc.).
//
// Return values:
//   - 200 OK: JSON object containing sets (SETs) and moreAvailable flag.
//
// Errors:
//   - 400 Bad Request: Invalid request parameters or missing stream ID.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Error during polling or database access.
func (sa *SignalsApplication) PollEvents(w http.ResponseWriter, r *http.Request) {
	PollEventsHandler(sa, w, r)
}

func PollEventsHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeEventDelivery})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx == nil || authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	streamState, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	behavior := os.Getenv("POLL_SRV_BEHAVIOR")
	if behavior == "" {
		behavior = "MODE"
	}

	// Parse the RFC8936 poll request
	pollReq, err := goSetPoll.ParsePollRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Convert to internal model type for application-layer processing
	request := model.PollParameters{
		MaxEvents:         pollReq.MaxEvents,
		ReturnImmediately: pollReq.ReturnImmediately,
		Acks:              pollReq.Acks,
		TimeoutSecs:       pollReq.TimeoutSecs,
	}
	if len(pollReq.SetErrs) > 0 {
		request.SetErrs = make(map[string]model.SetErrorType, len(pollReq.SetErrs))
		for jti, setErr := range pollReq.SetErrs {
			request.SetErrs[jti] = model.SetErrorType{
				Error:       setErr.Error,
				Description: setErr.Description,
			}
		}
	}

	// Determine effective status based on behavior
	effectiveStatus := streamState.Status
	if behavior == "ALWAYSON" && effectiveStatus == model.StreamStateDisable {
		effectiveStatus = model.StreamStatePause
	}

	if behavior == "MODE" || behavior == "ALWAYSON" {
		hasAcksOrErrs := len(request.Acks) > 0 || len(request.SetErrs) > 0

		if effectiveStatus == model.StreamStateDisable {
			if !hasAcksOrErrs {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		} else if effectiveStatus == model.StreamStatePause {
			if !hasAcksOrErrs {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}

		if effectiveStatus != model.StreamStateEnabled {
			request.ReturnImmediately = true
			// backoff rate limiter to prevent repeated requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	wait := ""
	if !request.ReturnImmediately {
		wait = "Long "
	}
	serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] %sPoll received...", authCtx.StreamId, wait))

	// First, process the acknowledgements
	for _, jti := range request.Acks {
		serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] Acking: Jti[%s]", authCtx.StreamId, jti))
		err = sa.GetProvider().AckEvent(jti, authCtx.StreamId, 0)
		if err != nil {
			serverLog.Error("Error acking event in poll", "sid", authCtx.StreamId, "jti", jti, "error", err)
		}
		event := sa.GetProvider().GetEvent(jti)
		serverLog.Debug(fmt.Sprintf("EventOut [%s]: Type: POLL ", sa.Name()))
		sa.GetEventRouter().IncrementCounter(streamState, event, false)
	}

	// Second, log any errors received
	for jti, setError := range request.SetErrs {
		errMsg := fmt.Sprintf("POLL-SRV[%s] ErrReceived: Jti[%s] Type: %s, Desc: %s\n", authCtx.StreamId, jti, setError.Error, setError.Description)
		serverLog.Warn(errMsg)
	}

	sets, more, status := sa.GetEventRouter().PollStreamHandler(authCtx.StreamId, request)

	if status != http.StatusOK {
		http.Error(w, "Stream not found or not ready", status)
		return
	}
	isMore := ""
	if more {
		isMore = "More available"
	}
	if !request.ReturnImmediately && len(sets) == 0 {
		isMore = " Timed out."
	}
	serverLog.Debug(fmt.Sprintf("POLL-SRV[%s], Returning %d SETs. %s", authCtx.StreamId, len(sets), isMore))

	// Use goSetPoll to write the RFC8936 response
	goSetPoll.WritePollResponse(w, goSetPoll.PollResponse{
		Sets:          sets,
		MoreAvailable: more,
	})
}

// PushEvents has been moved to the event router (to avoid an import cycle)
