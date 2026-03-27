package goSetPoll

import (
	"encoding/json"
	"net/http"
)

// ParsePollRequest parses the RFC8936 poll request from the HTTP request body.
// Returns the parsed request or an error if the body cannot be decoded.
func ParsePollRequest(r *http.Request) (*PollRequest, error) {
	var req PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

// WritePollResponse writes an RFC8936 poll response as JSON with 200 OK.
func WritePollResponse(w http.ResponseWriter, response PollResponse) {
	if response.Sets == nil {
		response.Sets = make(map[string]string)
	}
	respBytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Error serializing response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}
