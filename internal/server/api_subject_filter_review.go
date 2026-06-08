package server

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/i2-open/i2goSignals/pkg/services"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// subjectFilterReviewRequest is the body of POST /subject-filter/review (PRD
// #97 issue #101). stream_id is required; subject is optional — when present
// the response includes a point-lookup result.
type subjectFilterReviewRequest struct {
    StreamId string                   `json:"stream_id"`
    Subject  *goSet.SubjectIdentifier `json:"subject,omitempty"`
}

// subjectFilterReviewResponse is the wire-format admin review of a stream's
// locally managed SSF §8.1.3 subject filter (PRD #97 issue #101). It is the
// stable JSON contract between server, CLI, and goSignalsAdmin; the service
// types in pkg/services are translated to this shape so the wire format does
// not move when internal types refactor.
type subjectFilterReviewResponse struct {
    StreamId                   string                           `json:"stream_id"`
    Mode                       string                           `json:"mode,omitempty"`
    DefaultSubjects            string                           `json:"default_subjects,omitempty"`
    EventSource                *model.EventSource               `json:"event_source"`
    SubjectRemovalGraceSeconds int                              `json:"subject_removal_grace_seconds"`
    PassthruNoLocalFilter      bool                             `json:"passthru_no_local_filter,omitempty"`
    Counts                     *subjectFilterReviewCounts       `json:"counts,omitempty"`
    Pending                    []subjectFilterReviewEntry       `json:"pending,omitempty"`
    Lookup                     *subjectFilterReviewLookupResult `json:"lookup,omitempty"`
}

type subjectFilterReviewCounts struct {
    Total   int64 `json:"total"`
    Pending int64 `json:"pending"`
}

type subjectFilterReviewEntry struct {
    Subject      *goSet.SubjectIdentifier `json:"subject,omitempty"`
    CanonicalKey string                   `json:"canonical_key"`
    Kind         string                   `json:"kind"`
    EnforceAt    time.Time                `json:"enforce_at"`
}

type subjectFilterReviewLookupResult struct {
    Subject      *goSet.SubjectIdentifier `json:"subject"`
    Found        bool                     `json:"found"`
    Kind         string                   `json:"kind,omitempty"`
    CanonicalKey string                   `json:"canonical_key,omitempty"`
    EnforceAt    time.Time                `json:"enforce_at,omitempty"`
    Pending      bool                     `json:"pending,omitempty"`
    Delivers     bool                     `json:"delivers"`
}

// ReviewSubjectFilter handles POST /subject-filter/review (PRD #97 issue #101):
// the read-only admin view of a stream's locally managed subject filter. It is
// admin-scoped (distinct from the per-stream receiver scope used by SSF Add/
// Remove Subject) and inert when subject filtering is disabled server-wide.
//
// Inputs:
//   - Authorization (header): token with ScopeStreamAdmin, ScopeStreamMgmt,
//     or ScopeRoot. The per-stream receiver scope (ScopeEventDelivery) is
//     deliberately rejected — subject review needs an operator privilege.
//   - Body: { stream_id, subject? }. stream_id is required; subject opts a
//     point-lookup result into the response.
//
// Return values:
//   - 200 OK: JSON subjectFilterReviewResponse. A PASSTHRU stream returns
//     passthru_no_local_filter=true and no counts/pending (goSignals keeps no
//     local filter table for PASSTHRU).
//
// Errors:
//   - 400 Bad Request: malformed body or missing stream_id.
//   - 401/403: unauthorized, or a stream-scoped token names a different
//     stream than the body.
//   - 404 Not Found: subject filtering disabled server-wide, or unknown
//     stream.
//   - 500 Internal Server Error: DAO or serialization error.
func (sa *SignalsApplication) ReviewSubjectFilter(w http.ResponseWriter, r *http.Request) {
    ReviewSubjectFilterHandler(sa, w, r)
}

func ReviewSubjectFilterHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json; charset=UTF-8")
    if !services.SubjectFilteringEnabled() {
        // The feature is disabled server-wide; the §9 layer is inert per the
        // PRD's "disabled by default" stance.
        w.WriteHeader(http.StatusNotFound)
        return
    }

    authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{
        authSupport.ScopeStreamAdmin,
        authSupport.ScopeStreamMgmt,
        authSupport.ScopeRoot,
    })
    if status != http.StatusOK {
        w.WriteHeader(status)
        return
    }

    var req subjectFilterReviewRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.StreamId == "" {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    // A stream-bound token (mgmt) must match the requested stream; an admin
    // token has no stream binding and authorizes targeting any stream.
    if authCtx.StreamId != "" && authCtx.StreamId != req.StreamId {
        w.WriteHeader(http.StatusForbidden)
        return
    }

    stream, err := sa.GetStreamService().GetStreamState(r.Context(), req.StreamId)
    if err != nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }

    filterSvc := sa.GetSubjectFilterService()
    if filterSvc == nil {
        w.WriteHeader(http.StatusNotFound)
        return
    }

    review, err := filterSvc.Review(r.Context(), stream, req.Subject)
    if err != nil {
        serverLog.Error("Subject filter review failed", "sid", req.StreamId, "error", err)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    body, err := json.Marshal(buildSubjectFilterReviewResponse(stream, review))
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write(body)
}

// buildSubjectFilterReviewResponse translates the service-layer review into
// the wire-format response. Kept separate so the JSON contract is one tested
// adapter and the service stays free of HTTP concerns.
func buildSubjectFilterReviewResponse(stream *model.StreamStateRecord, review *services.SubjectFilterReview) subjectFilterReviewResponse {
    out := subjectFilterReviewResponse{
        StreamId:                   stream.StreamConfiguration.Id,
        Mode:                       stream.SubjectFilterMode,
        DefaultSubjects:            stream.DefaultSubjects,
        EventSource:                effectiveEventSource(stream.EventSource),
        SubjectRemovalGraceSeconds: effectiveRemovalGrace(stream.SubjectRemovalGraceSeconds),
        PassthruNoLocalFilter:      review.NoLocalFilter,
    }
    if review.Counts != nil {
        out.Counts = &subjectFilterReviewCounts{
            Total:   review.Counts.Total,
            Pending: review.Counts.Pending,
        }
    }
    if len(review.Pending) > 0 {
        out.Pending = make([]subjectFilterReviewEntry, 0, len(review.Pending))
        for _, e := range review.Pending {
            out.Pending = append(out.Pending, subjectFilterReviewEntry{
                Subject:      e.Subject,
                CanonicalKey: e.CanonicalKey,
                Kind:         e.Kind,
                EnforceAt:    e.EnforceAt,
            })
        }
    }
    if review.Lookup != nil {
        out.Lookup = &subjectFilterReviewLookupResult{
            Subject:      review.Lookup.Subject,
            Found:        review.Lookup.Found,
            Kind:         review.Lookup.Kind,
            CanonicalKey: review.Lookup.CanonicalKey,
            EnforceAt:    review.Lookup.EnforceAt,
            Pending:      review.Lookup.Pending,
            Delivers:     review.Lookup.Delivers,
        }
    }
    return out
}

// effectiveEventSource resolves a stream's stored EventSource to the value the
// admin review wire contract surfaces. A nil descriptor has EFFECTIVE type
// AUDIENCE (GH #118 / the nil-EventSource→AUDIENCE decision: an unset source
// behaves as audience matching), so it resolves to {"type":"AUDIENCE"} rather
// than being omitted. A non-nil descriptor is surfaced unchanged.
func effectiveEventSource(es *model.EventSource) *model.EventSource {
    if es == nil {
        return &model.EventSource{Type: model.EventSourceAudience}
    }
    return es
}

// effectiveRemovalGrace resolves the SSF §9.3 grace seconds surfaced by the
// admin review: a non-zero per-stream override wins; otherwise the server-wide
// I2SIG_SUBJECT_REMOVAL_GRACE default. Mirrors SubjectFilterService.resolveGrace
// so the review reports the same effective value the service enforces.
func effectiveRemovalGrace(perStream int) int {
    if perStream > 0 {
        return perStream
    }
    return services.SubjectRemovalGraceDefaultSeconds()
}
