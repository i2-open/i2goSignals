package services

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/oauthClient"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

// relayBody is the SSF §8.1.3.2/§8.1.3.3 Add/Remove Subject request body sent
// to an upstream transmitter. verified is meaningful for Add only.
type relayBody struct {
    StreamId string                   `json:"stream_id"`
    Subject  *goSet.SubjectIdentifier `json:"subject"`
    Verified bool                     `json:"verified,omitempty"`
}

// RelaySubjectChange relays a PASSTHRU subject change 1:1 to an upstream
// transmitter (issue #95). add selects the upstream endpoint and SSF semantics:
// Add posts to add_subject_endpoint, Remove to remove_subject_endpoint.
// remoteStreamID is the stream_id the upstream assigned to goSignals' receiver
// stream. A non-2xx upstream response is returned as an error.
func RelaySubjectChange(ctx context.Context, client *http.Client, upstream *model.TransmitterConfiguration, authHeader, remoteStreamID string, subject *goSet.SubjectIdentifier, verified, add bool) error {
    endpoint := upstream.RemoveSubjectEndpoint
    if add {
        endpoint = upstream.AddSubjectEndpoint
    }
    if endpoint == "" {
        return errors.New("upstream advertises no subject endpoint to relay to")
    }

    body, err := json.Marshal(relayBody{StreamId: remoteStreamID, Subject: subject, Verified: verified && add})
    if err != nil {
        return err
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    if authHeader != "" {
        req.Header.Set("Authorization", authHeader)
    }
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer func() { _ = resp.Body.Close() }()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("upstream subject relay returned status %d", resp.StatusCode)
    }
    return nil
}

// Relay-target resolution errors (issue #95). Both reject stream configuration
// at config time when a PASSTHRU/HYBRID stream cannot designate an upstream.
var (
    // ErrRelayTargetNotFound means no receiver stream feeds the downstream stream.
    ErrRelayTargetNotFound = errors.New("no upstream receiver stream feeds this stream")
    // ErrRelayTargetAmbiguous means several receiver streams share the issuer and
    // the operator must name a Subject handler SID explicitly.
    ErrRelayTargetAmbiguous = errors.New("multiple receiver streams match the issuer; name a subject handler explicitly")
)

// RelayConfigVerdict is the outcome of validating a transmitter stream's
// subject-filter mode against its upstream's discovery metadata (issue #95). A
// non-nil Err rejects the configuration at config time; a non-empty Warn is a
// survivable misconfiguration the caller logs at WARN while the stream runs.
type RelayConfigVerdict struct {
    Err  error
    Warn string
}

// ClassifyUpstreamSupport reports whether mode is compatible with what the
// upstream advertises. An upstream that advertises neither add_subject_endpoint
// nor remove_subject_endpoint does not support subject filtering at all:
// PASSTHRU/HYBRID then has nowhere to relay and is rejected, while LOCAL still
// works (filtering only what arrives) but earns a WARN.
func ClassifyUpstreamSupport(mode string, upstream *model.TransmitterConfiguration) RelayConfigVerdict {
    supportsFiltering := upstream != nil &&
        upstream.AddSubjectEndpoint != "" && upstream.RemoveSubjectEndpoint != ""

    switch mode {
    case model.SubjectFilterModePassthru, model.SubjectFilterModeHybrid:
        if !supportsFiltering {
            return RelayConfigVerdict{Err: fmt.Errorf(
                "subject_filter_mode %s requires an upstream that advertises add_subject_endpoint and remove_subject_endpoint", mode)}
        }
    case model.SubjectFilterModeLocal:
        if !supportsFiltering {
            return RelayConfigVerdict{Warn: "LOCAL subject filtering against an upstream that does not support subject filtering: only locally-filtered delivery is possible"}
        }
    }
    return RelayConfigVerdict{}
}

// UpstreamConn bundles what a subject relay needs to reach an upstream
// transmitter: its discovery metadata, an HTTP client carrying the upstream
// credential, and an Authorization header value (empty when the client's
// transport already injects the credential). Close, when non-nil, releases the
// HTTP client and must be invoked once the connection is done with.
type UpstreamConn struct {
    Config     *model.TransmitterConfiguration
    HttpClient *http.Client
    AuthHeader string
    Close      func()
}

// release invokes the connection's Close hook when one is set.
func (c *UpstreamConn) release() {
    if c != nil && c.Close != nil {
        c.Close()
    }
}

// NewDefaultUpstreamResolver builds the production UpstreamResolver: it derives
// a model.Server from the receiver stream's upstream credentials (resolving a
// tx_alias through servers when set), obtains a credentialed HTTP client, and
// fetches the upstream's SSF discovery metadata.
func NewDefaultUpstreamResolver(servers *ServerService) UpstreamResolver {
    return func(ctx context.Context, receiver *model.StreamStateRecord) (*UpstreamConn, error) {
        var server *model.Server
        if receiver.TxAlias != nil && *receiver.TxAlias != "" && servers != nil {
            resolved, err := servers.GetServerByAlias(ctx, *receiver.TxAlias)
            if err != nil {
                return nil, fmt.Errorf("cannot resolve upstream tx_alias %q: %w", *receiver.TxAlias, err)
            }
            server = resolved
        }
        if server == nil {
            if receiver.TxWellKnownUrl == nil || *receiver.TxWellKnownUrl == "" {
                return nil, ErrRelayTargetNotFound
            }
            server = &model.Server{Host: *receiver.TxWellKnownUrl, ClientToken: receiver.TxToken}
        }
        client, closeClient, err := oauthClient.GetClientForServer(ctx, server)
        if err != nil {
            return nil, fmt.Errorf("cannot obtain upstream client: %w", err)
        }
        config, err := wellKnownSupport.FetchSSFConfiguration(ctx, client, server.Host)
        if err != nil {
            closeClient()
            return nil, fmt.Errorf("cannot fetch upstream configuration: %w", err)
        }
        return &UpstreamConn{Config: config, HttpClient: client, Close: closeClient}, nil
    }
}

// UpstreamResolver resolves the live connection details for a receiver
// stream's upstream. It is injected so config-time validation and runtime
// relay can be exercised without a live upstream.
type UpstreamResolver func(ctx context.Context, receiver *model.StreamStateRecord) (*UpstreamConn, error)

// InterestPredicate reports whether a downstream transmitter stream's subject
// filter currently selects subject — the HYBRID interested-set membership test
// (issue #96). It is typically SubjectFilterService.Selects.
type InterestPredicate func(ctx context.Context, stream *model.StreamStateRecord, subject *goSet.SubjectIdentifier) bool

// SubjectRelayService relays PASSTHRU/HYBRID subject changes to the upstream
// transmitter and validates a transmitter stream's subject-filter mode against
// its upstream at config time (issue #95).
//
// listTransmitters and interested are the HYBRID interested-set inputs (issue
// #96): the set of downstream transmitter streams and the predicate reporting
// which of them still select a given subject.
type SubjectRelayService struct {
    listReceivers    func(ctx context.Context) ([]model.StreamStateRecord, error)
    resolve          UpstreamResolver
    listTransmitters func(ctx context.Context) ([]model.StreamStateRecord, error)
    interested       InterestPredicate
}

// NewSubjectRelayService constructs a SubjectRelayService. listReceivers
// supplies the receiver streams resolution searches (typically
// StreamService.ListReceiverStreams); listTransmitters supplies the downstream
// transmitter streams the HYBRID interested-set is computed over (typically
// StreamService.ListTransmitterStreams); interested reports HYBRID
// interested-set membership (typically SubjectFilterService.Selects); resolve
// fetches an upstream's discovery and credential.
func NewSubjectRelayService(
    listReceivers func(ctx context.Context) ([]model.StreamStateRecord, error),
    listTransmitters func(ctx context.Context) ([]model.StreamStateRecord, error),
    interested InterestPredicate,
    resolve UpstreamResolver,
) *SubjectRelayService {
    return &SubjectRelayService{
        listReceivers:    listReceivers,
        resolve:          resolve,
        listTransmitters: listTransmitters,
        interested:       interested,
    }
}

// Relay relays a subject change for the downstream transmitter stream to its
// upstream transmitter — the PASSTHRU path of issue #95. It resolves the
// feeding receiver stream, fetches the upstream connection, and posts the
// Add/Remove carrying the upstream's assigned stream id.
func (s *SubjectRelayService) Relay(ctx context.Context, downstream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified, add bool) error {
    receivers, err := s.listReceivers(ctx)
    if err != nil {
        return err
    }
    target, err := ResolveRelayTarget(downstream, receivers)
    if err != nil {
        return err
    }
    conn, err := s.resolve(ctx, target)
    if err != nil {
        return err
    }
    defer conn.release()
    remoteStreamID := ""
    if target.RemoteStreamId != nil {
        remoteStreamID = *target.RemoteStreamId
    }
    return RelaySubjectChange(ctx, conn.HttpClient, conn.Config, conn.AuthHeader, remoteStreamID, subject, verified, add)
}

// RelayHybrid relays a HYBRID downstream stream's subject change to the
// upstream transmitter only when the change crosses the interested-set 0↔1
// boundary (issue #96). The caller has already written downstream's own local
// filter; RelayHybrid decides whether the shared upstream subscription must
// follow.
//
// Relay is engaged only against a defaultSubjects=NONE upstream: against an ALL
// upstream every subject is delivered by default, so relaying a remove could
// starve a not-yet-created downstream — there HYBRID is pure local filtering.
// When engaged, RelayHybrid counts the other HYBRID downstreams fed by the same
// subject handler that still select the subject. Because downstream's own
// change is already applied, a count of zero means this change moved the
// interested-set across the boundary — an add as the first downstream appears
// (0→1) or a remove as the last one drops (1→0) — and the relay fires. A
// sibling still interested suppresses the relay, so one downstream's change
// never starves another.
func (s *SubjectRelayService) RelayHybrid(ctx context.Context, downstream *model.StreamStateRecord, subject *goSet.SubjectIdentifier, verified, add bool) error {
    receivers, err := s.listReceivers(ctx)
    if err != nil {
        return err
    }
    target, err := ResolveRelayTarget(downstream, receivers)
    if err != nil {
        return err
    }
    // HYBRID relays only against a NONE upstream (see the doc comment).
    if target.DefaultSubjects != model.DefaultSubjectsNone {
        return nil
    }
    transmitters, err := s.listTransmitters(ctx)
    if err != nil {
        return err
    }
    for i := range transmitters {
        sibling := &transmitters[i]
        if sibling.StreamConfiguration.Id == downstream.StreamConfiguration.Id {
            continue // self — its change is already applied and not double-counted
        }
        if sibling.SubjectFilterMode != model.SubjectFilterModeHybrid {
            continue
        }
        siblingTarget, err := ResolveRelayTarget(sibling, receivers)
        if err != nil || siblingTarget.StreamConfiguration.Id != target.StreamConfiguration.Id {
            continue // a sibling fed by a different subject handler
        }
        if s.interested(ctx, sibling, subject) {
            return nil // a sibling still wants the subject — not a 0↔1 transition
        }
    }
    conn, err := s.resolve(ctx, target)
    if err != nil {
        return err
    }
    defer conn.release()
    remoteStreamID := ""
    if target.RemoteStreamId != nil {
        remoteStreamID = *target.RemoteStreamId
    }
    return RelaySubjectChange(ctx, conn.HttpClient, conn.Config, conn.AuthHeader, remoteStreamID, subject, verified, add)
}

// ValidateConfig checks a downstream transmitter stream's subject-filter mode
// against its upstream at config time. A PASSTHRU/HYBRID stream with no
// resolvable relay target, or whose upstream advertises no subject endpoints,
// is rejected; a LOCAL stream is never rejected but may earn a WARN.
func (s *SubjectRelayService) ValidateConfig(ctx context.Context, downstream *model.StreamStateRecord) RelayConfigVerdict {
    mode := downstream.SubjectFilterMode
    if mode == "" {
        return RelayConfigVerdict{}
    }
    receivers, err := s.listReceivers(ctx)
    if err != nil {
        return RelayConfigVerdict{Err: err}
    }
    target, err := ResolveRelayTarget(downstream, receivers)
    if err != nil {
        // PASSTHRU/HYBRID must relay, so an unresolved target is fatal; LOCAL
        // does not relay and tolerates having no upstream subject handler.
        if mode == model.SubjectFilterModePassthru || mode == model.SubjectFilterModeHybrid {
            return RelayConfigVerdict{Err: err}
        }
        return RelayConfigVerdict{}
    }
    conn, err := s.resolve(ctx, target)
    if err != nil {
        return RelayConfigVerdict{Err: err}
    }
    defer conn.release()
    return ClassifyUpstreamSupport(mode, conn.Config)
}

// ResolveRelayTarget finds the receiver stream that feeds a downstream
// transmitter stream's events — the upstream a PASSTHRU/HYBRID subject change
// must relay to (issue #95). receivers is the caller's set of receiver streams
// (model.StreamStateRecord.IsReceiver()).
//
// An explicitly named Subject handler SID (downstream.EventSource.SourceStreamIds)
// always wins. Otherwise an AUDIENCE-routed stream is resolved by matching the
// downstream issuer against each receiver's issuer; several issuer matches make
// the target ambiguous.
func ResolveRelayTarget(downstream *model.StreamStateRecord, receivers []model.StreamStateRecord) (*model.StreamStateRecord, error) {
    // An explicitly named Subject handler SID resolves the target directly.
    if downstream.EventSource != nil && len(downstream.EventSource.SourceStreamIds) > 0 {
        sid := downstream.EventSource.SourceStreamIds[0]
        for i := range receivers {
            if receivers[i].StreamConfiguration.Id == sid {
                return &receivers[i], nil
            }
        }
        return nil, ErrRelayTargetNotFound
    }
    var matches []*model.StreamStateRecord
    for i := range receivers {
        if receivers[i].StreamConfiguration.Iss == downstream.StreamConfiguration.Iss {
            matches = append(matches, &receivers[i])
        }
    }
    switch len(matches) {
    case 0:
        return nil, ErrRelayTargetNotFound
    case 1:
        return matches[0], nil
    default:
        return nil, ErrRelayTargetAmbiguous
    }
}
