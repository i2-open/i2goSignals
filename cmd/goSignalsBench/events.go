package main

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// audMix selects which downstream audience(s) each generated SET carries. The
// goSignals1 ingress stream accepts every audience; the three transmitter legs
// (push, poll, sstp) each match one, so the mix decides how the router fans
// events out.
type audMix string

const (
	mixAlternate audMix = "alternate" // round-robin: push, poll, sstp, push, ...
	mixAll       audMix = "all"       // every event carries all three audiences (3x fan-out)
	mixPush      audMix = "push"      // push audience only
	mixPoll      audMix = "poll"      // poll audience only
	mixSstp      audMix = "sstp"      // sstp audience only
)

// legCount is the number of downstream legs the harness builds.
const legCount = 3

func parseAudMix(s string) (audMix, error) {
	switch audMix(s) {
	case mixAlternate, mixAll, mixPush, mixPoll, mixSstp:
		return audMix(s), nil
	case "both": // pre-SSTP spelling of "all"
		return mixAll, nil
	}
	return "", fmt.Errorf("unknown --mix %q (alternate|all|push|poll|sstp)", s)
}

// usesSstp reports whether the mix sends any event over the SSTP leg. When it
// does not, the harness skips creating the SSTP pair, so a run can target a
// server that rejects the pair (older scope rules) or has no SSTP at all.
func (m audMix) usesSstp() bool {
	_, _, sstp := m.expected(legCount)
	return sstp > 0
}

// expected returns how many of n events each leg should deliver.
func (m audMix) expected(n int) (push, poll, sstp int) {
	switch m {
	case mixAlternate:
		return (n + 2) / legCount, (n + 1) / legCount, n / legCount
	case mixAll:
		return n, n, n
	case mixPush:
		return n, 0, 0
	case mixPoll:
		return 0, n, 0
	default:
		return 0, 0, n
	}
}

func (m audMix) audiences(i int, pushAud, pollAud, sstpAud string) []string {
	switch m {
	case mixAlternate:
		switch i % legCount {
		case 0:
			return []string{pushAud}
		case 1:
			return []string{pollAud}
		default:
			return []string{sstpAud}
		}
	case mixAll:
		return []string{pushAud, pollAud, sstpAud}
	case mixPush:
		return []string{pushAud}
	case mixPoll:
		return []string{pollAud}
	default:
		return []string{sstpAud}
	}
}

// benchEventTypes are the SCIM profile (RFC 9967) event types the harness
// rotates through so every leg carries a realistic type mix.
var benchEventTypes = []string{
	model.EventScimCreateFull,
	model.EventScimPatchFull,
	model.EventScimDelete,
}

// benchEvent is one pre-built SET, signed by the ingest worker just before
// its POST so the toe it carries marks the start of delivery (#325).
type benchEvent struct {
	set goSet.SecurityEventToken
}

// signNow stamps toe with the current time and signs the SET. toe keeps its
// sub-second part on the wire (goSet toe codec), so the receiver's
// event-age histogram resolves milliseconds.
func (e *benchEvent) signNow(key *rsa.PrivateKey) (string, error) {
	e.set.TimeOfEvent = &jwt.NumericDate{Time: time.Now()}
	return e.set.JWS(jwt.SigningMethodRS256, key)
}

// buildEvent creates the i-th SET, unsigned. The payload shapes mirror the
// i2scim cluster demo (a SCIM User resource) so validators, when enabled, see
// the same data the SCIM nodes send.
func buildEvent(i int, issuer string, aud []string) benchEvent {
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier(fmt.Sprintf("/Users/bench-%08d", i)).AddExternalId(fmt.Sprintf("bench%d", i)),
	}
	set := goSet.CreateSet(subject, issuer, aud)
	eventType := benchEventTypes[i%len(benchEventTypes)]
	var payload map[string]any
	switch eventType {
	case model.EventScimDelete:
		payload = map[string]any{}
	case model.EventScimPatchFull:
		payload = map[string]any{
			"data": map[string]any{
				"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"active":  i%4 != 0,
				"title":   fmt.Sprintf("Engineer %d", i%7),
			},
		}
	default:
		payload = map[string]any{
			"data": map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"userName": fmt.Sprintf("bench%d", i),
				"name":     map[string]string{"givenName": "Bench", "familyName": fmt.Sprintf("User%d", i)},
				"emails": []map[string]string{
					{"type": "work", "value": fmt.Sprintf("bench%d@example.com", i)},
				},
			},
		}
	}
	set.AddEventPayload(eventType, payload)
	return benchEvent{set: set}
}

// buildEvents builds all n SETs ahead of ingest. They are signed by the
// ingest workers just before each POST (benchEvent.signNow), outside the
// timed POST, so client-side signing stays out of the ingest latency samples.
func buildEvents(n int, issuer, pushAud, pollAud, sstpAud string, mix audMix) []benchEvent {
	events := make([]benchEvent, n)
	for i := range events {
		events[i] = buildEvent(i, issuer, mix.audiences(i, pushAud, pollAud, sstpAud))
	}
	return events
}
