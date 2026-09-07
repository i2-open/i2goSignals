package main

import (
	"crypto/rsa"
	"fmt"
	"runtime"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// audMix selects which downstream audience(s) each generated SET carries. The
// goSignals1 ingress stream accepts both audiences; the two transmitter
// streams (push, poll) each match one, so the mix decides how the router fans
// events out.
type audMix string

const (
	mixAlternate audMix = "alternate" // even events -> push audience, odd -> poll audience
	mixBoth      audMix = "both"      // every event carries both audiences (2x fan-out)
	mixPush      audMix = "push"      // push audience only
	mixPoll      audMix = "poll"      // poll audience only
)

func parseAudMix(s string) (audMix, error) {
	switch audMix(s) {
	case mixAlternate, mixBoth, mixPush, mixPoll:
		return audMix(s), nil
	}
	return "", fmt.Errorf("unknown --mix %q (alternate|both|push|poll)", s)
}

// expected returns how many of n events each leg should deliver.
func (m audMix) expected(n int) (push, poll int) {
	switch m {
	case mixAlternate:
		return (n + 1) / 2, n / 2
	case mixBoth:
		return n, n
	case mixPush:
		return n, 0
	default:
		return 0, n
	}
}

func (m audMix) audiences(i int, pushAud, pollAud string) []string {
	switch m {
	case mixAlternate:
		if i%2 == 0 {
			return []string{pushAud}
		}
		return []string{pollAud}
	case mixBoth:
		return []string{pushAud, pollAud}
	case mixPush:
		return []string{pushAud}
	default:
		return []string{pollAud}
	}
}

// benchEventTypes are the SCIM profile (RFC 9967) event types the harness
// rotates through so every leg carries a realistic type mix.
var benchEventTypes = []string{
	model.EventScimCreateFull,
	model.EventScimPatchFull,
	model.EventScimDelete,
}

// signedEvent is one pre-built SET ready to POST.
type signedEvent struct {
	jti string
	jws string
}

// buildEvent creates and signs the i-th SET. The payload shapes mirror the
// i2scim cluster demo (a SCIM User resource) so validators, when enabled, see
// the same data the SCIM nodes send.
func buildEvent(i int, issuer string, aud []string, key *rsa.PrivateKey) (signedEvent, error) {
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
	jws, err := set.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		return signedEvent{}, err
	}
	return signedEvent{jti: set.ID, jws: jws}, nil
}

// buildEvents pre-signs all n SETs in parallel so client-side RSA signing is
// excluded from the measured ingest window.
func buildEvents(n int, issuer, pushAud, pollAud string, mix audMix, key *rsa.PrivateKey) ([]signedEvent, error) {
	events := make([]signedEvent, n)
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	next := make(chan int, n)
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				ev, err := buildEvent(i, issuer, mix.audiences(i, pushAud, pollAud), key)
				if err != nil {
					errs <- fmt.Errorf("event %d: %w", i, err)
					return
				}
				events[i] = ev
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	return events, nil
}
