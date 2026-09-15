package services

import (
	"context"
	"errors"
	"sort"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// KeyChange describes a change to the keys under one key name before it is
// made, so the #311 guard can judge it. Every record Retires reports true for
// stops being a signing candidate (it is suspended or deleted), and the change
// creates an active signing key for each algorithm in Adds (JWS names, RS256
// for an RSA key). Retires must match exactly the records the change suspends
// or deletes, and Adds exactly the signing keys it creates: the guard is only
// as right as this description.
type KeyChange struct {
	Retires func(rec *interfaces.JwkKeyRec) bool
	Adds    []string
}

// RetireAllKeys is the Retires of a change that suspends or deletes every
// record under the key name.
func RetireAllKeys(*interfaces.JwkKeyRec) bool { return true }

// RetireKid is the Retires of a change that suspends or deletes only the
// record with key id kid.
func RetireKid(kid string) func(*interfaces.JwkKeyRec) bool {
	return func(rec *interfaces.JwkKeyRec) bool { return rec.Kid == kid }
}

// StrandedStream is a signing transmitter a key change would leave with no
// active signing key (#311). SigningAlg is the effective algorithm, RS256 when
// the stream's signing_alg is empty.
type StrandedStream struct {
	StreamId    string `json:"stream_id"`
	Description string `json:"description"`
	SigningAlg  string `json:"signing_alg"`
}

// StrandedByKeyChange returns the streams change would strand, sorted by stream
// id, and the signature algorithms (JWS names, sorted) they would lose.
//
// A stream needs a key of keyName when it is a signing transmitter (#308) whose
// iss is keyName and whose status is not disabled; a paused stream counts. It is
// stranded when keyName has an active signing key for its algorithm now and
// would have none after change. An algorithm with no active key now strands
// nothing: #308's checks already report those streams, and re-enabling a
// disabled stream runs them again.
func (s *StreamService) StrandedByKeyChange(ctx context.Context, keyName string, change KeyChange) ([]string, []StrandedStream, error) {
	if s.keyService == nil {
		return nil, nil, nil
	}
	recs, err := s.ListTransmitterStreams(ctx)
	if err != nil {
		return nil, nil, err
	}
	type need struct {
		rec       model.StreamStateRecord
		storedAlg string
	}
	var needs []need
	for _, rec := range recs {
		cfg := signingTransmitterConfig(&rec)
		if cfg == nil || cfg.Iss != keyName || rec.Status == model.StreamStateDisable {
			continue
		}
		storedAlg, err := storedAlgFor(cfg.SigningAlg)
		if err != nil {
			continue // an unsupported algorithm has no key to lose
		}
		needs = append(needs, need{rec: rec, storedAlg: storedAlg})
	}
	if len(needs) == 0 {
		return nil, nil, nil
	}

	lost, err := s.keyService.signingAlgsLostBy(ctx, keyName, change)
	if err != nil {
		return nil, nil, err
	}

	var stranded []StrandedStream
	lostAlgs := map[string]bool{}
	for _, n := range needs {
		if !lost(n.storedAlg) {
			continue
		}
		alg := algLabel(n.storedAlg)
		lostAlgs[alg] = true
		stranded = append(stranded, StrandedStream{
			StreamId:    n.rec.StreamConfiguration.Id,
			Description: n.rec.StreamConfiguration.Description,
			SigningAlg:  alg,
		})
	}
	if len(stranded) == 0 {
		return nil, nil, nil
	}
	sort.Slice(stranded, func(i, j int) bool { return stranded[i].StreamId < stranded[j].StreamId })
	algs := make([]string, 0, len(lostAlgs))
	for alg := range lostAlgs {
		algs = append(algs, alg)
	}
	sort.Strings(algs)
	return algs, stranded, nil
}

// signingAlgsLostBy reads keyName's records once and returns a predicate
// reporting whether a stored algorithm has an active signing key now and would
// have none after change. "Active signing key" is latestActiveSigningRec, the
// same selection GetSigner makes, so the guard and the signer never disagree.
func (s *KeyService) signingAlgsLostBy(ctx context.Context, keyName string, change KeyChange) (func(storedAlg string) bool, error) {
	recs, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
		return nil, err
	}
	kept := make([]*interfaces.JwkKeyRec, 0, len(recs))
	for _, rec := range recs {
		if change.Retires == nil || !change.Retires(rec) {
			kept = append(kept, rec)
		}
	}
	added := map[string]bool{}
	for _, alg := range change.Adds {
		if storedAlg, err := storedAlgFor(alg); err == nil {
			added[storedAlg] = true
		}
	}
	return func(storedAlg string) bool {
		if now, _ := latestActiveSigningRec(recs, storedAlg); now == nil {
			return false
		}
		if added[storedAlg] {
			return false
		}
		after, _ := latestActiveSigningRec(kept, storedAlg)
		return after == nil
	}, nil
}
