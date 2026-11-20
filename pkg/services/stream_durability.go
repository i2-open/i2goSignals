package services

import (
	"fmt"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// validateDurability rejects a malformed per-stream durability value on the
// request before any state is mutated (issue #343). It wraps ErrInvalidRequest
// so the HTTP layer answers 400, like validateEventValidationMode.
func validateDurability(mode model.DurabilityMode) error {
	if _, err := model.ParseDurabilityMode(string(mode)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return nil
}

// applyDurability copies a set durability value from the request onto
// streamRec, normalized to its canonical token. An unset request value leaves
// the stored value unchanged. The value is stored whatever the deployment's
// mode: a `local` stream on a majority deployment runs at majority and the
// router WARNs once at ingest (ADR 0045). Already shape-checked by
// validateDurability.
func applyDurability(streamRec *model.StreamStateRecord, requested model.DurabilityMode) {
	mode, err := model.ParseDurabilityMode(string(requested))
	if err != nil || mode == model.DurabilityUnset {
		return
	}
	streamRec.Durability = mode
}

// ResolveDurabilityMode is the effective ingest durability of rec on a
// deployment whose I2SIG_STORE_WAL mode is local (deploymentLocal) or not:
// DurabilityLocal only when both the deployment and the stream ask for it,
// otherwise DurabilityMajority (ADR 0045, ADR 0038).
func ResolveDurabilityMode(rec *model.StreamStateRecord, deploymentLocal bool) model.DurabilityMode {
	if deploymentLocal && rec != nil && rec.Durability.IsLocal() {
		return model.DurabilityLocal
	}
	return model.DurabilityMajority
}

// SetDeploymentDurabilityLocal records whether this deployment runs
// I2SIG_STORE_WAL=local, so the read surfaces can report each stream's
// effective durability. Set by the composition root once the WAL is open.
func (s *StreamService) SetDeploymentDurabilityLocal(local bool) {
	s.deploymentLocal.Store(local)
}

// ResolveDurability returns rec's effective ingest durability on this node.
func (s *StreamService) ResolveDurability(rec *model.StreamStateRecord) model.DurabilityMode {
	return ResolveDurabilityMode(rec, s.deploymentLocal.Load())
}

// OverlayEffectiveDurability sets rec.EffectiveDurability for an admin
// stream-state read surface. Records read from the DAO never carry it.
func (s *StreamService) OverlayEffectiveDurability(rec *model.StreamStateRecord) {
	if rec == nil {
		return
	}
	rec.EffectiveDurability = s.ResolveDurability(rec)
}
