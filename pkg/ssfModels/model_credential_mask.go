package model

// MaskedCredentialValue is the unconditional redaction sentinel for delivery
// credentials on every read surface (config GET, state listings), per ADR 0022
// §3. The live credential value appears exactly twice in its life: the create
// response and the rotation response. On an UPDATE this same sentinel, when sent
// back in a credential field, means "leave the stored value unchanged" so a
// read-edit-write round trip cannot clobber a live bearer.
const MaskedCredentialValue = "***"

// maskField returns the redaction sentinel when v is a present credential, or v
// unchanged when it is empty. An absent credential is left empty so the sentinel
// is never ambiguous with "no credential configured" (a real state).
func maskField(v string) string {
	if v == "" {
		return ""
	}
	return MaskedCredentialValue
}

// maskDelivery redacts every per-method authorization_header in place on an
// (already deep-copied) delivery block.
func maskDelivery(d *OneOfStreamConfigurationDelivery) {
	if d == nil {
		return
	}
	if d.PollTransmitMethod != nil {
		d.PollTransmitMethod.AuthorizationHeader = maskField(d.PollTransmitMethod.AuthorizationHeader)
	}
	if d.PollReceiveMethod != nil {
		d.PollReceiveMethod.AuthorizationHeader = maskField(d.PollReceiveMethod.AuthorizationHeader)
	}
	if d.PushTransmitMethod != nil {
		d.PushTransmitMethod.AuthorizationHeader = maskField(d.PushTransmitMethod.AuthorizationHeader)
	}
	if d.PushReceiveMethod != nil {
		d.PushReceiveMethod.AuthorizationHeader = maskField(d.PushReceiveMethod.AuthorizationHeader)
	}
}

// maskConfigInPlace redacts every credential field of an (already deep-copied)
// StreamConfiguration: the per-method delivery bearer and the outbound tx_token.
func maskConfigInPlace(c *StreamConfiguration) {
	maskDelivery(c.Delivery)
	if c.TxToken != nil {
		m := maskField(*c.TxToken)
		c.TxToken = &m
	}
}

// MaskCredentials returns a deep copy of the StreamConfiguration with every
// credential field redacted to MaskedCredentialValue (ADR 0022 §3). The original
// is never mutated. An absent credential is left empty (not redacted).
func (sc *StreamConfiguration) MaskCredentials() StreamConfiguration {
	res := sc.DeepCopy()
	maskConfigInPlace(&res)
	return res
}

// MaskCredentials returns a deep copy of the StreamStateRecord with every
// credential field redacted (the embedded StreamConfiguration's delivery bearer
// and tx_token, the SSTP responder bearer in SstpMethod, and the inbound SSTP
// direction's credentials). The original record is never mutated.
func (ss *StreamStateRecord) MaskCredentials() *StreamStateRecord {
	res := ss.DeepCopy()
	if res == nil {
		return nil
	}
	maskConfigInPlace(&res.StreamConfiguration)
	if res.SstpInbound != nil {
		maskConfigInPlace(res.SstpInbound)
	}
	if res.SstpMethod != nil {
		res.SstpMethod.AuthorizationHeader = maskField(res.SstpMethod.AuthorizationHeader)
	}
	return res
}

// MergeUnchangedCredentials reconciles an incoming (update-body) StreamConfiguration
// against the stored one: wherever a credential field on the incoming config
// holds the masking sentinel MaskedCredentialValue, it is replaced by the stored
// live value (ADR 0022 §3 "incoming *** means leave unchanged"). A genuine new
// credential in the body is left as-is and replaces the stored value. The
// incoming config is mutated in place.
func (sc *StreamConfiguration) MergeUnchangedCredentials(stored *StreamConfiguration) {
	if sc == nil || stored == nil {
		return
	}
	mergeDelivery(sc.Delivery, stored.Delivery)
	if sc.TxToken != nil && *sc.TxToken == MaskedCredentialValue && stored.TxToken != nil {
		v := *stored.TxToken
		sc.TxToken = &v
	}
}

// MergeUnchangedCredentials reconciles an incoming (update-body) StreamStateRecord
// against the stored record: any credential field holding the masking sentinel is
// restored from the stored record (ADR 0022 §3). This covers the embedded
// StreamConfiguration, the inbound SSTP direction, and the SSTP responder bearer.
func (ss *StreamStateRecord) MergeUnchangedCredentials(stored *StreamStateRecord) {
	if ss == nil || stored == nil {
		return
	}
	ss.StreamConfiguration.MergeUnchangedCredentials(&stored.StreamConfiguration)
	if ss.SstpInbound != nil && stored.SstpInbound != nil {
		ss.SstpInbound.MergeUnchangedCredentials(stored.SstpInbound)
	}
	if ss.SstpMethod != nil && stored.SstpMethod != nil &&
		ss.SstpMethod.AuthorizationHeader == MaskedCredentialValue {
		ss.SstpMethod.AuthorizationHeader = stored.SstpMethod.AuthorizationHeader
	}
}

// mergeDelivery restores sentinel-marked per-method bearers on the incoming
// delivery from the stored delivery, matching by method direction.
func mergeDelivery(incoming, stored *OneOfStreamConfigurationDelivery) {
	if incoming == nil || stored == nil {
		return
	}
	if incoming.PollTransmitMethod != nil && stored.PollTransmitMethod != nil &&
		incoming.PollTransmitMethod.AuthorizationHeader == MaskedCredentialValue {
		incoming.PollTransmitMethod.AuthorizationHeader = stored.PollTransmitMethod.AuthorizationHeader
	}
	if incoming.PollReceiveMethod != nil && stored.PollReceiveMethod != nil &&
		incoming.PollReceiveMethod.AuthorizationHeader == MaskedCredentialValue {
		incoming.PollReceiveMethod.AuthorizationHeader = stored.PollReceiveMethod.AuthorizationHeader
	}
	if incoming.PushTransmitMethod != nil && stored.PushTransmitMethod != nil &&
		incoming.PushTransmitMethod.AuthorizationHeader == MaskedCredentialValue {
		incoming.PushTransmitMethod.AuthorizationHeader = stored.PushTransmitMethod.AuthorizationHeader
	}
	if incoming.PushReceiveMethod != nil && stored.PushReceiveMethod != nil &&
		incoming.PushReceiveMethod.AuthorizationHeader == MaskedCredentialValue {
		incoming.PushReceiveMethod.AuthorizationHeader = stored.PushReceiveMethod.AuthorizationHeader
	}
}
