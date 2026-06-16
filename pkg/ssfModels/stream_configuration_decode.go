package model

import "encoding/json"

// UnmarshalStreamConfigurationJSON decodes an SSF stream-configuration document
// into cfg while tolerating an "aud" value delivered as a single JSON string.
//
// RFC 7519 §4.1.3 — which SSF inherits via JWT semantics — permits aud to be
// either a single StringOrURI or an array of StringOrURI. goSignals models aud
// as []string, so a string-valued aud returned by a FOREIGN transmitter (during
// receiver auto-registration) would otherwise fail to decode with
// "cannot unmarshal string into Go struct field StreamConfiguration.aud".
//
// A string aud is normalized to a single-element slice; an array aud (or any
// other shape) is passed through unchanged. Use this anywhere goSignals parses a
// stream configuration it did not author, i.e. responses from remote
// transmitters whose on-wire aud shape we do not control.
func UnmarshalStreamConfigurationJSON(data []byte, cfg *StreamConfiguration) error {
	return json.Unmarshal(normalizeAudToArray(data), cfg)
}

// normalizeAudToArray rewrites a top-level "aud" string into a one-element JSON
// array, leaving every other field byte-for-byte intact (they are preserved as
// json.RawMessage, so nested custom unmarshalers such as the delivery oneOf are
// unaffected). If aud is absent, already an array, or the document is not a JSON
// object, the input is returned unchanged.
func normalizeAudToArray(data []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return data
	}
	raw, ok := m["aud"]
	if !ok {
		return data
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return data // aud is already an array (or some other shape) — leave as-is
	}
	arr, err := json.Marshal([]string{s})
	if err != nil {
		return data
	}
	m["aud"] = arr
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return out
}
