package model

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"sync"
)

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
// array by splicing one `[` and one `]` around the value's bytes. Every other
// byte of the document — member order, whitespace, nested values, string
// escapes — is carried through untouched, because none of it is ours to
// normalise: the document belongs to a foreign transmitter and the only claim
// this function has a mandate over is aud.
//
// If aud is absent, is any shape other than a string, or the document is not a
// JSON object, the input slice is returned as-is, with no copy.
//
// The scan is a single jsontext token walk. The earlier implementation decoded
// into a map[string]json.RawMessage and re-encoded it, which sorted the members
// into lexical order, compacted the transmitter's whitespace, and — because
// json.Unmarshal treats a JSON null as a no-op on its target — turned
// `{"aud":null}` into `{"aud":[""]}`, inventing an empty audience the
// transmitter never sent.
func normalizeAudToArray(data []byte) []byte {
	sc := audScanners.Get().(*audScanner)
	defer func() {
		sc.src.Reset(nil)
		audScanners.Put(sc)
	}()
	sc.src.Reset(data)
	sc.dec.Reset(&sc.src)
	dec := sc.dec

	if dec.PeekKind() != '{' {
		return data
	}
	if _, err := dec.ReadToken(); err != nil {
		return data
	}
	for {
		// Anything other than a member name here is the closing brace or a
		// syntax error; either way there is no top-level aud to rewrite.
		if dec.PeekKind() != '"' {
			return data
		}
		name, err := dec.ReadValue()
		if err != nil {
			return data
		}
		// Decoder-owned bytes are only valid until the next call, so resolve
		// both facts about the name before touching the decoder again.
		isAud := isAudName(name)
		nameEnd := dec.InputOffset()

		if !isAud {
			if err := dec.SkipValue(); err != nil {
				return data
			}
			continue
		}
		if dec.PeekKind() != '"' {
			return data // already an array, or a shape we do not rewrite
		}
		if _, err := dec.ReadToken(); err != nil {
			return data
		}
		valueEnd := dec.InputOffset()
		// InputOffset is the end of the token just read, so the string value
		// ends at valueEnd; between it and the end of the name lie only JSON
		// whitespace and the member colon, none of which can be a quote. The
		// first quote after the name is therefore the value's opening one.
		q := bytes.IndexByte(data[nameEnd:valueEnd], '"')
		if q < 0 {
			return data
		}
		valueStart := nameEnd + int64(q)

		out := make([]byte, 0, len(data)+2)
		out = append(out, data[:valueStart]...)
		out = append(out, '[')
		out = append(out, data[valueStart:valueEnd]...)
		out = append(out, ']')
		return append(out, data[valueEnd:]...)
	}
}

// isAudName reports whether raw — one member name exactly as it appears in the
// document, quotes and escapes included — denotes "aud".
//
// The comparison runs on the raw bytes so an ordinary member costs no string
// allocation; only a name carrying an escape is decoded. Escaped spellings are
// vanishingly rare on this wire but they are legal JSON, and missing one would
// mean silently declining to normalise an aud a transmitter did send.
func isAudName(raw jsontext.Value) bool {
	q := bytes.TrimSpace(raw)
	if !bytes.ContainsRune(q, '\\') {
		return string(q) == `"aud"`
	}
	var name string
	return json.Unmarshal(q, &name) == nil && name == "aud"
}

// audScanner is one reusable jsontext decoder bound to one reusable reader. A
// jsontext.Decoder owns a growable read buffer and a container stack sized for
// the document it last read; constructing one per call throws both away and
// re-grows them, which is nearly the whole cost of scanning a configuration
// that has no string aud to rewrite. The reader is a field rather than a fresh
// bytes.Reader because NewDecoder captures the reader pointer at construction,
// so the two have to be pooled as one value.
type audScanner struct {
	src bytes.Reader
	dec *jsontext.Decoder
}

var audScanners = sync.Pool{New: func() any {
	sc := &audScanner{}
	sc.dec = jsontext.NewDecoder(&sc.src)
	return sc
}}
