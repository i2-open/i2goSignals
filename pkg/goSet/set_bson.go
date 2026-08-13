package goSet

import (
	"encoding/json"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// This file gives the SET types a BSON representation that matches their wire
// (JSON) representation.
//
// Without it, the default mongo-driver struct codec serializes these types by
// Go field name and has no notion of the `json:",omitempty"` tags, so every
// persisted event carried all eleven embedded subject-identifier variants with
// empty values, and buried the RFC 8417 registered claims in a
// `registeredclaims` subdocument under Go names rather than their wire names
// (iss, aud, exp, nbf, iat, jti). See issue #259.
//
// The wire shape is produced by round-tripping through the type's own JSON
// encoding, which is the single source of truth for member names and for which
// members are omitted when empty. That also covers jwt.RegisteredClaims, a
// third-party type we cannot tag.

// wireBSON encodes v via its JSON representation so the resulting BSON document
// carries wire member names and omits absent members.
func wireBSON(v interface{}) ([]byte, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var doc bson.D
	if err := bson.UnmarshalExtJSON(j, false, &doc); err != nil {
		return nil, err
	}
	return bson.Marshal(doc)
}

// wireUnwrapBSON is the inverse of wireBSON: it re-reads a stored document
// through the type's JSON decoding.
func wireUnwrapBSON(data []byte, v interface{}) error {
	j, err := bson.MarshalExtJSON(bson.Raw(data), false, false)
	if err != nil {
		return err
	}
	return json.Unmarshal(j, v)
}

// hasLegacyKey reports whether the stored document carries any of the Go field
// names the pre-#259 default struct codec produced. Those names never occur in
// the wire shape, so their presence unambiguously identifies an old document.
//
// This matters because BSON decoding IGNORES unknown fields: without this
// check an old row would decode to a zero value — an empty subject that
// silently mis-matches a subject filter — rather than failing loudly.
func hasLegacyKey(data []byte, keys ...string) bool {
	elems, err := bson.Raw(data).Elements()
	if err != nil {
		return false
	}
	for _, e := range elems {
		for _, k := range keys {
			if e.Key() == k {
				return true
			}
		}
	}
	return false
}

// MarshalBSON persists a subject identifier in its RFC 9493 wire shape — only
// the members actually present, under their wire names.
func (sid SubjectIdentifier) MarshalBSON() ([]byte, error) {
	return wireBSON(subjectIdentifierWire(sid))
}

// UnmarshalBSON reads a subject identifier back from its stored wire shape,
// falling back to the pre-#259 Go-shaped layout for documents written before
// the fix.
func (sid *SubjectIdentifier) UnmarshalBSON(data []byte) error {
	if hasLegacyKey(data, legacySubjectKeys...) {
		// The wire type carries no BSON methods, so this is the default
		// struct codec — i.e. exactly the encoder that wrote the document.
		return bson.Unmarshal(data, (*subjectIdentifierWire)(sid))
	}
	return wireUnwrapBSON(data, (*subjectIdentifierWire)(sid))
}

// legacySubjectKeys are the embedded-struct field names the default codec
// emitted for SubjectIdentifier. None of them is a wire member name.
var legacySubjectKeys = []string{
	"usernameidentifier", "emailidentifier", "issuersubjectidentifier",
	"opaqueidentifier", "phonenumberidentifier", "decentralizedidentifier",
	"uniformresourceidentifier", "externalidentifier", "aliasesidentifier",
	"complexidentifier",
}

// subjectIdentifierWire is SubjectIdentifier stripped of its BSON methods, so
// the json codec inside wireBSON/wireUnwrapBSON sees the plain struct.
type subjectIdentifierWire SubjectIdentifier

// MarshalBSON persists a SET in its RFC 8417 wire shape: registered claims at
// the top level under their wire names (iss, sub, aud, exp, nbf, iat, jti),
// and no member the token does not carry.
func (set SecurityEventToken) MarshalBSON() ([]byte, error) {
	return wireBSON(securityEventTokenWire(set))
}

// UnmarshalBSON reads a SET back from its stored wire shape, falling back to
// the pre-#259 Go-shaped layout for documents written before the fix. A nested
// legacy sub_id is handled by SubjectIdentifier.UnmarshalBSON in turn.
func (set *SecurityEventToken) UnmarshalBSON(data []byte) error {
	if hasLegacyKey(data, "registeredclaims") {
		return bson.Unmarshal(data, (*securityEventTokenWire)(set))
	}
	return wireUnwrapBSON(data, (*securityEventTokenWire)(set))
}

// securityEventTokenWire is SecurityEventToken stripped of its BSON methods.
type securityEventTokenWire SecurityEventToken
