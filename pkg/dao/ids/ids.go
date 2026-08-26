// Package ids is the single non-Mongo identifier source for the whole server.
//
// Every identifier that is not minted by the Mongo driver at the storage
// boundary comes from here, so there is exactly one place to audit for entropy
// quality and exactly one place to change an id format. The Mongo driver's own
// ObjectID constructor is reserved for the Mongo provider packages; a
// tree-walking test enforces that (see id_source_test.go).
//
// Three shapes are offered, and the choice between them is a semantic one:
//
//   - NewObjectID — a 24-character lowercase hex string, the same shape as a
//     MongoDB ObjectID's Hex() form. Use it for record ids that a DAO converts
//     back into a bson.ObjectID at the storage boundary, so existing Mongo data
//     keeps round-tripping through the Mongo DAO's ParseObjectID.
//   - NewV7 — an RFC 9562 version-7 UUID. Time-ordered, so a set of them sorts
//     into mint order. Use it for stream ids, inbound SSTP SIDs and SET jti
//     values, where ordering is useful and no Mongo _id shape is required.
//   - NewSecret — an RFC 9562 version-4 UUID. Fully random with no embedded
//     timestamp. Use it for secret-bearing values such as an OAuth state
//     parameter, where leaking a mint time or an ordering would be a defect.
//
// All three draw on a cryptographically secure random number generator and
// panic if it fails: on a supported platform crypto/rand cannot fail, and a
// host where it does is in no state to keep issuing identifiers.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"uuid"
)

// NewObjectID returns a 24-character hex string suitable as a primary key.
// The format matches MongoDB ObjectID hex but is generated from crypto/rand.
func NewObjectID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read on standard platforms cannot fail; if it does
		// the host is in an unrecoverable state. Panic is the only sane response.
		panic("ids: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// NewV7 returns an RFC 9562 version-7 UUID in canonical string form.
//
// Version 7 embeds a millisecond timestamp in the leading bits, so values mint
// in strictly increasing order within a process and the canonical string form
// sorts the same way the bytes do. That makes it the right choice for stream
// ids, inbound SSTP SIDs and SET jti values, where an ordered identifier gives
// cheap chronological grouping in logs, indexes and event buffers.
func NewV7() string {
	return uuid.NewV7().String()
}

// NewSecret returns an RFC 9562 version-4 UUID in canonical string form.
//
// Version 4 is 122 bits of pure randomness with no embedded timestamp and no
// ordering, which is what a secret-bearing value wants: an OAuth state
// parameter or a comparable single-use token must not disclose when it was
// minted or how it relates to its neighbours. Use NewV7 instead whenever the
// value is an identifier rather than a secret.
func NewSecret() string {
	return uuid.NewV4().String()
}
