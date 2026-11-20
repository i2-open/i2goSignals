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
//   - NewObjectID — a 24-character lowercase hex string with a MongoDB
//     ObjectID's layout and Hex() form, so it sorts into mint order. Use it for
//     record ids that a DAO converts back into a bson.ObjectID at the storage
//     boundary, so existing Mongo data keeps round-tripping through the Mongo
//     DAO's ParseObjectID, and where id order is the fallback for the newest
//     record (the key store picks the newest key record by JwkKeyRec.CreatedAt,
//     through JwkKeyRec.NewerThan, and takes the higher id only when creation
//     times are equal or missing).
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
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"time"
	"uuid"
)

// objectIDProcess is NewObjectID's per-process random value and
// objectIDCounter its counter. The counter starts at a random value below 2^23,
// so at least 2^23 ids mint before its 24 bits wrap.
var (
	objectIDProcess [5]byte
	objectIDCounter atomic.Uint32
)

func init() {
	var seed [3]byte
	mustRead(objectIDProcess[:])
	mustRead(seed[:])
	objectIDCounter.Store(uint32(seed[0]&0x7f)<<16 | uint32(seed[1])<<8 | uint32(seed[2]))
}

// NewObjectID returns a 24-character hex string suitable as a primary key. It
// has the MongoDB ObjectID layout: a 4-byte big-endian Unix seconds timestamp,
// a 5-byte random per-process value and a 3-byte big-endian counter. Ids a
// process mints therefore sort into mint order, so where a caller falls back to
// id order, as JwkKeyRec.NewerThan does for key records with equal or no
// creation times, the higher id is the later mint; the random parts come from
// crypto/rand.
func NewObjectID() string {
	var b [12]byte
	binary.BigEndian.PutUint32(b[0:4], uint32(time.Now().Unix()))
	copy(b[4:9], objectIDProcess[:])
	c := objectIDCounter.Add(1)
	b[9], b[10], b[11] = byte(c>>16), byte(c>>8), byte(c)
	return hex.EncodeToString(b[:])
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read on standard platforms cannot fail; if it does
		// the host is in an unrecoverable state. Panic is the only sane response.
		panic("ids: crypto/rand failed: " + err.Error())
	}
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
