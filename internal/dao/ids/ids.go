// Package ids provides string-typed identifier generation for the DAO layer.
//
// IDs are 24-character lowercase hex strings — same shape as a MongoDB ObjectID's
// Hex() form, so existing Mongo data continues to round-trip cleanly through the
// Mongo DAO's ParseObjectID conversion at the storage boundary. Generation uses
// crypto/rand and has no dependency on the Mongo driver, so memory and other
// future adapters share the same ID format without importing bson.
package ids

import (
    "crypto/rand"
    "encoding/hex"
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
