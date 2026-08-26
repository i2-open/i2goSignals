package model

import (
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
)

// NewRecordId mints the primary key for the model records whose `_id` is typed
// bson.ObjectID -- SsfClient, Server, StreamStateRecord and friends.
//
// The entropy comes from pkg/dao/ids, the single non-Mongo id source; this
// function only re-types it. The distinction matters because the driver's own
// ObjectID constructor is confined to the Mongo provider packages, so that no
// other layer depends on the driver being present to mint an identifier, and a
// future change of id format has exactly one place to happen. Callers that want
// the id as a string should use ids.NewObjectID directly rather than calling
// Hex() on the result of this.
func NewRecordId() bson.ObjectID {
	oid, err := bson.ObjectIDFromHex(ids.NewObjectID())
	if err != nil {
		// ids.NewObjectID always yields 24 lowercase hex characters, which is
		// exactly what ObjectIDFromHex accepts, so this branch is unreachable
		// unless the id seam itself has been broken.
		panic("model: ids.NewObjectID produced an unparseable object id: " + err.Error())
	}
	return oid
}
