package mongo

import (
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ParseObjectID converts a hex string to a BSON ObjectID with proper error handling
func ParseObjectID(id string) (bson.ObjectID, error) {
	docId, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return bson.ObjectID{}, errors.New("invalid object id: " + err.Error())
	}
	return docId, nil
}

// IsNotFoundError checks if the error is a mongo.ErrNoDocuments error
func IsNotFoundError(err error) bool {
	return errors.Is(err, mongo.ErrNoDocuments)
}

// HandleFindError processes errors from MongoDB find operations
// Returns nil if no documents found, otherwise returns the error
func HandleFindError(err error, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if IsNotFoundError(err) {
		return notFoundErr
	}
	return err
}

// HandleDeleteResult processes the result of a delete operation
func HandleDeleteResult(result *mongo.DeleteResult, notFoundErr error) error {
	if result != nil && result.DeletedCount == 0 {
		return notFoundErr
	}
	return nil
}

// HandleUpdateResult processes the result of an update operation
func HandleUpdateResult(result *mongo.UpdateResult, notFoundErr error) error {
	if result != nil && result.MatchedCount == 0 {
		return notFoundErr
	}
	return nil
}
