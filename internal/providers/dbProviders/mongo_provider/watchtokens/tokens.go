// Package watchtokens is used to store resume tokens so that goSignalsServer can resume monitoring for change events
// in the MongoDB.
package watchtokens

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type TokenData struct {
	StreamTokens map[bson.ObjectID]bson.Raw
	EventsToken  bson.Raw
}

func (tok *TokenData) Store() {
	filename := storeFilename()
	if filename == "" {
		log.Default().Println("No filename for watch token, skipping Store")
		return
	}
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0770); err != nil {
		log.Default().Println("Error creating directory for watch token:", err)
		return
	}

	tf, err := os.Create(filename)
	if err != nil {
		log.Default().Println("Mongo resume token file creation failed", err)
		return
	}
	defer func(tf *os.File) {
		_ = tf.Close()
	}(tf)

	jsonOut, err := json.Marshal(tok)
	if err != nil {
		log.Default().Println("Failed to marshal Mongo resume token data", err)
		return
	}
	_, err = tf.Write(jsonOut)
	if err != nil {
		log.Default().Println("Failed to save Mongo resume token data", err)
		return
	}
	err = tf.Close()
	if err != nil {
		log.Default().Println("Failed to close Mongo resume token file", err)
	}
}

// Reset is called after re-initialization of the Mongo database to remove prior watchlist tokens
func (tok *TokenData) Reset() {
	tok.StreamTokens = map[bson.ObjectID]bson.Raw{}
	tok.EventsToken = nil
	tok.Store()
}

func Load() *TokenData {

	tokenData := &TokenData{}
	filename := storeFilename()

	dataBytes, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Mongo resume token file not found. Initializing new token file.")
			tokenData.Reset()
			return tokenData
		}
		if os.IsPermission(err) {
			log.Println("Permission denied accessing Mongo resume token file or directory:", err)
		} else {
			log.Println("Error reading Mongo resume token file:", err)
		}
		return tokenData
	}

	err = json.Unmarshal(dataBytes, tokenData)
	if err != nil {
		log.Println("Error parsing token data file, returning empty state:", err)
		return &TokenData{StreamTokens: make(map[bson.ObjectID]bson.Raw)}
	}

	return tokenData

}

func storeFilename() string {
	watchFile := envcompat.Lookup("I2SIG_STORE_MONGO_RESUME_FILE", "MONGO_WATCH_FILE")
	if watchFile != "" {
		return watchFile
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Default().Println("Error getting current directory for watch token: " + err.Error())
		cwd = "."
	}
	return filepath.Join(cwd, "resources/mongo_token.json")
}
