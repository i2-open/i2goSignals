// Package watchtokens is used to store resume tokens so that goSignalsServer can resume monitoring for change events
// in the MongoDB.
package watchtokens

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenData struct {
	StreamTokens map[primitive.ObjectID]bson.Raw
	EventsToken  bson.Raw
}

func (tok *TokenData) Store() {
	tf, err := os.Create(storeFilename())
	if err != nil {
		log.Default().Println("Mongo resume token file creation failed", err)
		return
	}
	jsonOut, _ := json.Marshal(tok)
	_, err = tf.Write(jsonOut)
	if err != nil {
		log.Default().Println("Failed to save Mongo resume token data", err)
		return
	}
	_ = tf.Close()
}

// Reset is called after re-initialization of the Mongo database to remove prior watchlist tokens
func (tok *TokenData) Reset() {
	tok.StreamTokens = map[primitive.ObjectID]bson.Raw{}
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
		return &TokenData{StreamTokens: make(map[primitive.ObjectID]bson.Raw)}
	}

	return tokenData

}

func storeFilename() string {
	cwd, _ := os.Getwd()
	watchFile := os.Getenv("MONGO_WATCH_FILE")
	if watchFile == "" {
		resDir := filepath.Join(cwd, "resources")
		_, err := os.Stat(resDir)
		if os.IsNotExist(err) {
			err := os.Mkdir(resDir, 0770)
			if err != nil {
				log.Default().Println("Error creating directory for watch token: " + err.Error())
				return ""
			}
		}
		watchFile = filepath.Join(cwd, "resources/mongo_token.json")

	}
	return watchFile
}
