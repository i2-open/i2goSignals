package watchtokens

import (
	"encoding/json"
	"fmt"
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
		fmt.Println("Token file creation failed", err)
		return
	}
	jsonOut, _ := json.Marshal(tok)
	_, err = tf.Write(jsonOut)
	if err != nil {
		fmt.Println("Failed to save token data", err)
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

	var tokenData TokenData
	dataBytes, err := os.ReadFile(storeFilename())
	if err != nil {
		fmt.Println("Token file not found or not yet initialized", err)
		tokenData = TokenData{}
	} else {
		err = json.Unmarshal(dataBytes, &tokenData)
		if err != nil {
			fmt.Println("Error parsing token data file", err)
			tokenData = TokenData{}
		}
	}
	return &tokenData

}

func storeFilename() string {
	cwd, _ := os.Getwd()
	watchFile := os.Getenv("MONGO_WATCH_FILE")
	if watchFile == "" {
		resDir := filepath.Join(cwd, "resources")
		_, err := os.Stat(resDir)
		if os.IsNotExist(err) {
			os.Mkdir(resDir, 770)
		}
		watchFile = filepath.Join(cwd, "resources/mongo_token.json")

	}
	return watchFile
}
