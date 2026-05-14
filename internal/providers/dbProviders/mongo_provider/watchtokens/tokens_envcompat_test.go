package watchtokens

import "testing"

// Slice #67: MONGO_WATCH_FILE → I2SIG_STORE_MONGO_RESUME_FILE.

func TestStoreFilename_NewNameWins(t *testing.T) {
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", "/tmp/new-resume.json")
    t.Setenv("MONGO_WATCH_FILE", "/tmp/old-resume.json")
    if got := storeFilename(); got != "/tmp/new-resume.json" {
        t.Fatalf("storeFilename() = %q, want %q", got, "/tmp/new-resume.json")
    }
}

func TestStoreFilename_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", "")
    t.Setenv("MONGO_WATCH_FILE", "/tmp/old-resume.json")
    if got := storeFilename(); got != "/tmp/old-resume.json" {
        t.Fatalf("storeFilename() = %q, want %q (deprecated MONGO_WATCH_FILE)", got, "/tmp/old-resume.json")
    }
}
