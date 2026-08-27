package ids

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mongoOnlyDirs are the module-relative directory prefixes allowed to call the
// Mongo driver's own ObjectID constructor. Everything else -- production code
// and tests alike -- mints through this package instead.
var mongoOnlyDirs = []string{
	"internal/dao/mongo",
	"internal/providers/dbProviders/mongo_provider",
}

// moduleRoot walks up from the test's working directory to the directory holding
// go.mod, so the walk below covers the whole repository rather than this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

// TestDriverObjectIDConstructorIsMongoOnly is the enforcement half of the single
// id seam: pkg/dao/ids is the only non-Mongo id source, and the driver's ObjectID
// constructor may appear only under the Mongo provider. Without this walk the
// rule decays one convenient call site at a time -- most often in a test, which
// is why _test.go files are in scope too and why there is no exemption for this
// file. The needle is assembled at run time precisely so that this test can
// describe the rule it enforces without tripping over its own source.
func TestDriverObjectIDConstructorIsMongoOnly(t *testing.T) {
	root := moduleRoot(t)
	needle := []byte("bson." + "NewObjectID")

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			for _, allowed := range mongoOnlyDirs {
				if rel == allowed {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, string(needle)) {
				offenders = append(offenders, rel+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(offenders) > 0 {
		t.Errorf("the Mongo driver's ObjectID constructor is confined to %v; "+
			"mint through pkg/dao/ids instead (ids.NewObjectID for a Mongo-shaped "+
			"record id, ids.NewV7 for a stream id/SID/jti, ids.NewSecret for a "+
			"secret). Offending lines:\n\t%s",
			mongoOnlyDirs, strings.Join(offenders, "\n\t"))
	}
}

// itoa avoids pulling strconv in for a single line number.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
