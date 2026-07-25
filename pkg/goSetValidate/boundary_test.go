package goSetValidate

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// productionImportAllowlist is the hard import ceiling for pkg/goSetValidate,
// frozen by the #247 Slice Contract. It is what makes the package
// standalone-consumable by a third-party SSF receiver: no stream state, no
// service layer, no server. Standard-library imports are always allowed and are
// recognised by the absence of a dot in the first path segment.
var productionImportAllowlist = map[string]bool{
	"github.com/i2-open/i2goSignals/pkg/goSet":        true,
	"github.com/i2-open/i2goSignals/pkg/goSet/events": true,
	"github.com/i2-open/i2goSignals/pkg/subjectid":    true,
	"github.com/MicahParks/keyfunc/v2":                true,
}

// testOnlyImportAllowlist adds the fixtures the unit tests need. Test files are
// not part of the published surface, but they are still bound by the
// no-internal/no-server rule asserted below.
var testOnlyImportAllowlist = map[string]bool{
	"github.com/golang-jwt/jwt/v5":        true,
	"github.com/stretchr/testify/assert":  true,
	"github.com/stretchr/testify/require": true,
}

// forbiddenImportSubstrings are the import shapes that would break the package
// boundary outright, in production code AND in tests.
var forbiddenImportSubstrings = []string{
	"i2goSignals/internal/",
	"i2goSignals/pkg/ssfModels",
	"i2goSignals/pkg/services",
	"i2goSignals/pkg/dao",
	"i2goSignals/pkg/eventRouter",
}

func isStdlib(path string) bool {
	first := path
	if idx := strings.Index(path, "/"); idx >= 0 {
		first = path[:idx]
	}
	return !strings.Contains(first, ".")
}

// TestPackageImportBoundary asserts the standing pkg/goSet* rule (no internal/
// imports) plus this package's tighter Slice-Contract allowlist. It parses the
// package's own source rather than trusting a human to notice a new import.
func TestPackageImportBoundary(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs, "expected to parse the goSetValidate package sources")

	sawProductionFile := false

	for _, pkg := range pkgs {
		for fileName, file := range pkg.Files {
			isTest := strings.HasSuffix(fileName, "_test.go")
			if !isTest {
				sawProductionFile = true
			}

			for _, spec := range file.Imports {
				path, uerr := strconv.Unquote(spec.Path.Value)
				require.NoError(t, uerr)

				for _, forbidden := range forbiddenImportSubstrings {
					assert.NotContains(t, path, forbidden,
						"%s imports %q — pkg/goSetValidate must stay standalone", fileName, path)
				}

				if isStdlib(path) {
					continue
				}
				if productionImportAllowlist[path] {
					continue
				}
				if isTest && testOnlyImportAllowlist[path] {
					continue
				}

				t.Errorf("%s imports %q, which is outside the pkg/goSetValidate import allowlist (#247 Slice Contract)", fileName, path)
			}
		}
	}

	assert.True(t, sawProductionFile, "expected at least one non-test source file")
}
