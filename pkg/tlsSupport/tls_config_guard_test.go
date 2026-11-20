package tlsSupport

// Source-scan half of the TLS policy guard (i2goSignals#271).
//
// The behavioural tests in pqkem_test.go prove that Harden produces a config
// satisfying the PQ-KEM + MinVersion invariant. That only matters if every
// tls.Config in the project actually goes through it, and several of the sites
// that must (the SPIFFE client configs, the http.DefaultTransport branch of
// CheckCaInstalled) cannot be exercised from a unit test at all. So this file
// checks the property at the source level instead of at runtime: it parses
// every non-test Go file in the module and enforces three rules.
//
//  1. Every tls.Config composite literal states MinVersion. Left unset it is
//     TLS 1.0 on the server side, which no amount of key-exchange hardening
//     compensates for, and the omission is invisible at the call site.
//  2. Every tls.Config literal inside pkg/tlsSupport and pkg/oauthClient is
//     handed to Harden. These are the packages whose configs carry the
//     project's key-exchange posture; a literal that skips Harden is a config
//     that silently opts out of I2SIG_TLS_PQ_KEM.
//  3. CurvePreferences is written in exactly one place — Harden. Setting it
//     anywhere else is how hybrid post-quantum key exchange gets turned off by
//     accident, since crypto/tls treats a non-empty list as an allow-list and
//     a list written before Go 1.24 will not contain X25519MLKEM768.
//
// A new TLS site therefore fails this test until it is deliberately hardened,
// which is the only way an invariant currently held by omission survives
// contact with future changes.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hardenedPackages are the packages whose tls.Config literals must all be
// wrapped in Harden. Everything else in the repo only has to state MinVersion:
// cmd/ binaries and per-stream push transports build one-off client configs
// whose trust decisions are already explicit at the call site.
var hardenedPackages = []string{
	"pkg/tlsSupport",
	"pkg/oauthClient",
}

// expectedTlsConfigSites pins how many tls.Config literals each hardened
// package file contains. It is not busywork: it is what makes a *new* site
// visible in review rather than merely compliant. Adding or removing a TLS
// config is a deliberate act — update this map in the same change.
var expectedTlsConfigSites = map[string]int{
	"pkg/tlsSupport/spiffe.go":       3,
	"pkg/tlsSupport/key.go":          5,
	"pkg/oauthClient/tls_helpers.go": 2,
}

// curvePreferencesOwner is the one file allowed to write CurvePreferences.
const curvePreferencesOwner = "pkg/tlsSupport/pqkem.go"

type tlsConfigSite struct {
	file          string // module-relative, slash-separated
	line          int
	hasMinVersion bool
	hardened      bool // passed directly to Harden(...)
	setsCurves    bool
}

func TestEveryTlsConfigLiteralStatesMinVersion(t *testing.T) {
	sites, _ := scanTlsConfigSites(t)
	require.NotEmpty(t, sites, "the scanner found no tls.Config literals at all — it has stopped working")

	var offenders []string
	for _, s := range sites {
		if !s.hasMinVersion {
			offenders = append(offenders, s.String())
		}
	}
	assert.Empty(t, offenders,
		"these tls.Config literals omit MinVersion; an unset MinVersion means TLS 1.0 on the "+
			"server side. Add `MinVersion: tls.VersionTLS12`:\n  %s", strings.Join(offenders, "\n  "))
}

func TestHardenedPackagesRouteEveryTlsConfigThroughHarden(t *testing.T) {
	sites, _ := scanTlsConfigSites(t)

	counted := map[string]int{}
	var offenders []string
	for _, s := range sites {
		if !inHardenedPackage(s.file) {
			continue
		}
		counted[s.file]++
		if !s.hardened {
			offenders = append(offenders, s.String())
		}
	}

	assert.Empty(t, offenders,
		"these tls.Config literals are not passed to tlsSupport.Harden, so they opt out of the "+
			"%s key-exchange policy:\n  %s", EnvTlsPqKem, strings.Join(offenders, "\n  "))
	assert.Equal(t, expectedTlsConfigSites, counted,
		"the inventory of TLS config sites in the hardened packages changed. If that was "+
			"intentional, update expectedTlsConfigSites in this file so the next reviewer sees it.")
}

func TestCurvePreferencesIsWrittenInExactlyOnePlace(t *testing.T) {
	sites, curveWriters := scanTlsConfigSites(t)

	var offenders []string
	for _, s := range sites {
		if s.setsCurves && s.file != curvePreferencesOwner {
			offenders = append(offenders, s.String())
		}
	}
	for _, w := range curveWriters {
		if w.file != curvePreferencesOwner {
			offenders = append(offenders, w.String())
		}
	}

	assert.Empty(t, offenders,
		"CurvePreferences may only be set in %s. crypto/tls treats a non-empty list as an "+
			"allow-list, so a list written anywhere else is how X25519MLKEM768 gets dropped by "+
			"accident:\n  %s", curvePreferencesOwner, strings.Join(offenders, "\n  "))
}

func (s tlsConfigSite) String() string {
	return s.file + ":" + itoa(s.line)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func inHardenedPackage(file string) bool {
	for _, p := range hardenedPackages {
		if strings.HasPrefix(file, p+"/") {
			return true
		}
	}
	return false
}

// scanTlsConfigSites parses every non-test .go file in the module and returns
// each tls.Config composite literal it finds, plus the locations of any
// assignment to a .CurvePreferences field.
func scanTlsConfigSites(t *testing.T) (sites []tlsConfigSite, curveWriters []tlsConfigSite) {
	t.Helper()
	root := moduleRoot(t)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		require.NoError(t, relErr)
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		require.NoErrorf(t, parseErr, "failed to parse %s", rel)

		hardenedLits := hardenCallArguments(file)

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				if !isTlsConfigType(node.Type) {
					return true
				}
				site := tlsConfigSite{
					file:     rel,
					line:     fset.Position(node.Lbrace).Line,
					hardened: hardenedLits[node],
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch key.Name {
					case "MinVersion":
						site.hasMinVersion = true
					case "CurvePreferences":
						site.setsCurves = true
					}
				}
				sites = append(sites, site)
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == "CurvePreferences" {
						curveWriters = append(curveWriters, tlsConfigSite{
							file: rel,
							line: fset.Position(sel.Pos()).Line,
						})
					}
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})
	sort.Slice(curveWriters, func(i, j int) bool {
		if curveWriters[i].file != curveWriters[j].file {
			return curveWriters[i].file < curveWriters[j].file
		}
		return curveWriters[i].line < curveWriters[j].line
	})
	return sites, curveWriters
}

// hardenCallArguments returns the set of composite literals that appear
// directly as an argument to Harden(...) or tlsSupport.Harden(...), including
// the &tls.Config{...} form.
func hardenCallArguments(file *ast.File) map[*ast.CompositeLit]bool {
	found := map[*ast.CompositeLit]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isHardenFunc(call.Fun) {
			return true
		}
		for _, arg := range call.Args {
			if unary, isUnary := arg.(*ast.UnaryExpr); isUnary && unary.Op == token.AND {
				arg = unary.X
			}
			if lit, isLit := arg.(*ast.CompositeLit); isLit {
				found[lit] = true
			}
		}
		return true
	})
	return found
}

func isHardenFunc(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name == "Harden"
	case *ast.SelectorExpr:
		pkg, ok := f.X.(*ast.Ident)
		return ok && pkg.Name == "tlsSupport" && f.Sel.Name == "Harden"
	}
	return false
}

func isTlsConfigType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Config" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "tls"
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod, so the scan covers the whole module rather than one package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, parent, dir, "no go.mod found above %s", dir)
		dir = parent
	}
}
