package timerlint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTimeAfterInLoops walks every Go source file in the module and fails on a
// time.After call that appears inside a for or range body — including inside a
// func literal or goroutine declared in that body, which is the same leak with
// an extra hop.
//
// If this test fails, do not silence it by hoisting the call: replace the wait
// with eventRouter.SleepCtx (cancellable, stops its own timer) or with an owned
// *time.Timer that is stopped on every exit path.
func TestNoTimeAfterInLoops(t *testing.T) {
	root := moduleRoot(t)

	var violations []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			// A file this test cannot parse is not this test's business to report.
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		for _, pos := range loopTimeAfterPositions(file) {
			violations = append(violations, rel+":"+itoa(fset.Position(pos).Line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	for _, v := range dedupe(violations) {
		t.Errorf("time.After inside a loop body at %s: use eventRouter.SleepCtx, "+
			"or own a *time.Timer and Stop it on every exit path", v)
	}
}

// loopTimeAfterPositions returns the position of every time.After call that
// appears anywhere inside a for or range body in f.
func loopTimeAfterPositions(f *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			body = loop.Body
		case *ast.RangeStmt:
			body = loop.Body
		default:
			return true
		}
		// Keep descending after recording: a nested loop reports its own body,
		// and the duplicate hits from the outer body are deduplicated by caller.
		found = append(found, timeAfterCalls(body)...)
		return true
	})
	return found
}

// timeAfterCalls returns the positions of every time.After call under body.
func timeAfterCalls(body *ast.BlockStmt) []token.Pos {
	var found []token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "After" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "time" {
			return true
		}
		found = append(found, call.Lparen)
		return true
	})
	return found
}

func skipDir(name string) bool {
	switch name {
	case "vendor", "node_modules", ".git", ".idea", "bin":
		return true
	}
	return false
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
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
			t.Fatal("no go.mod found above the test working directory")
		}
		dir = parent
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// TestDetectorFindsViolations is the linter's own negative control: a check that
// never fires is indistinguishable from a check that is broken, so this pins the
// detector against sources it must flag and sources it must not.
func TestDetectorFindsViolations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "for body",
			src: `package p
import "time"
func f(c chan int) {
	for {
		select {
		case <-c:
		case <-time.After(time.Second):
		}
	}
}`,
			want: 1,
		},
		{
			name: "range body",
			src: `package p
import "time"
func f(xs []int) {
	for range xs {
		<-time.After(time.Second)
	}
}`,
			want: 1,
		},
		{
			name: "goroutine inside loop",
			src: `package p
import "time"
func f(xs []int) {
	for range xs {
		go func() { <-time.After(time.Second) }()
	}
}`,
			want: 1,
		},
		{
			name: "single shot outside any loop is allowed",
			src: `package p
import "time"
func f(c chan int) bool {
	select {
	case <-c:
		return true
	case <-time.After(time.Second):
		return false
	}
}`,
			want: 0,
		},
		{
			name: "owned timer inside a loop is allowed",
			src: `package p
import "time"
func f(c chan int) {
	for {
		t := time.NewTimer(time.Second)
		select {
		case <-c:
		case <-t.C:
		}
		t.Stop()
	}
}`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := len(dedupe(positionStrings(fset, loopTimeAfterPositions(file))))
			if got != tc.want {
				t.Fatalf("detector found %d violations, want %d", got, tc.want)
			}
		})
	}
}

func positionStrings(fset *token.FileSet, in []token.Pos) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, itoa(fset.Position(p).Line))
	}
	return out
}
