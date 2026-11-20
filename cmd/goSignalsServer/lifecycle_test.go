package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
)

// TestStartProviderBindsMongoProviderToTheGivenLifecycle pins the production
// wiring end to end: the context main owns reaches the MongoProvider, and
// through it the cluster coordinator whose lease heartbeats must stop when the
// process does (seam S4).
func TestStartProviderBindsMongoProviderToTheGivenLifecycle(t *testing.T) {
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancelled up front so the initial connect to a host that is not there
	// aborts on the lifecycle context instead of waiting out its own budget.
	// Background reconnect keeps the Mongo provider rather than falling back to
	// memory, which is what makes the assertion below reachable.
	t.Setenv("I2SIG_STORE_MONGO_BACKGROUND_RECONNECT", "TRUE")
	cancel()

	persistence, err := StartProvider(lifecycle, "mongodb://127.0.0.1:1/")
	if persistence == nil {
		t.Fatalf("StartProvider returned no persistence (err=%v)", err)
	}

	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	// The coordinator is the MongoProvider's, constructed from the ctx the
	// provider was opened with, so its lifecycle context IS the provider's.
	coord, ok := persistence.Coordinator.(*mongo_provider.MongoCoordinator)
	if !ok {
		t.Fatalf("coordinator is %T, want *mongo_provider.MongoCoordinator; the "+
			"boot path fell back to a non-Mongo provider", persistence.Coordinator)
	}
	if coord.LifecycleContext() != lifecycle {
		t.Fatal("the boot path did not hand its lifecycle context to the MongoProvider")
	}
	if coord.LifecycleContext().Err() == nil {
		t.Fatal("cancelling the boot path's context did not reach the coordinator")
	}
}

// TestMainCancelsTheLifecycleItHandsToStartProvider closes the other half of the
// acceptance criterion. StartProvider above proves the context propagates;
// this proves main actually creates a cancellable one, hands *that* context to
// StartProvider, and defers its cancel — i.e. that shutdown is what cancels the
// coordinator's heartbeats.
//
// main() cannot be called from a test, so the check is on the source. It is
// deliberately structural rather than textual: it follows the identifiers, so
// renaming the variables is fine and quietly passing context.Background() or
// dropping the defer is not.
func TestMainCancelsTheLifecycleItHandsToStartProvider(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	mainFn := funcDecl(file, "main")
	if mainFn == nil {
		t.Fatal("no func main in main.go")
	}

	ctxName, cancelName := cancellableContext(mainFn.Body)
	if ctxName == "" {
		t.Fatal("main does not create a cancellable context; the coordinator's " +
			"lease heartbeats would have no shutdown signal")
	}
	if !defersCall(mainFn.Body, cancelName) {
		t.Fatalf("main never defers %s(); the lifecycle context is created but "+
			"never cancelled on the way out", cancelName)
	}
	if arg := firstArgToCall(mainFn.Body, "StartProvider"); arg != ctxName {
		t.Fatalf("main passes %q to StartProvider, want the cancellable context %q",
			arg, ctxName)
	}
}

func funcDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// cancellableContext finds `a, b := context.WithCancel(...)` and returns the two
// identifier names.
func cancellableContext(body *ast.BlockStmt) (ctxName, cancelName string) {
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "context", "WithCancel") {
			return true
		}
		lhs0, ok0 := assign.Lhs[0].(*ast.Ident)
		lhs1, ok1 := assign.Lhs[1].(*ast.Ident)
		if ok0 && ok1 {
			ctxName, cancelName = lhs0.Name, lhs1.Name
			return false
		}
		return true
	})
	return ctxName, cancelName
}

func defersCall(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		def, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if ident, ok := def.Call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// firstArgToCall returns the name of the first argument passed to fn, or "" if
// fn is never called or its first argument is not a plain identifier.
func firstArgToCall(body *ast.BlockStmt, fn string) string {
	arg := ""
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != fn {
			return true
		}
		if a, ok := call.Args[0].(*ast.Ident); ok {
			arg = a.Name
		}
		return false
	})
	return arg
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkg
}
