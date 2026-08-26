package mongo_provider

import (
	"context"
	"errors"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// unreachableClient returns a lazily-connected Mongo client pointing at a port
// nothing listens on. The driver does not dial on construction, so this needs no
// server: every operation the tests below issue fails on the context rather than
// on the network, which is exactly the distinction under test.
func unreachableClient(t *testing.T) *mongo.Client {
	t.Helper()
	cl, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/").
		SetServerSelectionTimeout(30 * time.Second))
	if err != nil {
		t.Fatalf("constructing lazy mongo client: %v", err)
	}
	t.Cleanup(func() { _ = cl.Disconnect(context.Background()) })
	return cl
}

// TestCoordinatorOpsAbortWhenTheLifecycleIsCancelled is the S4 acceptance test:
// the coordinator's heartbeat round-trips derive from the lifecycle context, so
// cancelling it at shutdown aborts an in-flight lease renew immediately instead
// of leaving it to burn its own 5s operation budget against a connection the
// process is dropping.
//
// Server selection is given 30s and the server does not exist, so the only way
// these calls can return promptly with context.Canceled is by deriving from the
// cancelled parent.
func TestCoordinatorOpsAbortWhenTheLifecycleIsCancelled(t *testing.T) {
	lifecycle, cancel := context.WithCancel(context.Background())
	coord := NewMongoCoordinator(lifecycle)

	db := unreachableClient(t).Database("lifecycle_ctx_test")
	coord.SetCollections(db.Collection(CDbLeases), db.Collection(CDbNodes))

	cancel() // shutdown

	ops := map[string]func() error{
		"TryAcquireOrRenewLease": func() error {
			_, _, err := coord.TryAcquireOrRenewLease("resource", "node-1", 30*time.Second)
			return err
		},
		"ReleaseLeaseIfOwned": func() error {
			return coord.ReleaseLeaseIfOwned("resource", "node-1")
		},
		"GetLeaseOwner": func() error {
			_, _, _, err := coord.GetLeaseOwner("resource")
			return err
		},
		"RegisterNode": func() error {
			return coord.RegisterNode(model.ClusterNode{Id: "node-1"})
		},
		"GetActiveNodeCount": func() error {
			_, err := coord.GetActiveNodeCount()
			return err
		},
		"GetActiveNodes": func() error {
			_, err := coord.GetActiveNodes()
			return err
		},
		"GetNode": func() error {
			_, err := coord.GetNode("node-1")
			return err
		},
	}

	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			err := op()
			elapsed := time.Since(start)

			if !errors.Is(err, context.Canceled) {
				t.Fatalf("got %v, want an error wrapping context.Canceled: the "+
					"operation is not deriving from the lifecycle context", err)
			}
			if elapsed > time.Second {
				t.Fatalf("took %v to observe cancellation; it should be immediate", elapsed)
			}
		})
	}
}

// TestNewMongoCoordinatorTreatsNilCtxAsBackground pins the documented fallback:
// a caller with no lifecycle to offer still gets a usable coordinator rather
// than a nil-parent panic inside context.WithTimeout.
func TestNewMongoCoordinatorTreatsNilCtxAsBackground(t *testing.T) {
	//lint:ignore SA1012 deliberately exercising the nil-ctx fallback
	coord := NewMongoCoordinator(nil)
	ctx, cancel := coord.opCtx()
	defer cancel()

	if ctx.Err() != nil {
		t.Fatalf("derived context is already done: %v", ctx.Err())
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("derived context has no deadline; the operation timeout was lost")
	}
	if remaining := time.Until(deadline); remaining > coordinatorOpTimeout {
		t.Fatalf("derived deadline is %v out, want at most %v", remaining, coordinatorOpTimeout)
	}
}

// TestOpenWithContextThreadsTheLifecycleToTheCoordinator pins the S4 wiring
// inside the provider: whatever ctx MongoProvider is constructed with is the ctx
// its coordinator heartbeats derive from. Without this the coordinator could
// silently fall back to context.Background and every other test here would still
// pass, because they construct the coordinator directly.
func TestOpenWithContextThreadsTheLifecycleToTheCoordinator(t *testing.T) {
	lifecycle, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancelled before Open so the initial connect aborts on the lifecycle
	// context instead of spending its 60s budget on an unreachable host. That
	// it aborts at all is itself part of the wiring under test.
	cancel()

	p, err := OpenWithContext(lifecycle, "mongodb://127.0.0.1:1/", "lifecycle_wiring_test")
	if p == nil {
		t.Fatalf("OpenWithContext returned no provider (err=%v)", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.lifetimeCtx() != lifecycle {
		t.Fatal("provider did not retain the lifecycle context it was opened with")
	}
	if p.coordinator == nil {
		t.Fatal("provider has no coordinator")
	}
	if p.coordinator.ctx != lifecycle {
		t.Fatal("coordinator heartbeats are not scoped to the provider's lifecycle context")
	}

	// Teardown must survive the cancellation that triggers it, or Close would
	// abort its own Disconnect.
	if err := p.teardownCtx().Err(); err != nil {
		t.Fatalf("teardown context is cancelled (%v); Disconnect would abort immediately", err)
	}
}

// TestOpenUsesBackgroundLifecycle documents the convenience form: Open is
// OpenWithContext with no shutdown signal, and must not leave a nil parent
// context behind for the coordinator to trip over.
func TestOpenUsesBackgroundLifecycle(t *testing.T) {
	// A URI the driver rejects outright, so the initial connect fails on
	// parsing rather than waiting out a dial to a host that is not there.
	p, _ := Open("mongodb://:::/", "lifecycle_default_test")
	if p == nil {
		t.Fatal("Open returned no provider")
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.lifetimeCtx() == nil {
		t.Fatal("provider lifecycle context is nil")
	}
	if err := p.lifetimeCtx().Err(); err != nil {
		t.Fatalf("provider lifecycle context is already done: %v", err)
	}
}
