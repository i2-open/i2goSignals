package server

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestPeerRouteTable_MatchesPeerRoutes (#373): every route the peer surface
// exports is the gateway's own peerRoutes() entry of the same name — same
// method, pattern and handler (before PeerRouteTable binds the surface issuer)
// — and the exported set is the eight-route subset the seam block names.
func TestPeerRouteTable_MatchesPeerRoutes(t *testing.T) {
	sa := &SignalsApplication{}
	full := map[string]Route{}
	for _, r := range (&HttpRouter{sa: sa}).peerRoutes() {
		full[r.Name] = r
	}

	got := sa.peerRouteSubset()
	if n := len(sa.PeerRouteTable()); n != len(got) {
		t.Fatalf("PeerRouteTable: got %d routes, subset has %d", n, len(got))
	}
	wantNames := []string{"GenerateIat", "RegisterClient", "TriggerEvent", "ReceivePushEvent",
		"VerificationRequestSSF", "JwksJson", "JwksJsonTenant", "PollEvents"}
	if len(got) != len(wantNames) {
		t.Fatalf("PeerRouteTable: got %d routes, want %d", len(got), len(wantNames))
	}
	for i, name := range wantNames {
		g := got[i]
		if g.Name != name {
			t.Fatalf("route %d: got %s, want %s", i, g.Name, name)
		}
		f, ok := full[name]
		if !ok {
			t.Fatalf("%s is not in peerRoutes()", name)
		}
		if g.Method != f.Method || g.Pattern != f.Pattern || g.IsIdQuery != f.IsIdQuery {
			t.Errorf("%s: got {%s %s %v}, peerRoutes has {%s %s %v}", name, g.Method, g.Pattern, g.IsIdQuery, f.Method, f.Pattern, f.IsIdQuery)
		}
		if reflect.ValueOf(g.HandlerFunc).Pointer() != reflect.ValueOf(f.HandlerFunc).Pointer() {
			t.Errorf("%s: handler differs from peerRoutes()", name)
		}
	}
}

// fakePeerRouter records the peer calls the adapter forwards.
type fakePeerRouter struct{ calls []string }

func (f *fakePeerRouter) HandleEventCtx(context.Context, *goSet.SecurityEventToken, string, string) error {
	f.calls = append(f.calls, "HandleEventCtx")
	return nil
}

func (f *fakePeerRouter) SubmitOperationalEvent(string, *goSet.SecurityEventToken, string) (*model.EventRecord, error) {
	f.calls = append(f.calls, "SubmitOperationalEvent")
	return nil, nil
}

func (f *fakePeerRouter) GenerateVerifyEvent(string, string) (*model.EventRecord, error) {
	f.calls = append(f.calls, "GenerateVerifyEvent")
	return nil, nil
}

func (f *fakePeerRouter) PollStreamHandler(context.Context, string, model.PollParameters) (map[string]string, bool, int) {
	f.calls = append(f.calls, "PollStreamHandler")
	return nil, false, 0
}

func (f *fakePeerRouter) DeliveryStarted() bool {
	f.calls = append(f.calls, "DeliveryStarted")
	return true
}

// TestPeerRouterAdapter_DelegatesPeerMethodsAndNamesUnsupported (#374 review):
// a narrow router is lifted to EventRouter by peerRouterAdapter. The five peer
// methods reach the router; any other method panics with a message naming the
// peer surface and the method, not a bare nil dereference.
func TestPeerRouterAdapter_DelegatesPeerMethodsAndNamesUnsupported(t *testing.T) {
	fake := &fakePeerRouter{}
	app := NewPeerApplication(PeerAppDeps{Router: fake})
	er := app.EventRouter
	if _, ok := er.(*peerRouterAdapter); !ok {
		t.Fatalf("narrow router: EventRouter is %T, want *peerRouterAdapter", er)
	}

	ctx := context.Background()
	_ = er.HandleEventCtx(ctx, nil, "", "sid")
	_, _ = er.SubmitOperationalEvent("sid", nil, "")
	_, _ = er.GenerateVerifyEvent("sid", "state")
	_, _, _ = er.PollStreamHandler(ctx, "sid", model.PollParameters{})
	_ = er.DeliveryStarted()
	want := []string{"HandleEventCtx", "SubmitOperationalEvent", "GenerateVerifyEvent", "PollStreamHandler", "DeliveryStarted"}
	if !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("delegated calls: got %v, want %v", fake.calls, want)
	}

	unsupported := map[string]func(){
		"HandleEvent":               func() { _ = er.HandleEvent(nil, "", "") },
		"HandleEventsCtx":           func() { _ = er.HandleEventsCtx(ctx, nil, nil, "") },
		"UpdateStreamState":         func() { er.UpdateStreamState(nil) },
		"RemoveStream":              func() { er.RemoveStream("sid") },
		"NotifySubjectFilterChange": func() { er.NotifySubjectFilterChange("sid") },
		"SstpServerHandler": func() {
			_, _ = er.SstpServerHandler(ctx, nil, goSetSstp.Message{}, nil)
		},
		"Shutdown":         func() { er.Shutdown() },
		"GetPushStreamCnt": func() { _ = er.GetPushStreamCnt() },
		"WakeSstpServer":   func() { er.WakeSstpServer("sid") },
	}
	for method, call := range unsupported {
		t.Run(method, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s did not panic", method)
				}
				msg := fmt.Sprint(r)
				if !strings.Contains(msg, "peer surface") || !strings.Contains(msg, method) {
					t.Errorf("%s panic %q does not name the peer surface and the method", method, msg)
				}
			}()
			call()
		})
	}
}
