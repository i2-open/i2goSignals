package delivery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sstpPairRecord builds a minimal SSTP pair record whose client side targets
// endpointUrl in RouteModeForward (no signing key needed).
func sstpPairRecord(endpointUrl string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        "tx-sid",
			Iss:       "https://issuer.example.com",
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		PairId: "pair-1",
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         endpointUrl,
			AuthorizationHeader: "Bearer pair-secret",
		},
	}
}

// TestSstpHTTPAdapter_PostsSetsAndParsesAck is the tracer bullet: one cycle posts
// the outbound SETs as application/sstp+json with the pair bearer, and the parsed
// "ack" is surfaced in the outcome with ClassOK.
func TestSstpHTTPAdapter_PostsSetsAndParsesAck(t *testing.T) {
	var gotCT, gotAuth string
	var gotBody goSetSstp.Message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: []string{"jti-1"}})
	}))
	defer srv.Close()

	adapter := NewSstpHTTPAdapter(srv.Client())
	out := adapter.DeliverSstp(context.Background(), SstpRequest{
		Stream: sstpPairRecord(srv.URL),
		Events: []*model.AgEventRecord{{Jti: "jti-1", Original: "signed.set.value"}},
	})

	assert.Equal(t, goSetSstp.ClassOK, out.Classification.Class)
	assert.Equal(t, []string{"jti-1"}, out.Acked)
	assert.Equal(t, goSetSstp.ContentType, gotCT)
	assert.Equal(t, "Bearer pair-secret", gotAuth)
	require.Contains(t, gotBody.Sets, "jti-1")
	assert.Equal(t, "signed.set.value", gotBody.Sets["jti-1"])
}

// TestSstpHTTPAdapter_ReturnEventsFalseOnWire: a second parallel push cycle
// (push-while-poll-held, Q7.2) sets SstpRequest.ReturnEvents=false; the adapter
// must surface that on the wire as returnEvents:false so the peer does NOT hold a
// long-poll for this short-lived push. When ReturnEvents is nil the field is
// omitted (default true applies on the peer).
func TestSstpHTTPAdapter_ReturnEventsFalseOnWire(t *testing.T) {
	var gotBody goSetSstp.Message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: []string{"jti-1"}})
	}))
	defer srv.Close()

	adapter := NewSstpHTTPAdapter(srv.Client())
	out := adapter.DeliverSstp(context.Background(), SstpRequest{
		Stream:       sstpPairRecord(srv.URL),
		Events:       []*model.AgEventRecord{{Jti: "jti-1", Original: "signed.set.value"}},
		ReturnEvents: goSetSstp.BoolPtr(false),
	})

	assert.Equal(t, goSetSstp.ClassOK, out.Classification.Class)
	require.NotNil(t, gotBody.ReturnEvents, "returnEvents must be present on the second push")
	assert.False(t, *gotBody.ReturnEvents, "second push must set returnEvents=false")
}

// TestSstpHTTPAdapter_ReturnEventsOmittedWhenNil: a normal (primary) cycle leaves
// ReturnEvents nil so the field is omitted and the peer applies the default (true).
func TestSstpHTTPAdapter_ReturnEventsOmittedWhenNil(t *testing.T) {
	var gotBody goSetSstp.Message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{})
	}))
	defer srv.Close()

	adapter := NewSstpHTTPAdapter(srv.Client())
	_ = adapter.DeliverSstp(context.Background(), SstpRequest{Stream: sstpPairRecord(srv.URL)})
	assert.Nil(t, gotBody.ReturnEvents, "primary cycle must omit returnEvents (default true)")
}

// TestSstpHTTPAdapter_4xxClassifiesRequestError: an HTTP 4xx maps to
// ClassRequestError so the runner pauses only the outbound direction.
func TestSstpHTTPAdapter_4xxClassifiesRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	adapter := NewSstpHTTPAdapter(srv.Client())
	out := adapter.DeliverSstp(context.Background(), SstpRequest{Stream: sstpPairRecord(srv.URL)})
	assert.Equal(t, goSetSstp.ClassRequestError, out.Classification.Class)
}

// TestSstpHTTPAdapter_5xxClassifiesTransient: an HTTP 5xx maps to ClassTransient
// so the runner backs off without pausing.
func TestSstpHTTPAdapter_5xxClassifiesTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	adapter := NewSstpHTTPAdapter(srv.Client())
	out := adapter.DeliverSstp(context.Background(), SstpRequest{Stream: sstpPairRecord(srv.URL)})
	assert.Equal(t, goSetSstp.ClassTransient, out.Classification.Class)
}

// TestSstpHTTPAdapter_TransportFailureClassifiesTransport: an unreachable peer
// yields ClassTransport (no HTTP response).
func TestSstpHTTPAdapter_TransportFailureClassifiesTransport(t *testing.T) {
	adapter := NewSstpHTTPAdapter(&http.Client{})
	// 127.0.0.1:1 is reliably refused.
	out := adapter.DeliverSstp(context.Background(), SstpRequest{Stream: sstpPairRecord("http://127.0.0.1:1/sstp/pair-1")})
	assert.Equal(t, goSetSstp.ClassTransport, out.Classification.Class)
}
