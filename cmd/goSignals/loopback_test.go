package main

import (
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestLoopbackCallback_CapturesCodeOnMatchingState(t *testing.T) {
    cb := newLoopbackCallback("expected-state")
    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code-123&state=expected-state", nil)

    cb.handler(rec, req)

    select {
    case res := <-cb.result:
        if res.err != nil {
            t.Fatalf("unexpected callback error: %v", res.err)
        }
        if res.code != "auth-code-123" {
            t.Errorf("expected code 'auth-code-123', got %q", res.code)
        }
    case <-time.After(time.Second):
        t.Fatal("callback did not deliver a result")
    }
    if rec.Code != http.StatusOK {
        t.Errorf("expected 200 to the browser, got %d", rec.Code)
    }
}

func TestLoopbackCallback_RejectsStateMismatch(t *testing.T) {
    cb := newLoopbackCallback("expected-state")
    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state=wrong", nil)

    cb.handler(rec, req)

    select {
    case res := <-cb.result:
        if res.err == nil {
            t.Errorf("expected error on state mismatch (CSRF protection)")
        }
    case <-time.After(time.Second):
        t.Fatal("callback did not deliver a result")
    }
}

func TestLoopbackCallback_SurfacesIdPError(t *testing.T) {
    cb := newLoopbackCallback("s")
    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=nope&state=s", nil)

    cb.handler(rec, req)

    select {
    case res := <-cb.result:
        if res.err == nil {
            t.Errorf("expected error when IdP returns error param")
        }
    case <-time.After(time.Second):
        t.Fatal("callback did not deliver a result")
    }
}
