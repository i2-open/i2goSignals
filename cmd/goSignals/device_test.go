package main

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "testing"
    "time"
)

// TestRequestDeviceAuthorization_ParsesResponse verifies the RFC 8628 device
// authorization request: it POSTs client_id + scope to the device
// authorization endpoint and parses device_code, user_code, verification_uri,
// verification_uri_complete, interval and expires_in.
func TestRequestDeviceAuthorization_ParsesResponse(t *testing.T) {
    var gotForm url.Values
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        gotForm = r.Form
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{
            "device_code":"dev-123",
            "user_code":"WDJB-MJHT",
            "verification_uri":"https://idp.example.com/device",
            "verification_uri_complete":"https://idp.example.com/device?user_code=WDJB-MJHT",
            "expires_in":900,
            "interval":5
        }`))
    }))
    defer srv.Close()

    da, err := requestDeviceAuthorization(srv.URL, "gosignals-cli", []string{"openid", "admin"})
    if err != nil {
        t.Fatalf("requestDeviceAuthorization failed: %v", err)
    }
    if gotForm.Get("client_id") != "gosignals-cli" {
        t.Errorf("expected client_id in request, got %q", gotForm.Get("client_id"))
    }
    if gotForm.Get("scope") != "openid admin" {
        t.Errorf("expected space-joined scope, got %q", gotForm.Get("scope"))
    }
    if da.DeviceCode != "dev-123" || da.UserCode != "WDJB-MJHT" {
        t.Errorf("unexpected device authorization: %+v", da)
    }
    if da.VerificationURI != "https://idp.example.com/device" {
        t.Errorf("unexpected verification_uri: %q", da.VerificationURI)
    }
    if da.VerificationURIComplete != "https://idp.example.com/device?user_code=WDJB-MJHT" {
        t.Errorf("unexpected verification_uri_complete: %q", da.VerificationURIComplete)
    }
    if da.Interval != 5 || da.ExpiresIn != 900 {
        t.Errorf("unexpected interval/expires_in: %+v", da)
    }
}

// TestRequestDeviceAuthorization_DefaultsInterval verifies that when the IdP
// omits interval, RFC 8628's default of 5 seconds is applied.
func TestRequestDeviceAuthorization_DefaultsInterval(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"device_code":"d","user_code":"u","verification_uri":"https://x/device","expires_in":600}`))
    }))
    defer srv.Close()

    da, err := requestDeviceAuthorization(srv.URL, "c", nil)
    if err != nil {
        t.Fatalf("requestDeviceAuthorization failed: %v", err)
    }
    if da.Interval != 5 {
        t.Errorf("expected default interval 5, got %d", da.Interval)
    }
}

// TestRequestDeviceAuthorization_ErrorStatus surfaces a non-2xx response as an
// error rather than a malformed device authorization.
func TestRequestDeviceAuthorization_ErrorStatus(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte(`{"error":"invalid_client"}`))
    }))
    defer srv.Close()

    if _, err := requestDeviceAuthorization(srv.URL, "c", nil); err == nil {
        t.Error("expected error on non-2xx device authorization response")
    }
}

// TestPollDeviceToken_PendingThenSuccess drives the polling loop: the token
// endpoint first returns authorization_pending, then a successful token
// response. The loop must keep polling and yield a Session.
func TestPollDeviceToken_PendingThenSuccess(t *testing.T) {
    idToken := makeUnsignedIDToken(map[string]any{"sub": "bob", "email": "bob@example.com"})
    var calls int
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
            t.Errorf("expected device_code grant_type, got %q", r.Form.Get("grant_type"))
        }
        if r.Form.Get("device_code") != "dev-xyz" {
            t.Errorf("expected device_code, got %q", r.Form.Get("device_code"))
        }
        calls++
        w.Header().Set("Content-Type", "application/json")
        if calls < 2 {
            w.WriteHeader(http.StatusBadRequest)
            _, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
            return
        }
        _, _ = w.Write([]byte(`{"access_token":"acc","refresh_token":"ref","expires_in":3600,"scope":"admin","id_token":"` + idToken + `"}`))
    }))
    defer srv.Close()

    da := &deviceAuthorization{DeviceCode: "dev-xyz", Interval: 1, ExpiresIn: 60}
    sess, err := pollDeviceToken(deviceTokenRequest{
        TokenEndpoint: srv.URL,
        ClientId:      "gosignals-cli",
        Device:        da,
        clock:         fakeClock(),
    })
    if err != nil {
        t.Fatalf("pollDeviceToken failed: %v", err)
    }
    if calls < 2 {
        t.Errorf("expected at least 2 polls (pending then success), got %d", calls)
    }
    if sess.AccessToken != "acc" || sess.Subject != "bob" {
        t.Errorf("unexpected session: %+v", sess)
    }
}

// TestPollDeviceToken_SlowDownBacksOff verifies that a slow_down error
// increases the polling interval by 5 seconds per RFC 8628 and the loop
// recovers on the next successful poll.
func TestPollDeviceToken_SlowDownBacksOff(t *testing.T) {
    var sleeps []time.Duration
    clk := &recordingClock{}
    var calls int
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        w.Header().Set("Content-Type", "application/json")
        switch calls {
        case 1:
            w.WriteHeader(http.StatusBadRequest)
            _, _ = w.Write([]byte(`{"error":"slow_down"}`))
        default:
            _, _ = w.Write([]byte(`{"access_token":"acc"}`))
        }
    }))
    defer srv.Close()

    da := &deviceAuthorization{DeviceCode: "d", Interval: 5, ExpiresIn: 120}
    _, err := pollDeviceToken(deviceTokenRequest{
        TokenEndpoint: srv.URL,
        ClientId:      "c",
        Device:        da,
        clock:         clk.sleep,
    })
    if err != nil {
        t.Fatalf("pollDeviceToken failed: %v", err)
    }
    sleeps = clk.sleeps
    if len(sleeps) < 2 {
        t.Fatalf("expected at least 2 sleeps, got %v", sleeps)
    }
    // First sleep is the initial interval (5s); after slow_down the next sleep
    // must be 5s longer (10s).
    if sleeps[0] != 5*time.Second {
        t.Errorf("expected first sleep of 5s, got %v", sleeps[0])
    }
    if sleeps[1] != 10*time.Second {
        t.Errorf("expected interval to grow to 10s after slow_down, got %v", sleeps[1])
    }
}

// TestPollDeviceToken_ExpiredToken stops with an error when the IdP reports the
// device code has expired.
func TestPollDeviceToken_ExpiredToken(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte(`{"error":"expired_token"}`))
    }))
    defer srv.Close()

    da := &deviceAuthorization{DeviceCode: "d", Interval: 1, ExpiresIn: 60}
    if _, err := pollDeviceToken(deviceTokenRequest{
        TokenEndpoint: srv.URL,
        ClientId:      "c",
        Device:        da,
        clock:         fakeClock(),
    }); err == nil {
        t.Error("expected error when device code expired")
    }
}

// TestPollDeviceToken_LocalDeadline stops polling once the device code's own
// expires_in has elapsed, without depending on the IdP returning expired_token.
func TestPollDeviceToken_LocalDeadline(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
    }))
    defer srv.Close()

    // expires_in of 0 means the deadline is already reached after the first poll.
    da := &deviceAuthorization{DeviceCode: "d", Interval: 1, ExpiresIn: 0}
    if _, err := pollDeviceToken(deviceTokenRequest{
        TokenEndpoint: srv.URL,
        ClientId:      "c",
        Device:        da,
        clock:         fakeClock(),
    }); err == nil {
        t.Error("expected error when device code local deadline elapses")
    }
}

// TestRunDeviceLogin_EndToEnd drives the full device-code flow against a mock
// IdP: request device authorization, then poll the token endpoint (pending then
// success). It verifies the resulting Session has the same shape as the PKCE
// path (access/refresh token, subject from id_token).
func TestRunDeviceLogin_EndToEnd(t *testing.T) {
    idToken := makeUnsignedIDToken(map[string]any{"sub": "carol", "email": "carol@example.com"})
    var polls int
    mux := http.NewServeMux()
    mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://idp/device","verification_uri_complete":"https://idp/device?user_code=ABCD-EFGH","expires_in":120,"interval":1}`))
    })
    mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
        polls++
        w.Header().Set("Content-Type", "application/json")
        if polls < 2 {
            w.WriteHeader(http.StatusBadRequest)
            _, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
            return
        }
        _, _ = w.Write([]byte(`{"access_token":"acc","refresh_token":"ref","expires_in":3600,"scope":"admin","id_token":"` + idToken + `"}`))
    })
    srv := httptest.NewServer(mux)
    defer srv.Close()

    sess, err := runDeviceLogin(loginOptions{
        Issuer:   "https://idp.example.com",
        ClientId: "gosignals-cli",
        Scopes:   []string{"openid", "admin"},
        Endpoints: &oidcEndpoints{
            Token:               srv.URL + "/token",
            DeviceAuthorization: srv.URL + "/device",
            Issuer:              "https://idp.example.com",
        },
        sleep: fakeClock(),
    })
    if err != nil {
        t.Fatalf("runDeviceLogin failed: %v", err)
    }
    if sess.AccessToken != "acc" || sess.RefreshToken != "ref" || sess.Subject != "carol" {
        t.Errorf("device login produced unexpected session: %+v", sess)
    }
}

// TestRunDeviceLogin_RequiresDeviceEndpoint errors clearly when the issuer does
// not advertise a device authorization endpoint.
func TestRunDeviceLogin_RequiresDeviceEndpoint(t *testing.T) {
    _, err := runDeviceLogin(loginOptions{
        ClientId:  "c",
        Endpoints: &oidcEndpoints{Token: "https://idp/token"},
    })
    if err == nil {
        t.Error("expected error when device_authorization_endpoint is not advertised")
    }
}

// TestRunLogin_ForceDeviceRoutesToDeviceFlow verifies the public dispatcher:
// with ForceDevice set, runLogin runs the device-code flow even on a host that
// could bind loopback and open a browser.
func TestRunLogin_ForceDeviceRoutesToDeviceFlow(t *testing.T) {
    idToken := makeUnsignedIDToken(map[string]any{"sub": "dave"})
    mux := http.NewServeMux()
    mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"device_code":"dc","user_code":"U","verification_uri":"https://idp/device","expires_in":120,"interval":1}`))
    })
    mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
        _ = r.ParseForm()
        if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
            t.Errorf("expected device_code grant, got %q", r.Form.Get("grant_type"))
        }
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"access_token":"acc","id_token":"` + idToken + `"}`))
    })
    srv := httptest.NewServer(mux)
    defer srv.Close()

    sess, err := runLogin(loginOptions{
        ClientId: "c",
        Endpoints: &oidcEndpoints{
            Token:               srv.URL + "/token",
            DeviceAuthorization: srv.URL + "/device",
        },
        ForceDevice: true,
        sleep:       fakeClock(),
    })
    if err != nil {
        t.Fatalf("runLogin (force device) failed: %v", err)
    }
    if sess.AccessToken != "acc" || sess.Subject != "dave" {
        t.Errorf("unexpected session from forced device flow: %+v", sess)
    }
}

// TestRunLogin_AutoFallbackToDeviceWhenHeadless verifies the auto-fallback: with
// no browser and no loopback bind available, runLogin selects the device-code
// flow without --device.
func TestRunLogin_AutoFallbackToDeviceWhenHeadless(t *testing.T) {
    origBrowser := browserAvailable
    origBind := canBindLoopback
    defer func() {
        browserAvailable = origBrowser
        canBindLoopback = origBind
    }()
    browserAvailable = func() bool { return false }
    canBindLoopback = func() bool { return false }

    idToken := makeUnsignedIDToken(map[string]any{"sub": "erin"})
    mux := http.NewServeMux()
    mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"device_code":"dc","user_code":"U","verification_uri":"https://idp/device","expires_in":120,"interval":1}`))
    })
    mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"access_token":"acc","id_token":"` + idToken + `"}`))
    })
    srv := httptest.NewServer(mux)
    defer srv.Close()

    sess, err := runLogin(loginOptions{
        ClientId: "c",
        Endpoints: &oidcEndpoints{
            Token:               srv.URL + "/token",
            DeviceAuthorization: srv.URL + "/device",
        },
        sleep: fakeClock(),
    })
    if err != nil {
        t.Fatalf("runLogin (auto-fallback) failed: %v", err)
    }
    if sess.AccessToken != "acc" || sess.Subject != "erin" {
        t.Errorf("auto-fallback did not produce device session: %+v", sess)
    }
}

// TestSelectLoginMethod_ForceDevice forces the device path regardless of
// loopback/browser availability.
func TestSelectLoginMethod_ForceDevice(t *testing.T) {
    m := selectLoginMethod(loginCapabilities{ForceDevice: true, CanBindLoopback: true, CanOpenBrowser: true})
    if m != loginMethodDevice {
        t.Errorf("--device should force device path, got %v", m)
    }
}

// TestSelectLoginMethod_FallbackWhenNoLoopback chooses device-code when a
// loopback listener cannot be bound (e.g. locked-down container).
func TestSelectLoginMethod_FallbackWhenNoLoopback(t *testing.T) {
    m := selectLoginMethod(loginCapabilities{CanBindLoopback: false, CanOpenBrowser: true})
    if m != loginMethodDevice {
        t.Errorf("missing loopback should fall back to device, got %v", m)
    }
}

// TestSelectLoginMethod_FallbackWhenNoBrowser chooses device-code on a headless
// host where no browser can be opened.
func TestSelectLoginMethod_FallbackWhenNoBrowser(t *testing.T) {
    m := selectLoginMethod(loginCapabilities{CanBindLoopback: true, CanOpenBrowser: false})
    if m != loginMethodDevice {
        t.Errorf("missing browser should fall back to device, got %v", m)
    }
}

// TestSelectLoginMethod_PKCEWhenCapable uses the loopback PKCE path when both a
// loopback listener and a browser are available and --device was not given.
func TestSelectLoginMethod_PKCEWhenCapable(t *testing.T) {
    m := selectLoginMethod(loginCapabilities{CanBindLoopback: true, CanOpenBrowser: true})
    if m != loginMethodPKCE {
        t.Errorf("capable host should use PKCE loopback, got %v", m)
    }
}

// fakeClock returns a sleep func that does not actually sleep, so polling tests
// run instantly.
func fakeClock() func(time.Duration) {
    return func(time.Duration) {}
}

// recordingClock records the durations it is asked to sleep without sleeping.
type recordingClock struct {
    sleeps []time.Duration
}

func (c *recordingClock) sleep(d time.Duration) {
    c.sleeps = append(c.sleeps, d)
}
