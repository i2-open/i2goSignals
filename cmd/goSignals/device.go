package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/url"
    "strings"
    "time"
)

// deviceCodeGrantType is the RFC 8628 grant_type used when polling the token
// endpoint for a device-code authorization.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// deviceAuthorization is the subset of the RFC 8628 device authorization
// response the CLI consumes.
type deviceAuthorization struct {
    DeviceCode              string `json:"device_code"`
    UserCode                string `json:"user_code"`
    VerificationURI         string `json:"verification_uri"`
    VerificationURIComplete string `json:"verification_uri_complete"`
    ExpiresIn               int    `json:"expires_in"`
    Interval                int    `json:"interval"`
}

// requestDeviceAuthorization performs the RFC 8628 device authorization request,
// posting the public client_id (and optional scopes) to the issuer's device
// authorization endpoint. A missing interval defaults to 5 seconds per the spec.
func requestDeviceAuthorization(deviceEndpoint, clientId string, scopes []string) (*deviceAuthorization, error) {
    form := url.Values{}
    form.Set("client_id", clientId)
    scope := "openid email profile"
    if len(scopes) > 0 {
        scope = strings.Join(scopes, " ")
    }
    form.Set("scope", scope)

    client := getHttpClient(30 * time.Second)
    resp, err := client.PostForm(deviceEndpoint, form)
    if err != nil {
        return nil, err
    }
    defer func() { _ = resp.Body.Close() }()
    body, _ := io.ReadAll(resp.Body)
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, fmt.Errorf("device authorization endpoint returned %s: %s", resp.Status, string(body))
    }

    var da deviceAuthorization
    if err := json.Unmarshal(body, &da); err != nil {
        return nil, fmt.Errorf("could not parse device authorization response: %w", err)
    }
    if da.DeviceCode == "" {
        return nil, fmt.Errorf("device authorization response did not include a device_code")
    }
    if da.Interval <= 0 {
        da.Interval = 5
    }
    return &da, nil
}

// loginMethod identifies which login flow the engine will run.
type loginMethod int

const (
    loginMethodPKCE loginMethod = iota
    loginMethodDevice
)

func (m loginMethod) String() string {
    if m == loginMethodDevice {
        return "device-code"
    }
    return "pkce-loopback"
}

// loginCapabilities describes what the current host can do, so the engine can
// pick the appropriate login flow.
type loginCapabilities struct {
    // ForceDevice is set by the --device flag.
    ForceDevice bool
    // CanBindLoopback is true when an ephemeral 127.0.0.1 listener was bound.
    CanBindLoopback bool
    // CanOpenBrowser is true when the system browser can be launched.
    CanOpenBrowser bool
}

// selectLoginMethod chooses between the PKCE loopback flow and the RFC 8628
// device-code flow. --device always forces device-code; otherwise the
// device-code flow is selected automatically whenever a loopback listener can't
// be bound or a browser can't be opened (headless hosts, SSH sessions,
// locked-down containers). When both capabilities are present, the richer PKCE
// loopback flow is used.
func selectLoginMethod(caps loginCapabilities) loginMethod {
    if caps.ForceDevice {
        return loginMethodDevice
    }
    if !caps.CanBindLoopback || !caps.CanOpenBrowser {
        return loginMethodDevice
    }
    return loginMethodPKCE
}

// runDeviceLogin performs the RFC 8628 device authorization grant: it requests
// a device/user code, prints the verification URL + user code for the operator
// to complete on a second device, then polls the token endpoint until the
// authorization completes. It produces a Session identical in shape to the PKCE
// path by reusing sessionFromTokenResponse.
func runDeviceLogin(opts loginOptions) (*Session, error) {
    if opts.Endpoints == nil || opts.Endpoints.DeviceAuthorization == "" {
        return nil, fmt.Errorf("issuer does not advertise a device_authorization_endpoint; device-code login is not available")
    }

    da, err := requestDeviceAuthorization(opts.Endpoints.DeviceAuthorization, opts.ClientId, opts.Scopes)
    if err != nil {
        return nil, err
    }

    fmt.Println("To complete login, on any device open:")
    if da.VerificationURIComplete != "" {
        fmt.Println("  " + da.VerificationURIComplete)
        fmt.Println("(or open " + da.VerificationURI + " and enter code: " + da.UserCode + ")")
    } else {
        fmt.Println("  " + da.VerificationURI)
        fmt.Println("and enter code: " + da.UserCode)
    }
    fmt.Println("Waiting for authorization...")

    return pollDeviceToken(deviceTokenRequest{
        TokenEndpoint: opts.Endpoints.Token,
        ClientId:      opts.ClientId,
        Device:        da,
        clock:         opts.sleep,
    })
}

// deviceTokenRequest carries the parameters for polling the token endpoint with
// a device_code grant. clock is a seam so tests can drive the polling loop
// without real time elapsing.
type deviceTokenRequest struct {
    TokenEndpoint string
    ClientId      string
    Device        *deviceAuthorization
    // clock is invoked to wait between polls; defaults to time.Sleep.
    clock func(time.Duration)
}

// pollDeviceToken implements the RFC 8628 token polling loop. It repeatedly
// POSTs grant_type=device_code to the token endpoint, sleeping the advertised
// interval between attempts. authorization_pending continues polling; slow_down
// grows the interval by 5 seconds; expired_token (or the locally-tracked
// expires_in deadline) aborts; any other error aborts. A successful response is
// converted to a Session via the shared sessionFromTokenResponse helper.
func pollDeviceToken(req deviceTokenRequest) (*Session, error) {
    sleep := req.clock
    if sleep == nil {
        sleep = time.Sleep
    }
    interval := time.Duration(req.Device.Interval) * time.Second
    if interval <= 0 {
        interval = 5 * time.Second
    }
    deadline := time.Now().Add(time.Duration(req.Device.ExpiresIn) * time.Second)

    client := getHttpClient(30 * time.Second)
    for {
        sleep(interval)

        form := url.Values{}
        form.Set("grant_type", deviceCodeGrantType)
        form.Set("device_code", req.Device.DeviceCode)
        form.Set("client_id", req.ClientId)

        resp, err := client.PostForm(req.TokenEndpoint, form)
        if err != nil {
            return nil, err
        }
        body, _ := io.ReadAll(resp.Body)
        _ = resp.Body.Close()

        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            return sessionFromTokenBody(body, req.ClientId)
        }

        var errResp struct {
            Error            string `json:"error"`
            ErrorDescription string `json:"error_description"`
        }
        _ = json.Unmarshal(body, &errResp)

        switch errResp.Error {
        case "authorization_pending":
            // keep polling at the current interval
        case "slow_down":
            interval += 5 * time.Second
        case "expired_token":
            return nil, fmt.Errorf("device code expired before authorization completed")
        default:
            return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, string(body))
        }

        if time.Now().After(deadline) {
            return nil, fmt.Errorf("device code expired before authorization completed")
        }
    }
}
