package services

import "testing"

// TestNewStreamServiceConfigDefaults pins the StreamServiceConfig contract
// decided in issue #182: MinVerificationInterval / MaxInactivityTimeout treat
// any non-positive value (absent zero-value cfg, explicit 0, or negative) as
// "unset" and fall back to the historical defaults (300 / 3600); a positive
// value is preserved verbatim. `0` is not a supported operator value for these
// knobs because the rest of the stream-config layer interprets 0 as "unset".
func TestNewStreamServiceConfigDefaults(t *testing.T) {
    const (
        defaultMinVerification = 300
        defaultMaxInactivity   = 3600
    )

    tests := []struct {
        name                string
        cfg                 StreamServiceConfig
        wantMinVerification int
        wantMaxInactivity   int
    }{
        {
            name:                "absent uses defaults",
            cfg:                 StreamServiceConfig{},
            wantMinVerification: defaultMinVerification,
            wantMaxInactivity:   defaultMaxInactivity,
        },
        {
            name:                "explicit zero coerces to defaults",
            cfg:                 StreamServiceConfig{MinVerificationInterval: 0, MaxInactivityTimeout: 0},
            wantMinVerification: defaultMinVerification,
            wantMaxInactivity:   defaultMaxInactivity,
        },
        {
            name:                "negative coerces to defaults",
            cfg:                 StreamServiceConfig{MinVerificationInterval: -1, MaxInactivityTimeout: -42},
            wantMinVerification: defaultMinVerification,
            wantMaxInactivity:   defaultMaxInactivity,
        },
        {
            name:                "positive preserved",
            cfg:                 StreamServiceConfig{MinVerificationInterval: 120, MaxInactivityTimeout: 7200},
            wantMinVerification: 120,
            wantMaxInactivity:   7200,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            svc := NewStreamService(nil, nil, "http://test", tt.cfg)
            if svc.minVerificationInterval != tt.wantMinVerification {
                t.Errorf("minVerificationInterval = %d, want %d",
                    svc.minVerificationInterval, tt.wantMinVerification)
            }
            if svc.maxInactivityTimeout != tt.wantMaxInactivity {
                t.Errorf("maxInactivityTimeout = %d, want %d",
                    svc.maxInactivityTimeout, tt.wantMaxInactivity)
            }
        })
    }
}
