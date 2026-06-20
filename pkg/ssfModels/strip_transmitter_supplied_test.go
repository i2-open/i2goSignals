package model

import "testing"

// TestStripTransmitterSupplied is the pure, table-driven contract test for the
// lifted helper. It is the single source of truth for strip behavior shared by
// the CLI (executeCreateRequest) and the server-side receiver create-stream
// handler. See strip_transmitter_supplied.go for the SSF §8.1.1.1 rationale.
func TestStripTransmitterSupplied(t *testing.T) {
	pushTransmit := func() *OneOfStreamConfigurationDelivery {
		return &OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &PushTransmitMethod{
				Method:      DeliveryPush,
				EndpointUrl: "https://receiver.example.com/events",
			},
		}
	}
	pollTransmit := func() *OneOfStreamConfigurationDelivery {
		return &OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &PollTransmitMethod{Method: DeliveryPoll},
		}
	}
	pushReceive := func() *OneOfStreamConfigurationDelivery {
		return &OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &PushReceiveMethod{
				Method:      ReceivePush,
				EndpointUrl: "https://sut.example.com/events",
			},
		}
	}
	pollReceive := func() *OneOfStreamConfigurationDelivery {
		return &OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &PollReceiveMethod{
				Method:      ReceivePoll,
				EndpointUrl: "https://transmitter.example.com/poll",
			},
		}
	}

	const iss = "https://issuer.example.com"
	const jwks = "https://issuer.example.com/jwks.json"
	aud := []string{"https://other.example.com"}

	cases := []struct {
		name           string
		strict         bool
		deliver        func() *OneOfStreamConfigurationDelivery
		wantIdentityON bool // true => Iss/Aud/IssuerJWKSUrl preserved
	}{
		// Flexible: identity always preserved (operator intent).
		{"flexible-push-transmit", false, pushTransmit, true},
		{"flexible-poll-transmit", false, pollTransmit, true},
		{"flexible-push-receive", false, pushReceive, true},
		{"flexible-poll-receive", false, pollReceive, true},
		// Strict: transmitter-side (publisher-leg) stripped; receiver-side kept.
		{"strict-push-transmit", true, pushTransmit, false},
		{"strict-poll-transmit", true, pollTransmit, false},
		{"strict-push-receive", true, pushReceive, true},
		{"strict-poll-receive", true, pollReceive, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			reg := StreamConfiguration{
				Id:                      "should-be-cleared",
				Iss:                     iss,
				Aud:                     aud,
				IssuerJWKSUrl:           jwks,
				EventsSupported:         []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
				EventsDelivered:         []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
				MinVerificationInterval: 42,
				InactivityTimeout:       99,
				Delivery:                tc.deliver(),
			}

			wire := StripTransmitterSupplied(reg, tc.strict)

			// Read-Only fields are always cleared regardless of strict.
			if wire.Id != "" {
				t.Errorf("Id = %q, want cleared", wire.Id)
			}
			if wire.EventsSupported != nil {
				t.Errorf("EventsSupported = %v, want nil", wire.EventsSupported)
			}
			if wire.EventsDelivered != nil {
				t.Errorf("EventsDelivered = %v, want nil", wire.EventsDelivered)
			}
			if wire.MinVerificationInterval != 0 {
				t.Errorf("MinVerificationInterval = %d, want 0", wire.MinVerificationInterval)
			}
			if wire.InactivityTimeout != 0 {
				t.Errorf("InactivityTimeout = %d, want 0", wire.InactivityTimeout)
			}

			if tc.wantIdentityON {
				if wire.Iss != iss {
					t.Errorf("Iss = %q, want preserved %q", wire.Iss, iss)
				}
				if len(wire.Aud) != 1 || wire.Aud[0] != aud[0] {
					t.Errorf("Aud = %v, want preserved %v", wire.Aud, aud)
				}
				if wire.IssuerJWKSUrl != jwks {
					t.Errorf("IssuerJWKSUrl = %q, want preserved %q", wire.IssuerJWKSUrl, jwks)
				}
			} else {
				if wire.Iss != "" {
					t.Errorf("Iss = %q, want stripped", wire.Iss)
				}
				if wire.Aud != nil {
					t.Errorf("Aud = %v, want stripped (nil)", wire.Aud)
				}
				if wire.IssuerJWKSUrl != "" {
					t.Errorf("IssuerJWKSUrl = %q, want stripped", wire.IssuerJWKSUrl)
				}
			}
		})
	}

	// Purity: the input must not be mutated.
	t.Run("does-not-mutate-input", func(t *testing.T) {
		reg := StreamConfiguration{
			Id:       "keep-me",
			Iss:      iss,
			Aud:      aud,
			Delivery: pushTransmit(),
		}
		_ = StripTransmitterSupplied(reg, true)
		if reg.Id != "keep-me" {
			t.Errorf("input Id mutated to %q", reg.Id)
		}
		if reg.Iss != iss {
			t.Errorf("input Iss mutated to %q", reg.Iss)
		}
		if len(reg.Aud) != 1 || reg.Aud[0] != aud[0] {
			t.Errorf("input Aud mutated to %v", reg.Aud)
		}
	})

	// Nil delivery under strict must not panic and strips identity (treated as
	// non-receiver-side / publisher-leg by default).
	t.Run("nil-delivery-strict", func(t *testing.T) {
		reg := StreamConfiguration{Iss: iss, Aud: aud, IssuerJWKSUrl: jwks}
		wire := StripTransmitterSupplied(reg, true)
		if wire.Iss != "" || wire.Aud != nil || wire.IssuerJWKSUrl != "" {
			t.Errorf("nil-delivery strict did not strip: iss=%q aud=%v jwks=%q", wire.Iss, wire.Aud, wire.IssuerJWKSUrl)
		}
	})
}
