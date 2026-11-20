// Regression tests for the stream-registration request shape that the
// goSignals CLI sends to its registration target (executeCreateRequest →
// stripTransmitterSupplied). Conformance-driven fixes are locked in here so Go
// unit tests catch regressions without re-running the 20-min SSF conformance
// suite:
//
//  1. stripTransmitterSupplied(reg, strict=false) preserves Aud/Iss/IssuerJWKSUrl
//     on BOTH receiver-side and transmitter-side registrations. On receiver-side
//     they are the foreign transmitter's hints the local SUT needs to validate
//     inbound SETs (RFC8417 §2.2) and discover SSF endpoints (commit 7fc5946).
//     On transmitter-side they are the operator's --iss / --aud /
//     --iss-jwks-url intent — stripping them silently forces a goSignals SUT
//     to fall back to its default issuer alias and bootstrap-client_id
//     audience, which broke `create stream poll publish` (goSignals_test.go
//     Test4_PollStream).
//
//  2. stripTransmitterSupplied(reg, strict=true) additionally strips Aud/Iss/
//     IssuerJWKSUrl from TRANSMITTER-side (publisher-leg) bodies. SSF §8.1.1.1
//     reserves iss/aud as transmitter-owned; the OpenID conformance suite (and
//     other strict-spec transmitters) reject publisher-leg POSTs that contain
//     them with HTTP 400. Strict mode is opt-in per server via `add server
//     --strict-ssf`. Receiver-side bodies are NEVER additionally stripped:
//     they target the operator's local SUT, which owns its own SSF wire
//     cleanup on outbound calls.
//
//  3. StreamConfiguration.Id (json:"stream_id") marshals with omitempty so a
//     fresh CREATE body does NOT carry a "stream_id" key. SSF 1.0 §7.1.1 lists
//     stream_id as Read-Only / transmitter-assigned; strict transmitters reject
//     create bodies that contain it (commit b1932b5).
//
// All three behaviors are validated end-to-end by the OpenID conformance
// receiver plans (rx-poll, rx-poll-caep, rx-push, rx-push-caep) and the
// goSignals tool integration suite. These unit tests catch regressions at the
// fast gate so a CI failure pinpoints the broken invariant before the
// conformance run.
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestStreamRegister_PreservesTransmitterAud asserts that
// stripTransmitterSupplied keeps Aud, Iss, and IssuerJWKSUrl on a
// receiver-side (Delivery.method == Receive*) StreamConfiguration regardless
// of the strict-SSF flag. These three fields describe the FOREIGN transmitter
// the local SUT will receive from:
//   - Aud is the audience claim the SUT must validate inbound SETs against
//     (RFC8417 §2.2).
//   - Iss + IssuerJWKSUrl let the SUT discover the transmitter's SSF endpoints
//     (verification, status) for stream management.
//
// Reverting the receiver-side preserve branch (commit 7fc5946) makes this
// test fail.
func TestStreamRegister_PreservesTransmitterAud(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		deliver func() *model.OneOfStreamConfigurationDelivery
	}{
		{
			name:   "receive-push",
			method: model.ReceivePush,
			deliver: func() *model.OneOfStreamConfigurationDelivery {
				return &model.OneOfStreamConfigurationDelivery{
					PushReceiveMethod: &model.PushReceiveMethod{
						Method:      model.ReceivePush,
						EndpointUrl: "https://sut.example.com/events",
					},
				}
			},
		},
		{
			name:   "receive-poll",
			method: model.ReceivePoll,
			deliver: func() *model.OneOfStreamConfigurationDelivery {
				return &model.OneOfStreamConfigurationDelivery{
					PollReceiveMethod: &model.PollReceiveMethod{
						Method:      model.ReceivePoll,
						EndpointUrl: "https://transmitter.example.com/poll",
					},
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			reg := model.StreamConfiguration{
				Iss:             "https://issuer.example.com",
				Aud:             []string{"https://other.example.com"},
				IssuerJWKSUrl:   "https://issuer.example.com/jwks.json",
				EventsRequested: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
				Delivery:        tc.deliver(),
			}

			// Receiver-side preservation must hold under BOTH strict modes —
			// strict only governs the transmitter-side §8.1.1.1 wire strip.
			for _, strict := range []bool{false, true} {
				strict := strict
				t.Run(fmtStrict(strict), func(t *testing.T) {
					wire := stripTransmitterSupplied(reg, strict)
					require.NotNil(t, wire.Delivery, "delivery preserved")
					assert.Equal(t, tc.method, wire.Delivery.GetMethod(), "delivery method preserved")
					assert.Equal(t, "https://issuer.example.com", wire.Iss, "Iss preserved for receiver-side registration")
					assert.Equal(t, []string{"https://other.example.com"}, wire.Aud, "Aud preserved for receiver-side registration")
					assert.Equal(t, "https://issuer.example.com/jwks.json", wire.IssuerJWKSUrl, "IssuerJWKSUrl preserved for receiver-side registration")
				})
			}
		})
	}

	// Transmitter-side registrations to a NON-STRICT (goSignals-cluster) target
	// preserve Iss/Aud/IssuerJWKSUrl: those are the operator's --iss / --aud /
	// --iss-jwks-url intent for the goSignals SUT-as-transmitter. Stripping
	// forces the SUT to fall back to its default issuer alias and to default
	// Aud to the bootstrap token's client_id, which silently breaks
	// `create stream poll publish` (goSignals_test.go Test4_PollStream).
	t.Run("transmitter-side-non-strict-preserves", func(t *testing.T) {
		reg := model.StreamConfiguration{
			Iss:           "https://issuer.example.com",
			Aud:           []string{"https://other.example.com"},
			IssuerJWKSUrl: "https://issuer.example.com/jwks.json",
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:      model.DeliveryPush,
					EndpointUrl: "https://receiver.example.com/events",
				},
			},
		}

		wire := stripTransmitterSupplied(reg, false)

		assert.Equal(t, "https://issuer.example.com", wire.Iss, "Iss preserved for transmitter-side non-strict registration (operator intent)")
		assert.Equal(t, []string{"https://other.example.com"}, wire.Aud, "Aud preserved for transmitter-side non-strict registration (operator intent)")
		assert.Equal(t, "https://issuer.example.com/jwks.json", wire.IssuerJWKSUrl, "IssuerJWKSUrl preserved for transmitter-side non-strict registration (operator intent)")
	})

	// Transmitter-side registrations to a STRICT-SSF target strip
	// Iss/Aud/IssuerJWKSUrl: SSF §8.1.1.1 reserves these for the transmitter,
	// and strict transmitters (the OpenID conformance suite, etc.) return
	// HTTP 400 if the receiver supplies them on a publisher-leg POST. This is
	// the integration-level lock-down for the receiver-plan conformance fix
	// (`add server --strict-ssf`); reverting it makes every receiver plan
	// module FAIL/INTERRUPTED.
	t.Run("transmitter-side-strict-strips", func(t *testing.T) {
		for _, m := range []struct {
			name    string
			deliver func() *model.OneOfStreamConfigurationDelivery
		}{
			{
				name: "push-transmit",
				deliver: func() *model.OneOfStreamConfigurationDelivery {
					return &model.OneOfStreamConfigurationDelivery{
						PushTransmitMethod: &model.PushTransmitMethod{
							Method:      model.DeliveryPush,
							EndpointUrl: "https://receiver.example.com/events",
						},
					}
				},
			},
			{
				name: "poll-transmit",
				deliver: func() *model.OneOfStreamConfigurationDelivery {
					return &model.OneOfStreamConfigurationDelivery{
						PollTransmitMethod: &model.PollTransmitMethod{
							Method: model.DeliveryPoll,
						},
					}
				},
			},
		} {
			m := m
			t.Run(m.name, func(t *testing.T) {
				reg := model.StreamConfiguration{
					Iss:           "https://issuer.example.com",
					Aud:           []string{"https://other.example.com"},
					IssuerJWKSUrl: "https://issuer.example.com/jwks.json",
					Delivery:      m.deliver(),
				}

				wire := stripTransmitterSupplied(reg, true)

				assert.Equal(t, "", wire.Iss, "Iss stripped for strict transmitter-side registration (SSF §8.1.1.1)")
				assert.Nil(t, wire.Aud, "Aud stripped for strict transmitter-side registration (SSF §8.1.1.1)")
				assert.Equal(t, "", wire.IssuerJWKSUrl, "IssuerJWKSUrl stripped for strict transmitter-side registration (SSF §8.1.1.1)")
			})
		}
	})
}

func fmtStrict(strict bool) string {
	if strict {
		return "strict"
	}
	return "non-strict"
}

// TestStreamRegister_OmitsEmptyStreamId asserts that a fresh receiver
// stream-registration body marshals without a "stream_id" key when the
// receiver has not (and cannot) supply one. SSF 1.0 §7.1.1 marks stream_id
// Read-Only / transmitter-assigned; strict transmitters reject create bodies
// that contain it. Removing the omitempty tag on Id (commit b1932b5) makes
// this test fail because json.Marshal then emits "stream_id":"".
func TestStreamRegister_OmitsEmptyStreamId(t *testing.T) {
	// A minimally-populated receiver registration — what the CLI builds before
	// calling executeCreateRequest -> stripTransmitterSupplied. Id is left at
	// its zero value because the local SUT assigns it on the response.
	reg := model.StreamConfiguration{
		EventsRequested: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: "https://transmitter.example.com/poll",
			},
		},
	}

	body, err := json.Marshal(&reg)
	require.NoError(t, err)

	assert.NotContains(t, string(body), `"stream_id"`, "stream_id must be omitted from a CREATE body when unset")

	// Also assert through the path the CLI takes on the wire — stripTransmitter-
	// Supplied + MarshalIndent. Belt-and-braces: catches a future change that
	// re-introduces an explicit Id assignment in that helper.
	wire := stripTransmitterSupplied(reg, false)
	wireBody, err := json.MarshalIndent(&wire, "", " ")
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(wireBody), `"stream_id"`), "stream_id must be omitted from the on-the-wire CREATE body")
}
