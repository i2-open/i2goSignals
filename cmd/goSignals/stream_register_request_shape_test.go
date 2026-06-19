// Regression tests for the receiver-side stream-registration request shape that
// the goSignals CLI sends to a remote transmitter. Two conformance-driven fixes
// are locked in here so Go unit tests catch regressions without re-running the
// 20-min SSF conformance suite:
//
//  1. stripTransmitterSupplied preserves transmitter-supplied Aud/Iss/
//     IssuerJWKSUrl on receiver-side registrations. Clearing Aud caused the
//     local SUT to default it to the bootstrap token's client_id, which broke
//     RFC8417 §2.2 audience validation on every inbound SET (commit 7fc5946).
//
//  2. StreamConfiguration.Id (json:"stream_id") marshals with omitempty so a
//     fresh CREATE body does NOT carry a "stream_id" key. SSF 1.0 §7.1.1 lists
//     stream_id as Read-Only / transmitter-assigned; strict transmitters reject
//     create bodies that contain it (commit b1932b5).
//
// Both behaviors are validated end-to-end by the OpenID conformance receiver
// plans (rx-poll, rx-poll-caep, rx-push, rx-push-caep). These tests catch
// regressions on the unit-test gate so a CI failure pinpoints the broken
// invariant before the conformance run.
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
// receiver-side (Delivery.method == Receive*) StreamConfiguration. These three
// fields describe the FOREIGN transmitter the local SUT will receive from:
//   - Aud is the audience claim the SUT must validate inbound SETs against
//     (RFC8417 §2.2).
//   - Iss + IssuerJWKSUrl let the SUT discover the transmitter's SSF endpoints
//     (verification, status) for stream management.
//
// Reverting the receiver-side branch in stripTransmitterSupplied (commit
// 7fc5946) makes this test fail.
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

            wire := stripTransmitterSupplied(reg)

            require.NotNil(t, wire.Delivery, "delivery preserved")
            assert.Equal(t, tc.method, wire.Delivery.GetMethod(), "delivery method preserved")
            assert.Equal(t, "https://issuer.example.com", wire.Iss, "Iss preserved for receiver-side registration")
            assert.Equal(t, []string{"https://other.example.com"}, wire.Aud, "Aud preserved for receiver-side registration")
            assert.Equal(t, "https://issuer.example.com/jwks.json", wire.IssuerJWKSUrl, "IssuerJWKSUrl preserved for receiver-side registration")
        })
    }

    // Sanity contrast: transmitter-side registrations MUST strip Aud/Iss/
    // IssuerJWKSUrl. If a future refactor flips the branch condition, this
    // sub-test will catch it.
    t.Run("transmitter-side-still-strips", func(t *testing.T) {
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

        wire := stripTransmitterSupplied(reg)

        assert.Equal(t, "", wire.Iss, "Iss stripped for transmitter-side registration")
        assert.Nil(t, wire.Aud, "Aud stripped for transmitter-side registration")
        assert.Equal(t, "", wire.IssuerJWKSUrl, "IssuerJWKSUrl stripped for transmitter-side registration")
    })
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
    wire := stripTransmitterSupplied(reg)
    wireBody, err := json.MarshalIndent(&wire, "", " ")
    require.NoError(t, err)
    assert.False(t, strings.Contains(string(wireBody), `"stream_id"`), "stream_id must be omitted from the on-the-wire CREATE body")
}
