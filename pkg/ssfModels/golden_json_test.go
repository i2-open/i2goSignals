package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Golden-JSON conformance tests (issue #273).
//
// These files pin the EXACT bytes json.Marshal produces for the SSF/RFC 8936
// structs that reach the wire. They exist so a struct-tag change, a Go release,
// or a future encoding/json v2 migration cannot silently reshape a protocol
// message: a byte you did not mean to change shows up here as a failing test
// rather than as an interop bug at a receiver.
//
// Each type gets three fixtures — zero-value, fully populated, and a realistic
// mixed case whose bool/numeric fields sit at their zero values, which is the
// case an `omitempty` -> `omitzero` retag would move if the two ever disagreed.
//
// Regenerate with `UPDATE_GOLDEN=1 go test ./pkg/ssfModels/...` and then READ
// the diff. An unexplained diff is a wire-format change, not a test to bless.

// goldenTime and goldenTime2 are fixed instants so no pinned byte depends on
// the clock.
var (
	goldenTime  = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	goldenTime2 = time.Date(2026, 3, 4, 6, 7, 8, 0, time.UTC)
)

// goldenOID is a fixed ObjectID, for the same reason.
var goldenOID = mustGoldenOID("64b7f0c2a1b2c3d4e5f60718")

func mustGoldenOID(hex string) bson.ObjectID {
	oid, err := bson.ObjectIDFromHex(hex)
	if err != nil {
		panic(err)
	}
	return oid
}

func goldenPtr[T any](v T) *T { return &v }

// assertGolden compares got against the recorded wire bytes for name.
//
// The file on disk holds the marshalled bytes plus one trailing newline, so the
// goldens stay ordinary newline-terminated text while the comparison remains
// byte-for-byte against what actually goes on the wire.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden.json")

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, append(bytes.Clone(got), '\n'), 0o644); err != nil {
			t.Fatalf("writing golden %s: %v", path, err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (regenerate with UPDATE_GOLDEN=1): %v", path, err)
	}
	want := bytes.TrimSuffix(raw, []byte("\n"))
	if !bytes.Equal(want, got) {
		t.Errorf("wire bytes changed for %s\n want: %s\n  got: %s", name, want, got)
	}
}

type goldenCase struct {
	name  string
	value any
}

func goldenCases() []goldenCase {
	pollDelivery := &OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &PollTransmitMethod{
			Method:              "urn:ietf:rfc:8936",
			EndpointUrl:         "https://tx.example.com/poll",
			AuthorizationHeader: "Bearer golden",
			PollConfig: &PollParameters{
				MaxEvents:         25,
				ReturnImmediately: true,
				TimeoutSecs:       30,
			},
		},
	}

	scPopulated := StreamConfiguration{
		Id:                      "stream-golden-1",
		Iss:                     "https://tx.example.com",
		Aud:                     []string{"https://rx.example.com"},
		EventsSupported:         []string{"urn:example:event:a", "urn:example:event:b"},
		Description:             "golden stream",
		EventsRequested:         []string{"urn:example:event:a"},
		EventsDelivered:         []string{"urn:example:event:a"},
		Delivery:                pollDelivery,
		MinVerificationInterval: 60,
		InactivityTimeout:       3600,
		Format:                  "iss_sub",
		ReceiverJWKSUrl:         "https://rx.example.com/jwks.json",
		IssuerJWKSUrl:           "https://tx.example.com/jwks.json",
		ResetDate:               goldenPtr(goldenTime),
		ResetJti:                "jti-reset",
		RouteMode:               "IMPORT",
		SigningOnly:             true,
		TxWellKnownUrl:          goldenPtr("https://tx.example.com/.well-known/ssf-configuration"),
		TxToken:                 goldenPtr("tx-token"),
		TxAlias:                 goldenPtr("tx-alias"),
		RemoteStreamId:          goldenPtr("remote-stream-1"),
		TxTLSCertificate:        "-----BEGIN CERTIFICATE-----golden-----END CERTIFICATE-----",
		TxTLSSkipVerify:         true,
	}

	// Every bool/numeric field deliberately left at its zero value: this is the
	// fixture that proves an omitempty -> omitzero retag is byte-identical.
	scMixed := StreamConfiguration{
		Id:              "stream-golden-2",
		Iss:             "https://tx.example.com",
		Aud:             []string{"https://rx.example.com"},
		EventsRequested: []string{"urn:example:event:a"},
		Delivery: &OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &PollTransmitMethod{Method: "urn:ietf:rfc:8936"},
		},
	}

	subject := &goSet.SubjectIdentifier{
		Format:          "email",
		EmailIdentifier: goSet.EmailIdentifier{Email: "golden@example.com"},
	}

	setPopulated := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-golden-1",
			Issuer:    "https://tx.example.com",
			Audience:  jwt.ClaimStrings{"https://rx.example.com"},
			IssuedAt:  jwt.NewNumericDate(goldenTime),
			ExpiresAt: jwt.NewNumericDate(goldenTime2),
		},
		TimeOfEvent:   jwt.NewNumericDate(goldenTime),
		TransactionId: "txn-golden",
		SubjectId:     subject,
		Events: map[string]interface{}{
			"urn:example:event:a": map[string]string{"detail": "golden"},
		},
		Kid: "kid-golden",
	}

	ssrPopulated := StreamStateRecord{
		Id:                  goldenOID,
		ProjectId:           "project-golden",
		StreamConfiguration: scPopulated,
		StartDate:           goldenTime,
		CreatedAt:           goldenTime,
		ModifiedAt:          goldenTime2,
		Status:              "enabled",
		ErrorMsg:            "",
		RemoteAddress: &RemoteIP{
			Protocol:  "https",
			IP:        "198.51.100.7",
			Forwarded: "203.0.113.9",
		},
		DefaultSubjects:            "ALL",
		SubjectFilterMode:          "local",
		EventSource:                &EventSource{Type: "explicit", SourceStreamIds: []string{"stream-golden-9"}},
		SubjectRemovalGraceSeconds: 3600,
		RetentionWindowDays:        goldenPtr(30),
		EventValidation:            EventValidationWarn,
		SstpInbound:                &scMixed,
		SstpMethod: &SstpMethod{
			Role:                "initiator",
			EndpointUrl:         "https://peer.example.com/sstp/abc",
			AuthorizationHeader: "Bearer pair",
			PeerPairId:          "peer-pair-1",
			PeerServerAlias:     "peer",
		},
		PairId:               "pair-golden-1",
		InboundStatus:        "enabled",
		InboundErrorMsg:      "",
		JwksReadiness:        &JwksReadiness{State: JwksReadinessReady},
		InboundJwksReadiness: &JwksReadiness{State: JwksReadinessUnresolved, LastError: "dial tcp", NextRetryAt: goldenPtr(goldenTime2)},
	}

	ssrMixed := StreamStateRecord{
		Id:                  goldenOID,
		ProjectId:           "project-golden",
		StreamConfiguration: scMixed,
		StartDate:           goldenTime,
		CreatedAt:           goldenTime,
		ModifiedAt:          goldenTime,
		Status:              "enabled",
	}

	serverPopulated := Server{
		Id:           goldenOID,
		Alias:        "peer",
		Type:         ServerTypeGosignals,
		Host:         "https://peer.example.com",
		ClientToken:  goldenPtr("client-token"),
		RefreshToken: goldenPtr("refresh-token"),
		TokenExpires: goldenPtr(goldenTime2),
		IatToken:     goldenPtr("iat-token"),
		OAuthClientConfig: &OAuthClientConfig{
			TokenURL:     "https://as.example.com/token",
			ClientID:     "client-golden",
			ClientSecret: "secret-golden",
			Audience:     "https://peer.example.com",
			Resource:     "https://peer.example.com/events",
			Scopes:       []string{"stream", "event"},
		},
		SpiffeConfig: &SpiffeConfig{
			TrustDomain: "peer.example.com",
			SpiffeID:    "spiffe://peer.example.com/workload/ssf-server",
		},
		ProjectId: "project-golden",
		ServerConfiguration: &TransmitterConfiguration{
			Issuer:                   "https://peer.example.com",
			JwksUri:                  "https://peer.example.com/jwks.json",
			DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935", "urn:ietf:rfc:8936"},
			ConfigurationEndpoint:    "https://peer.example.com/stream",
		},
		OfflineMode:    true,
		OfflineError:   "connection refused",
		TLSCertificate: "-----BEGIN CERTIFICATE-----peer-----END CERTIFICATE-----",
		TLSSkipVerify:  true,
		StrictSsf:      true,
	}

	serverMixed := Server{
		Id:        goldenOID,
		Alias:     "peer",
		Type:      ServerTypeSsf,
		Host:      "https://peer.example.com",
		ProjectId: "project-golden",
	}

	return []goldenCase{
		{"stream_configuration_zero", StreamConfiguration{}},
		{"stream_configuration_populated", scPopulated},
		{"stream_configuration_mixed", scMixed},

		{"poll_parameters_zero", PollParameters{}},
		{"poll_parameters_populated", PollParameters{
			MaxEvents:         25,
			ReturnImmediately: true,
			Acks:              []string{"jti-1", "jti-2"},
			SetErrs: map[string]SetErrorType{
				"jti-3": {Error: "invalid_key", Description: "unknown kid"},
			},
			TimeoutSecs: 30,
		}},
		{"poll_parameters_mixed", PollParameters{Acks: []string{"jti-1"}}},

		{"poll_response_zero", PollResponse{}},
		{"poll_response_populated", PollResponse{
			Sets:          map[string]string{"jti-1": "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
			MoreAvailable: true,
		}},
		{"poll_response_mixed", PollResponse{Sets: map[string]string{}}},

		// INTENTIONAL WIRE CHANGE (#273): EnforceAt is a non-pointer
		// time.Time, so its old `omitempty` was a no-op — encoding/json
		// never treats a struct as empty — and every entry without a
		// removal grace shipped a meaningless
		// "enforce_at":"0001-01-01T00:00:00Z". Under `omitzero` the zero
		// instant is omitted, which is what the tag always claimed. The
		// zero and mixed goldens below record that: absent enforce_at now
		// means "no grace deadline", the same thing the epoch-zero stamp
		// meant, and readers already decode a missing member to the zero
		// time.
		{"subject_filter_entry_zero", SubjectFilterEntry{}},
		{"subject_filter_entry_populated", SubjectFilterEntry{
			StreamId:     "stream-golden-1",
			CanonicalKey: "email:golden@example.com",
			Kind:         SubjectKindSimple,
			Subject:      subject,
			Verified:     true,
			EnforceAt:    goldenTime,
		}},
		{"subject_filter_entry_mixed", SubjectFilterEntry{
			StreamId:     "stream-golden-1",
			CanonicalKey: "email:golden@example.com",
			Kind:         SubjectKindSimple,
			Subject:      subject,
		}},

		{"add_subject_parameters_zero", AddSubjectParameters{}},
		{"add_subject_parameters_populated", AddSubjectParameters{
			Subject:  &AllOfAddSubjectParametersSubject{},
			Verified: true,
		}},
		{"add_subject_parameters_mixed", AddSubjectParameters{
			Subject: &AllOfAddSubjectParametersSubject{},
		}},

		{"event_record_zero", EventRecord{}},
		{"event_record_populated", EventRecord{
			Jti:         "jti-golden-1",
			Event:       setPopulated,
			Original:    "eyJhbGciOiJSUzI1NiJ9.e30.sig",
			Sid:         "stream-golden-1",
			Types:       []string{"urn:example:event:a"},
			Operational: true,
			SortTime:    goldenTime,
		}},
		{"event_record_mixed", EventRecord{
			Jti:      "jti-golden-2",
			Event:    setPopulated,
			Sid:      "stream-golden-1",
			Types:    []string{"urn:example:event:a"},
			SortTime: goldenTime,
		}},

		{"token_record_zero", TokenRecord{}},
		{"token_record_populated", TokenRecord{
			JTI:              "jti-golden-1",
			ClientID:         "client-golden",
			Subject:          "sub-golden",
			ProjectID:        "project-golden",
			Type:             TokenTypeStream,
			Scopes:           []string{"stream", "event"},
			IssuedAt:         goldenTime,
			ExpiresAt:        goldenTime2,
			RevokedAt:        goldenTime2,
			Parent:           "jti-parent",
			StreamID:         "stream-golden-1",
			LastRedemptionIP: "198.51.100.7",
			LastRedemptionAt: goldenTime,
			RedemptionCount:  3,
		}},
		{"token_record_mixed", TokenRecord{
			JTI:       "jti-golden-2",
			ProjectID: "project-golden",
			Type:      TokenTypeIAT,
			Scopes:    []string{"register"},
			IssuedAt:  goldenTime,
			ExpiresAt: goldenTime2,
		}},

		{"stream_state_record_zero", StreamStateRecord{}},
		{"stream_state_record_populated", ssrPopulated},
		{"stream_state_record_mixed", ssrMixed},

		{"server_zero", Server{}},
		{"server_populated", serverPopulated},
		{"server_mixed", serverMixed},
	}
}

// TestGoldenJSON pins the wire bytes of every SSF struct that reaches a peer.
func TestGoldenJSON(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			assertGolden(t, tc.name, got)
		})
	}
}
