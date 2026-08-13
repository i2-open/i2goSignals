package goSet

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// bsonKeys returns the top-level field names of a marshalled BSON document,
// in document order.
func bsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	elems, err := bson.Raw(raw).Elements()
	require.NoError(t, err)
	keys := make([]string, 0, len(elems))
	for _, e := range elems {
		keys = append(keys, e.Key())
	}
	return keys
}

// TestSubjectIdentifierBSON_OpaqueStoresOnlyWireMembers pins the defect in
// issue #259: a compact opaque sub_id must persist as exactly the two members
// that appeared on the wire, not as every identifier variant the Go struct
// happens to embed.
//
// Expected shape is the SET the transmitter actually sent:
//
//	{"format":"opaque","id":"codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd"}
func TestSubjectIdentifierBSON_OpaqueStoresOnlyWireMembers(t *testing.T) {
	sid := &SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: OpaqueIdentifier{Id: "codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd"},
	}

	raw, err := bson.Marshal(sid)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"format", "id"}, bsonKeys(t, raw),
		"only the members present on the wire may be persisted")
	assert.Equal(t, "opaque", bson.Raw(raw).Lookup("format").StringValue())
	assert.Equal(t, "codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd",
		bson.Raw(raw).Lookup("id").StringValue())
}

// TestSubjectIdentifierBSON_OpaqueRoundTrip: the compact document must decode
// back to the subject that was stored. Delivery-time subject filtering reads
// SubjectId out of Mongo, so a lossy decode would silently mis-match.
func TestSubjectIdentifierBSON_OpaqueRoundTrip(t *testing.T) {
	sid := &SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: OpaqueIdentifier{Id: "codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd"},
	}

	raw, err := bson.Marshal(sid)
	require.NoError(t, err)

	var got SubjectIdentifier
	require.NoError(t, bson.Unmarshal(raw, &got))
	assert.Equal(t, *sid, got)
}

// TestSubjectIdentifierBSON_SimpleFormats covers the remaining RFC 9493 simple
// formats. Each must store exactly its own wire members and survive a
// round-trip. Expected key sets come from the format definitions, not from the
// Go struct layout.
func TestSubjectIdentifierBSON_SimpleFormats(t *testing.T) {
	cases := []struct {
		name     string
		sid      SubjectIdentifier
		wantKeys []string
	}{
		{
			name:     "email",
			sid:      SubjectIdentifier{Format: "email", EmailIdentifier: EmailIdentifier{Email: "user@example.com"}},
			wantKeys: []string{"format", "email"},
		},
		{
			name: "iss_sub",
			sid: SubjectIdentifier{Format: "iss_sub", IssuerSubjectIdentifier: IssuerSubjectIdentifier{
				Issuer: "https://issuer.example", Sub: "user-42",
			}},
			wantKeys: []string{"format", "iss", "sub"},
		},
		{
			name:     "phone_number",
			sid:      SubjectIdentifier{Format: "phone_number", PhoneNumberIdentifier: PhoneNumberIdentifier{PhoneNumber: "+15551234567"}},
			wantKeys: []string{"format", "phone_number"},
		},
		{
			name:     "did",
			sid:      SubjectIdentifier{Format: "did", DecentralizedIdentifier: DecentralizedIdentifier{Url: "did:example:123"}},
			wantKeys: []string{"format", "url"},
		},
		{
			name:     "uri",
			sid:      SubjectIdentifier{Format: "uri", UniformResourceIdentifier: UniformResourceIdentifier{Uri: "https://example.com/users/42"}},
			wantKeys: []string{"format", "uri"},
		},
		{
			name:     "external",
			sid:      SubjectIdentifier{Format: "external", ExternalIdentifier: ExternalIdentifier{ExternalId: "ext-99"}},
			wantKeys: []string{"format", "externalId"},
		},
		{
			name:     "username",
			sid:      SubjectIdentifier{Format: "username", UsernameIdentifier: UsernameIdentifier{Username: "jdoe"}},
			wantKeys: []string{"format", "username"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := bson.Marshal(tc.sid)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.wantKeys, bsonKeys(t, raw))

			var got SubjectIdentifier
			require.NoError(t, bson.Unmarshal(raw, &got))
			assert.Equal(t, tc.sid, got)
		})
	}
}

// TestSubjectIdentifierBSON_Aliases: the RFC 9493 §3.2.8 aliases format stores
// its member identifiers compactly and nested, and round-trips.
func TestSubjectIdentifierBSON_Aliases(t *testing.T) {
	sid := SubjectIdentifier{
		Format: "aliases",
		AliasesIdentifier: AliasesIdentifier{Identifiers: []SubjectIdentifier{
			{Format: "email", EmailIdentifier: EmailIdentifier{Email: "user@example.com"}},
			{Format: "opaque", OpaqueIdentifier: OpaqueIdentifier{Id: "opq-1"}},
		}},
	}

	raw, err := bson.Marshal(sid)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"format", "identifiers"}, bsonKeys(t, raw))

	members, err := bson.Raw(raw).Lookup("identifiers").Array().Values()
	require.NoError(t, err)
	require.Len(t, members, 2)
	first, err := members[0].Document().Elements()
	require.NoError(t, err)
	firstKeys := make([]string, 0, len(first))
	for _, e := range first {
		firstKeys = append(firstKeys, e.Key())
	}
	assert.ElementsMatch(t, []string{"format", "email"}, firstKeys,
		"nested alias members must be compact too")

	var got SubjectIdentifier
	require.NoError(t, bson.Unmarshal(raw, &got))
	assert.Equal(t, sid, got)
}

// TestSubjectIdentifierBSON_Complex: the SSF §8.1.3 complex subject stores only
// the members that are present — an absent member is a wildcard during §8.1.3.1
// matching, so persisting it as null would change matching semantics.
func TestSubjectIdentifierBSON_Complex(t *testing.T) {
	sid := SubjectIdentifier{
		Format: "complex",
		ComplexIdentifier: ComplexIdentifier{
			User:   &SubjectIdentifier{Format: "email", EmailIdentifier: EmailIdentifier{Email: "user@example.com"}},
			Tenant: &SubjectIdentifier{Format: "opaque", OpaqueIdentifier: OpaqueIdentifier{Id: "tenant-7"}},
		},
	}

	raw, err := bson.Marshal(sid)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"format", "user", "tenant"}, bsonKeys(t, raw),
		"absent complex members are wildcards and must not be stored")

	userKeys, err := bson.Raw(raw).Lookup("user").Document().Elements()
	require.NoError(t, err)
	keys := make([]string, 0, len(userKeys))
	for _, e := range userKeys {
		keys = append(keys, e.Key())
	}
	assert.ElementsMatch(t, []string{"format", "email"}, keys)

	var got SubjectIdentifier
	require.NoError(t, bson.Unmarshal(raw, &got))
	assert.Equal(t, sid, got)
}

// TestSecurityEventTokenBSON_WireNamedClaims: a persisted SET carries the RFC
// 8417 §2.2 claims at the top level under their wire names — not buried in a
// `registeredclaims` subdocument under Go field names — and omits every claim
// the token does not actually carry.
func TestSecurityEventTokenBSON_WireNamedClaims(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "jti-1",
			Issuer:   "https://issuer.example",
			Audience: jwt.ClaimStrings{"https://receiver.example"},
			IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0)),
		},
		SubjectId: &SubjectIdentifier{
			Format:           "opaque",
			OpaqueIdentifier: OpaqueIdentifier{Id: "codex:exec-1"},
		},
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]any{},
		},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	assert.ElementsMatch(t,
		[]string{"jti", "iss", "aud", "iat", "sub_id", "events"},
		bsonKeys(t, raw),
		"only the claims present on the wire, under RFC 8417 names")

	assert.Equal(t, "jti-1", bson.Raw(raw).Lookup("jti").StringValue())
	assert.Equal(t, "https://issuer.example", bson.Raw(raw).Lookup("iss").StringValue())
	assert.Equal(t, int64(1700000000), bson.Raw(raw).Lookup("iat").AsInt64())
}

// TestSecurityEventTokenBSON_RoundTrip: a stored SET decodes back to the token
// that was persisted. ResetDate/ResetJti replay and delivery-time subject
// filtering both read the parsed Event back out of Mongo.
func TestSecurityEventTokenBSON_RoundTrip(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-2",
			Issuer:    "https://issuer.example",
			Audience:  jwt.ClaimStrings{"https://receiver.example", "https://other.example"},
			IssuedAt:  jwt.NewNumericDate(time.Unix(1700000000, 0)),
			ExpiresAt: jwt.NewNumericDate(time.Unix(1700003600, 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(1699999000, 0)),
			Subject:   "top-level-subject",
		},
		TimeOfEvent:   jwt.NewNumericDate(time.Unix(1699999999, 0)),
		TransactionId: "txn-9",
		Kid:           "key-1",
		SubjectId: &SubjectIdentifier{
			Format:                  "iss_sub",
			IssuerSubjectIdentifier: IssuerSubjectIdentifier{Issuer: "https://issuer.example", Sub: "user-42"},
		},
		Events: map[string]interface{}{
			"urn:ietf:params:event:SCIM:create": map[string]any{"attributes": []any{"id", "userName"}},
		},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))

	assert.Equal(t, set.ID, got.ID)
	assert.Equal(t, set.Issuer, got.Issuer)
	assert.Equal(t, set.Subject, got.Subject)
	assert.Equal(t, set.Audience, got.Audience)
	assert.Equal(t, set.TransactionId, got.TransactionId)
	assert.Equal(t, set.Kid, got.Kid)
	require.NotNil(t, got.SubjectId)
	assert.Equal(t, *set.SubjectId, *got.SubjectId)
	require.NotNil(t, got.IssuedAt)
	assert.True(t, set.IssuedAt.Equal(got.IssuedAt.Time))
	require.NotNil(t, got.ExpiresAt)
	assert.True(t, set.ExpiresAt.Equal(got.ExpiresAt.Time))
	require.NotNil(t, got.NotBefore)
	assert.True(t, set.NotBefore.Equal(got.NotBefore.Time))
	require.NotNil(t, got.TimeOfEvent)
	assert.True(t, set.TimeOfEvent.Equal(got.TimeOfEvent.Time))
	assert.Equal(t, set.GetEventIds(), got.GetEventIds())
}

// legacySubjectDoc is the Go-shaped subject document that this codebase wrote
// before issue #259 — every embedded identifier variant, under Go field names,
// with empty values. Transcribed from the BSON recorded on the issue, not
// generated by the code under test.
func legacySubjectDoc(opaqueId string) bson.D {
	return bson.D{
		{Key: "format", Value: "opaque"},
		{Key: "usernameidentifier", Value: bson.D{{Key: "username", Value: ""}}},
		{Key: "emailidentifier", Value: bson.D{{Key: "email", Value: ""}}},
		{Key: "issuersubjectidentifier", Value: bson.D{{Key: "issuer", Value: ""}, {Key: "sub", Value: ""}}},
		{Key: "opaqueidentifier", Value: bson.D{{Key: "id", Value: opaqueId}}},
		{Key: "phonenumberidentifier", Value: bson.D{{Key: "phonenumber", Value: ""}}},
		{Key: "decentralizedidentifier", Value: bson.D{{Key: "url", Value: ""}}},
		{Key: "uniformresourceidentifier", Value: bson.D{{Key: "uri", Value: ""}}},
		{Key: "externalidentifier", Value: bson.D{{Key: "externalid", Value: ""}}},
		{Key: "aliasesidentifier", Value: bson.D{{Key: "identifiers", Value: nil}}},
		{Key: "complexidentifier", Value: bson.D{
			{Key: "user", Value: nil}, {Key: "group", Value: nil}, {Key: "device", Value: nil},
			{Key: "session", Value: nil}, {Key: "tenant", Value: nil}, {Key: "orgunit", Value: nil},
		}},
	}
}

// TestSubjectIdentifierBSON_ReadsLegacyDocument: documents written before the
// fix must still decode to the subject they encode. Unknown BSON fields are
// ignored rather than rejected, so without explicit legacy handling an old row
// would decode to an EMPTY subject and silently mis-match a subject filter
// instead of failing loudly.
func TestSubjectIdentifierBSON_ReadsLegacyDocument(t *testing.T) {
	raw, err := bson.Marshal(legacySubjectDoc("codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd"))
	require.NoError(t, err)

	var got SubjectIdentifier
	require.NoError(t, bson.Unmarshal(raw, &got))

	assert.Equal(t, "opaque", got.Format)
	assert.Equal(t, "codex:exec-b3bfa4ad-2981-44d3-a794-6054ad4b20dd", got.Id,
		"a pre-fix document must not decode to an empty subject")
}

// TestSecurityEventTokenBSON_ReadsLegacyDocument: same for the whole SET —
// registered claims buried in a `registeredclaims` subdocument under Go names,
// with a nested legacy subject.
func TestSecurityEventTokenBSON_ReadsLegacyDocument(t *testing.T) {
	legacy := bson.D{
		{Key: "registeredclaims", Value: bson.D{
			{Key: "issuer", Value: "https://issuer.example"},
			{Key: "subject", Value: ""},
			{Key: "audience", Value: bson.A{"https://receiver.example"}},
			{Key: "expiresat", Value: nil},
			{Key: "notbefore", Value: nil},
			{Key: "issuedat", Value: bson.D{{Key: "time", Value: time.Unix(1700000000, 0)}}},
			{Key: "id", Value: "legacy-jti"},
		}},
		{Key: "timeofevent", Value: nil},
		{Key: "transactionid", Value: ""},
		{Key: "subjectid", Value: legacySubjectDoc("codex:exec-legacy")},
		{Key: "events", Value: bson.D{{Key: "urn:example:event", Value: bson.D{}}}},
		{Key: "kid", Value: ""},
	}
	raw, err := bson.Marshal(legacy)
	require.NoError(t, err)

	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))

	assert.Equal(t, "legacy-jti", got.ID)
	assert.Equal(t, "https://issuer.example", got.Issuer)
	assert.Equal(t, jwt.ClaimStrings{"https://receiver.example"}, got.Audience)
	require.NotNil(t, got.IssuedAt)
	assert.Equal(t, int64(1700000000), got.IssuedAt.Unix())
	require.NotNil(t, got.SubjectId)
	assert.Equal(t, "codex:exec-legacy", got.SubjectId.Id,
		"nested legacy subject must decode too")
	assert.Equal(t, []string{"urn:example:event"}, got.GetEventIds())
}
