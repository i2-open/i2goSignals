package goSet

import (
	"encoding/json"
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

// TestEventSubjectBSON_KeepsTopLevelSub: EventSubject embeds SubjectIdentifier
// by value, so it would inherit that type's promoted MarshalBSON — which sees
// only the SubjectIdentifier half and silently drops the top-level `sub` the
// type exists to carry. Issue #259 flagged the collision and scoped the type
// out; this pins that the wire-shape codec did not reintroduce it as data loss.
func TestEventSubjectBSON_KeepsTopLevelSub(t *testing.T) {
	es := EventSubject{
		SubIdentifier: SubIdentifier{Sub: "top-level-sub"},
		SubjectIdentifier: SubjectIdentifier{
			Format:           "opaque",
			OpaqueIdentifier: OpaqueIdentifier{Id: "codex:exec-1"},
		},
	}

	raw, err := bson.Marshal(es)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"sub", "format", "id"}, bsonKeys(t, raw),
		"both halves are stored, not just the SubjectIdentifier")
	assert.Equal(t, "top-level-sub", bson.Raw(raw).Lookup("sub").StringValue())

	var got EventSubject
	require.NoError(t, bson.Unmarshal(raw, &got))
	assert.Equal(t, es, got, "round trip preserves both halves")
}

// TestEventSubjectBSON_MatchesJSONShape: the stored shape is the wire shape,
// which for EventSubject means Go's embedded-field depth rules decide `sub` —
// SubIdentifier.Sub shadows the deeper IssuerSubjectIdentifier.Sub. BSON must
// mirror whatever JSON does rather than invent a resolution of its own.
func TestEventSubjectBSON_MatchesJSONShape(t *testing.T) {
	es := EventSubject{
		SubIdentifier: SubIdentifier{Sub: "top-level-sub"},
		SubjectIdentifier: SubjectIdentifier{
			Format:                  "iss_sub",
			IssuerSubjectIdentifier: IssuerSubjectIdentifier{Issuer: "https://issuer.example"},
		},
	}

	raw, err := bson.Marshal(es)
	require.NoError(t, err)
	j, err := json.Marshal(es)
	require.NoError(t, err)

	var fromJSON map[string]interface{}
	require.NoError(t, json.Unmarshal(j, &fromJSON))
	var fromBSON map[string]interface{}
	require.NoError(t, bson.Unmarshal(raw, &fromBSON))

	assert.Equal(t, fromJSON, fromBSON, "stored document matches the wire document")
}

// TestSecurityEventTokenBSON_OmitsNullMembers: a minimal SET stores no
// null-valued key. `events` is required by RFC 8417 and so cannot carry
// `json:",omitempty"` — its wire shape must not move — but a nil map has no
// business reaching the stored document.
func TestSecurityEventTokenBSON_OmitsNullMembers(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-null"},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	assert.Equal(t, []string{"jti"}, bsonKeys(t, raw),
		"a nil events map must not be stored as null")

	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))
	assert.Equal(t, "jti-null", got.ID)
	assert.Nil(t, got.Events, "an omitted events key reads back as nil, as it was")
}

// TestSecurityEventTokenBSON_KeepsNullsInsideEventPayloads: the null filter is
// top-level only. A null inside an arbitrary event payload is the payload's
// own data — dropping it would corrupt the SET on round-trip.
func TestSecurityEventTokenBSON_KeepsNullsInsideEventPayloads(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-payload-null"},
		Events: map[string]interface{}{
			"urn:example:event": map[string]any{"previous_value": nil},
		},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))

	payload, ok := got.Events["urn:example:event"].(map[string]interface{})
	require.True(t, ok, "event payload survives the round trip")
	value, present := payload["previous_value"]
	assert.True(t, present, "an explicit null in a payload is the payload's data")
	assert.Nil(t, value)
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

// bsonTypeAt returns the BSON type stored at a dotted path.
func bsonTypeAt(t *testing.T, raw []byte, path ...string) bson.Type {
	t.Helper()
	val, err := bson.Raw(raw).LookupErr(path...)
	require.NoError(t, err, "no member at %v", path)
	return val.Type
}

// TestSecurityEventTokenBSON_DateClaimsAreInt64 pins the stored integer type to
// the member rather than to the value. The ExtJSON parser picks the narrowest
// integer type a value fits in, so `iat` persisted as int32 while any
// NumericDate at or past 2038-01-19T03:14:07Z persisted as int64 — the same
// claim carrying two different BSON types depending on when the SET was issued.
func TestSecurityEventTokenBSON_DateClaimsAreInt64(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example",
			ID:        "urn:uuid:8a843c88",
			IssuedAt:  jwt.NewNumericDate(time.Unix(1786735851, 0)), // pre-2038, fits int32
			ExpiresAt: jwt.NewNumericDate(time.Unix(2200000000, 0)), // post-2038, does not
		},
		TimeOfEvent: jwt.NewNumericDate(time.Unix(1786735851, 0)),
		Events:      map[string]interface{}{"urn:example:event": map[string]interface{}{}},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	for _, claim := range []string{"iat", "exp", "toe"} {
		assert.Equal(t, bson.TypeInt64, bsonTypeAt(t, raw, claim),
			"%s must persist as int64 whichever side of 2038 it falls on", claim)
	}
}

// TestSecurityEventTokenBSON_PayloadIntegersAreInt64: the widening recurses into
// event payloads, including through arrays. Unlike the null filter — which is
// top-level only because dropping a null loses data — widening an integer is
// lossless and invisible to a reader, so there is no reason to stop at the
// top level and leave payload numbers typed by magnitude.
func TestSecurityEventTokenBSON_PayloadIntegersAreInt64(t *testing.T) {
	set := SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://issuer.example", ID: "j"},
		Events: map[string]interface{}{
			"urn:example:event": map[string]interface{}{
				"count":  42,
				"nested": map[string]interface{}{"deep": 7},
				"list":   []interface{}{1, 9999999999},
				"ratio":  1.5,
			},
		},
	}

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	assert.Equal(t, bson.TypeInt64, bsonTypeAt(t, raw, "events", "urn:example:event", "count"))
	assert.Equal(t, bson.TypeInt64, bsonTypeAt(t, raw, "events", "urn:example:event", "nested", "deep"))
	assert.Equal(t, bson.TypeInt64, bsonTypeAt(t, raw, "events", "urn:example:event", "list", "0"),
		"array elements are widened too")
	assert.Equal(t, bson.TypeInt64, bsonTypeAt(t, raw, "events", "urn:example:event", "list", "1"))
	assert.Equal(t, bson.TypeDouble, bsonTypeAt(t, raw, "events", "urn:example:event", "ratio"),
		"a fractional number stays a double; only integers are widened")
}

// TestSecurityEventTokenBSON_WideningPreservesValues: widening changes the
// stored type, never the value a reader gets back. Relaxed ExtJSON renders
// int32 and int64 identically, so the delivered SET is byte-for-byte what it
// was before — this pins that the round-trip stayed lossless.
func TestSecurityEventTokenBSON_WideningPreservesValues(t *testing.T) {
	wire := `{"iss":"https://issuer.example","aud":["https://receiver.example"],` +
		`"exp":2200000000,"iat":1786735851,"jti":"urn:uuid:8a843c88","toe":1786735851,` +
		`"sub_id":{"format":"opaque","id":"claude-code:toolu_01"},` +
		`"events":{"urn:example:event":{"count":42,"list":[1,9999999999],"ratio":1.5}}}`

	var set SecurityEventToken
	require.NoError(t, json.Unmarshal([]byte(wire), &set))

	raw, err := bson.Marshal(set)
	require.NoError(t, err)

	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))

	out, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(out),
		"widening must not alter any value on the way back to the wire")
}
