package subjectid_test

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/subjectid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCanonicalKeyEmail is the tracer bullet: an email subject canonicalizes to
// a single, format-prefixed, stable string with the domain lower-cased.
func TestCanonicalKeyEmail(t *testing.T) {
	sid := &goSet.SubjectIdentifier{Format: "email"}
	sid.Email = "Alice@Example.COM"

	key, err := subjectid.CanonicalKey(sid)
	require.NoError(t, err)
	assert.Equal(t, "email:Alice@example.com", key,
		"email domain is lower-cased, local-part preserved, format-prefixed")
}

// TestCanonicalKeyIssSub canonicalizes an iss_sub subject into a composite key
// that unambiguously combines issuer and subject.
func TestCanonicalKeyIssSub(t *testing.T) {
	sid := &goSet.SubjectIdentifier{Format: "iss_sub"}
	sid.Issuer = "https://idp.example.com"
	sid.Sub = "248289761001"

	key, err := subjectid.CanonicalKey(sid)
	require.NoError(t, err)
	assert.Equal(t, `iss_sub:"https://idp.example.com"|"248289761001"`, key)

	// A change to either component yields a different key.
	other := &goSet.SubjectIdentifier{Format: "iss_sub"}
	other.Issuer = "https://idp.example.com"
	other.Sub = "248289761001x"
	otherKey, err := subjectid.CanonicalKey(other)
	require.NoError(t, err)
	assert.NotEqual(t, key, otherKey)
}

// TestCanonicalKeyPhoneNumber strips visual separators so that the same number
// written different ways canonicalizes identically (RFC9493 §3.2.5).
func TestCanonicalKeyPhoneNumber(t *testing.T) {
	a := &goSet.SubjectIdentifier{Format: "phone_number"}
	a.PhoneNumber = "+1 (604) 555-1212"
	b := &goSet.SubjectIdentifier{Format: "phone_number"}
	b.PhoneNumber = "+1.604.555.1212"

	keyA, err := subjectid.CanonicalKey(a)
	require.NoError(t, err)
	keyB, err := subjectid.CanonicalKey(b)
	require.NoError(t, err)

	assert.Equal(t, "phone_number:+16045551212", keyA)
	assert.Equal(t, keyA, keyB, "visual separators do not affect the canonical key")
}

// TestCanonicalKeySingleValueFormats covers the formats whose canonical key is
// the trimmed value behind a format prefix: opaque, did, uri and account.
func TestCanonicalKeySingleValueFormats(t *testing.T) {
	opaque := &goSet.SubjectIdentifier{Format: "opaque"}
	opaque.Id = " 11112222333344445555 "
	key, err := subjectid.CanonicalKey(opaque)
	require.NoError(t, err)
	assert.Equal(t, "opaque:11112222333344445555", key)

	did := &goSet.SubjectIdentifier{Format: "did"}
	did.Url = "did:example:123456/did/url"
	key, err = subjectid.CanonicalKey(did)
	require.NoError(t, err)
	assert.Equal(t, "did:did:example:123456/did/url", key)

	// account and uri both carry their value in the uri field; the format
	// prefix keeps an acct URI and a plain URI with the same value distinct.
	acct := &goSet.SubjectIdentifier{Format: "account"}
	acct.Uri = "acct:example.user@service.example.com"
	uri := &goSet.SubjectIdentifier{Format: "uri"}
	uri.Uri = "acct:example.user@service.example.com"

	acctKey, err := subjectid.CanonicalKey(acct)
	require.NoError(t, err)
	uriKey, err := subjectid.CanonicalKey(uri)
	require.NoError(t, err)
	assert.Equal(t, "account:acct:example.user@service.example.com", acctKey)
	assert.Equal(t, "uri:acct:example.user@service.example.com", uriKey)
	assert.NotEqual(t, acctKey, uriKey, "format prefix prevents account/uri collision")
}

// TestCanonicalKeyErrors rejects subjects that cannot produce a stable key.
func TestCanonicalKeyErrors(t *testing.T) {
	_, err := subjectid.CanonicalKey(nil)
	assert.Error(t, err, "nil subject identifier")

	_, err = subjectid.CanonicalKey(&goSet.SubjectIdentifier{})
	assert.Error(t, err, "missing format")

	_, err = subjectid.CanonicalKey(&goSet.SubjectIdentifier{Format: "carrier_pigeon"})
	assert.Error(t, err, "unrecognized format")

	_, err = subjectid.CanonicalKey(&goSet.SubjectIdentifier{Format: "email"})
	assert.Error(t, err, "email format with no email value")
}

// TestCanonicalKeyAliases canonicalizes an aliases subject into a key built
// from its member keys; member order does not affect the result.
func TestCanonicalKeyAliases(t *testing.T) {
	email := goSet.SubjectIdentifier{Format: "email"}
	email.Email = "alice@example.com"
	phone := goSet.SubjectIdentifier{Format: "phone_number"}
	phone.PhoneNumber = "+16045551212"

	a := &goSet.SubjectIdentifier{Format: "aliases"}
	a.Identifiers = []goSet.SubjectIdentifier{email, phone}
	b := &goSet.SubjectIdentifier{Format: "aliases"}
	b.Identifiers = []goSet.SubjectIdentifier{phone, email}

	keyA, err := subjectid.CanonicalKey(a)
	require.NoError(t, err)
	keyB, err := subjectid.CanonicalKey(b)
	require.NoError(t, err)

	assert.Equal(t, keyA, keyB, "aliases canonical key is order-independent")
	assert.Contains(t, keyA, "email:alice@example.com")
	assert.Contains(t, keyA, "phone_number:+16045551212")

	// An aliases subject with no members has no stable key.
	_, err = subjectid.CanonicalKey(&goSet.SubjectIdentifier{Format: "aliases"})
	assert.Error(t, err, "empty aliases subject")
}

// TestKind classifies a subject as simple, complex or aliases.
func TestKind(t *testing.T) {
	simple := &goSet.SubjectIdentifier{Format: "email"}
	simple.Email = "alice@example.com"
	assert.Equal(t, subjectid.KindSimple, subjectid.Kind(simple))

	aliases := &goSet.SubjectIdentifier{Format: "aliases"}
	aliases.Identifiers = []goSet.SubjectIdentifier{*simple}
	assert.Equal(t, subjectid.KindAliases, subjectid.Kind(aliases))

	complex := &goSet.SubjectIdentifier{}
	complex.User = simple
	assert.Equal(t, subjectid.KindComplex, subjectid.Kind(complex))
}

// TestCanonicalKeyComplex canonicalizes a complex subject from its defined
// members; an undefined member contributes nothing to the key.
func TestCanonicalKeyComplex(t *testing.T) {
	user := goSet.SubjectIdentifier{Format: "email"}
	user.Email = "alice@example.com"
	device := goSet.SubjectIdentifier{Format: "opaque"}
	device.Id = "device-42"

	full := &goSet.SubjectIdentifier{}
	full.User = &user
	full.Device = &device

	key, err := subjectid.CanonicalKey(full)
	require.NoError(t, err)
	assert.Contains(t, key, "user=email:alice@example.com")
	assert.Contains(t, key, "device=opaque:device-42")

	// The same members produce the same key regardless of which was set first.
	again := &goSet.SubjectIdentifier{}
	again.Device = &device
	again.User = &user
	keyAgain, err := subjectid.CanonicalKey(again)
	require.NoError(t, err)
	assert.Equal(t, key, keyAgain, "complex canonical key is stable")

	// A user-only complex subject yields a different, narrower key.
	userOnly := &goSet.SubjectIdentifier{}
	userOnly.User = &user
	userOnlyKey, err := subjectid.CanonicalKey(userOnly)
	require.NoError(t, err)
	assert.NotEqual(t, key, userOnlyKey)

	// A complex subject with no members has no stable key.
	_, err = subjectid.CanonicalKey(&goSet.SubjectIdentifier{})
	assert.Error(t, err)
}

// TestMatchSimple matches simple subjects on exact identity: two subjects match
// iff their canonical keys are equal.
func TestMatchSimple(t *testing.T) {
	a := &goSet.SubjectIdentifier{Format: "email"}
	a.Email = "alice@example.com"
	// Same identity, different domain case — normalization makes them equal.
	b := &goSet.SubjectIdentifier{Format: "email"}
	b.Email = "alice@EXAMPLE.COM"
	assert.True(t, subjectid.MatchSimple(a, b), "same identity matches")

	c := &goSet.SubjectIdentifier{Format: "email"}
	c.Email = "bob@example.com"
	assert.False(t, subjectid.MatchSimple(a, c), "different identity does not match")

	// A different format with a coincidentally similar value does not match.
	uri := &goSet.SubjectIdentifier{Format: "uri"}
	uri.Uri = "alice@example.com"
	assert.False(t, subjectid.MatchSimple(a, uri), "format prefix keeps subjects distinct")

	// An un-keyable subject never matches.
	assert.False(t, subjectid.MatchSimple(a, &goSet.SubjectIdentifier{Format: "email"}),
		"a subject with no stable key does not match")
}

// email and opaque are small constructors that keep the complex-subject tests
// readable.
func email(addr string) *goSet.SubjectIdentifier {
	s := &goSet.SubjectIdentifier{Format: "email"}
	s.Email = addr
	return s
}

func opaque(id string) *goSet.SubjectIdentifier {
	s := &goSet.SubjectIdentifier{Format: "opaque"}
	s.Id = id
	return s
}

// TestMatchComplex matches complex subjects field-wise: a field undefined on
// either side acts as a wildcard, so a broad subscription matches a narrower,
// more-specific event subject.
func TestMatchComplex(t *testing.T) {
	// Fully specified on both sides, identical — match.
	subFull := &goSet.SubjectIdentifier{}
	subFull.User = email("alice@example.com")
	subFull.Device = opaque("device-42")
	evtFull := &goSet.SubjectIdentifier{}
	evtFull.User = email("alice@example.com")
	evtFull.Device = opaque("device-42")
	assert.True(t, subjectid.MatchComplex(subFull, evtFull), "identical complex subjects match")

	// Broad subscription (user only) matches a narrower event (user + device):
	// the subscription leaves device undefined, so device is a wildcard.
	broad := &goSet.SubjectIdentifier{}
	broad.User = email("alice@example.com")
	assert.True(t, subjectid.MatchComplex(broad, evtFull),
		"broad subscription matches narrower event subject")

	// A field defined on both sides but differing — no match.
	wrongDevice := &goSet.SubjectIdentifier{}
	wrongDevice.User = email("alice@example.com")
	wrongDevice.Device = opaque("device-99")
	assert.False(t, subjectid.MatchComplex(wrongDevice, evtFull),
		"a field that differs on both sides defeats the match")

	// The wildcard is symmetric: a field undefined on the event side is also a
	// wildcard, so a more-specific subscription still matches a broad event.
	narrowEvent := &goSet.SubjectIdentifier{}
	narrowEvent.User = email("alice@example.com")
	assert.True(t, subjectid.MatchComplex(subFull, narrowEvent),
		"a field undefined on the event side acts as a wildcard too")
}

// TestMatch dispatches by subject kind and resolves aliases.
func TestMatch(t *testing.T) {
	alice := email("alice@example.com")
	bob := email("bob@example.com")

	// Same-kind dispatch: simple→simple and complex→complex.
	assert.True(t, subjectid.Match(alice, email("alice@EXAMPLE.com")))
	assert.False(t, subjectid.Match(alice, bob))

	complexAlice := &goSet.SubjectIdentifier{}
	complexAlice.User = alice
	assert.True(t, subjectid.Match(complexAlice, complexAlice))

	// Kind mismatch: a simple subject never matches a complex one.
	assert.False(t, subjectid.Match(alice, complexAlice), "simple and complex kinds do not match")

	// An aliases subject matches another subject when any alias matches.
	aliasSet := &goSet.SubjectIdentifier{Format: "aliases"}
	aliasSet.Identifiers = []goSet.SubjectIdentifier{*bob, *alice}
	assert.True(t, subjectid.Match(aliasSet, alice), "aliases matches when one alias matches")
	assert.False(t, subjectid.Match(aliasSet, email("carol@example.com")),
		"aliases does not match when no alias matches")

	// Two aliases subjects match when they share an alias.
	otherSet := &goSet.SubjectIdentifier{Format: "aliases"}
	otherSet.Identifiers = []goSet.SubjectIdentifier{*alice}
	assert.True(t, subjectid.Match(aliasSet, otherSet), "aliases sets match on a shared alias")
}
