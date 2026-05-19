// Package subjectid is a pure, isolation-testable module for SSF subject
// identity and matching. It normalizes RFC9493 subject identifiers to a
// canonical filter key and implements the SSF §8.1.3.1 match predicate.
//
// The package is pure: no I/O, no DAO, no goSignals internal dependencies. It
// is the spec-correctness foundation that PRD #89's SubjectFilterService and
// the ADR-0003 split-storage model are built on.
package subjectid

import (
	"fmt"
	"sort"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// SubjectKind classifies a subject by how SSF §8.1.3.1 matches it: a simple
// subject by exact identity, a complex subject field-wise, an aliases subject
// as a set of equivalent identifiers.
type SubjectKind int

const (
	KindSimple SubjectKind = iota
	KindComplex
	KindAliases
)

// orderedComplexMembers is the fixed iteration order of complex-subject
// members, giving a complex subject a deterministic canonical key.
var orderedComplexMembers = []string{"user", "group", "device", "session", "tenant", "org_unit"}

// complexMember returns the named complex-subject member, or nil if undefined.
func complexMember(sid *goSet.SubjectIdentifier, name string) *goSet.SubjectIdentifier {
	switch name {
	case "user":
		return sid.User
	case "group":
		return sid.Group
	case "device":
		return sid.Device
	case "session":
		return sid.Session
	case "tenant":
		return sid.Tenant
	case "org_unit":
		return sid.OrgUnit
	default:
		return nil
	}
}

// Kind classifies a subject as simple, complex, or aliases. A subject carrying
// any complex member is complex; one in the aliases format is aliases;
// otherwise it is simple.
func Kind(sid *goSet.SubjectIdentifier) SubjectKind {
	if sid == nil {
		return KindSimple
	}
	if sid.Format == "aliases" || len(sid.Identifiers) > 0 {
		return KindAliases
	}
	for _, name := range orderedComplexMembers {
		if complexMember(sid, name) != nil {
			return KindComplex
		}
	}
	return KindSimple
}

// CanonicalKey normalizes a subject identifier to a stable canonical key. For a
// simple subject the key is a single, format-prefixed string suitable for
// hash-indexed membership (ADR-0003). Each RFC9493 format applies its own
// normalization rules. Complex and aliases subjects normalize to a stable key
// built from their members. It returns an error when the subject's format is
// missing, unrecognized, or its required value is empty.
func CanonicalKey(sid *goSet.SubjectIdentifier) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("subject identifier is nil")
	}

	switch Kind(sid) {
	case KindAliases:
		return aliasesKey(sid)
	case KindComplex:
		return complexKey(sid)
	}

	switch sid.Format {
	case "email":
		email := strings.TrimSpace(sid.Email)
		if email == "" {
			return "", fmt.Errorf("email format subject has no email value")
		}
		return "email:" + normalizeEmail(email), nil
	case "iss_sub":
		iss := strings.TrimSpace(sid.Issuer)
		sub := strings.TrimSpace(sid.Sub)
		if iss == "" || sub == "" {
			return "", fmt.Errorf("iss_sub format subject is missing iss or sub")
		}
		return fmt.Sprintf("iss_sub:%q|%q", iss, sub), nil
	case "phone_number":
		phone := normalizePhoneNumber(sid.PhoneNumber)
		if phone == "" {
			return "", fmt.Errorf("phone_number format subject has no phone_number value")
		}
		return "phone_number:" + phone, nil
	case "opaque":
		id := strings.TrimSpace(sid.Id)
		if id == "" {
			return "", fmt.Errorf("opaque format subject has no id value")
		}
		return "opaque:" + id, nil
	case "did":
		url := strings.TrimSpace(sid.Url)
		if url == "" {
			return "", fmt.Errorf("did format subject has no url value")
		}
		return "did:" + url, nil
	case "account":
		uri := strings.TrimSpace(sid.Uri)
		if uri == "" {
			return "", fmt.Errorf("account format subject has no uri value")
		}
		return "account:" + uri, nil
	case "uri":
		uri := strings.TrimSpace(sid.Uri)
		if uri == "" {
			return "", fmt.Errorf("uri format subject has no uri value")
		}
		return "uri:" + uri, nil
	default:
		return "", fmt.Errorf("unrecognized subject format %q", sid.Format)
	}
}

// MatchSimple reports whether two simple subjects are the same identity, per
// SSF §8.1.3.1: simple subjects match iff they are exactly identical. It is the
// canonical-key equality path of ADR-0003. A subject that cannot produce a
// stable canonical key never matches.
func MatchSimple(a, b *goSet.SubjectIdentifier) bool {
	keyA, err := CanonicalKey(a)
	if err != nil {
		return false
	}
	keyB, err := CanonicalKey(b)
	if err != nil {
		return false
	}
	return keyA == keyB
}

// Match reports whether two subjects refer to the same principal under SSF
// §8.1.3.1. It dispatches by subject kind: an aliases subject matches when any
// of its aliases matches; otherwise both subjects must share a kind — two
// simple subjects match by canonical-key equality, two complex subjects
// field-wise. A simple subject never matches a complex one.
func Match(a, b *goSet.SubjectIdentifier) bool {
	if a == nil || b == nil {
		return false
	}
	// An aliases subject matches if any of its members matches the other side.
	if Kind(a) == KindAliases {
		for i := range a.Identifiers {
			if Match(&a.Identifiers[i], b) {
				return true
			}
		}
		return false
	}
	if Kind(b) == KindAliases {
		return Match(b, a)
	}
	switch Kind(a) {
	case KindComplex:
		return Kind(b) == KindComplex && MatchComplex(a, b)
	default:
		return Kind(b) == KindSimple && MatchSimple(a, b)
	}
}

// MatchComplex reports whether two complex subjects match field-wise, per SSF
// §8.1.3.1. For each complex member, a side that leaves it undefined acts as a
// wildcard; the match holds when every member defined on both sides is the
// same identity. It is the field-wise scan path of ADR-0003 — a broad
// subscription (few members) still matches a narrower, more-specific event.
func MatchComplex(subscription, event *goSet.SubjectIdentifier) bool {
	if subscription == nil || event == nil {
		return false
	}
	for _, name := range orderedComplexMembers {
		subMember := complexMember(subscription, name)
		evtMember := complexMember(event, name)
		if subMember == nil || evtMember == nil {
			continue // undefined on either side: wildcard
		}
		if !MatchSimple(subMember, evtMember) {
			return false
		}
	}
	return true
}

// aliasesKey builds an order-independent canonical key from the member keys of
// an aliases subject.
func aliasesKey(sid *goSet.SubjectIdentifier) (string, error) {
	if len(sid.Identifiers) == 0 {
		return "", fmt.Errorf("aliases format subject has no identifiers")
	}
	memberKeys := make([]string, 0, len(sid.Identifiers))
	for i := range sid.Identifiers {
		memberKey, err := CanonicalKey(&sid.Identifiers[i])
		if err != nil {
			return "", fmt.Errorf("aliases member %d: %w", i, err)
		}
		memberKeys = append(memberKeys, memberKey)
	}
	sort.Strings(memberKeys)
	return "aliases:[" + strings.Join(memberKeys, ",") + "]", nil
}

// complexKey builds a stable canonical key from the defined members of a
// complex subject, visiting members in a fixed order.
func complexKey(sid *goSet.SubjectIdentifier) (string, error) {
	parts := make([]string, 0, len(orderedComplexMembers))
	for _, name := range orderedComplexMembers {
		member := complexMember(sid, name)
		if member == nil {
			continue
		}
		memberKey, err := CanonicalKey(member)
		if err != nil {
			return "", fmt.Errorf("complex member %q: %w", name, err)
		}
		parts = append(parts, name+"="+memberKey)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("complex subject has no members")
	}
	return "complex:[" + strings.Join(parts, ",") + "]", nil
}

// normalizeEmail lower-cases the domain part of an email address while
// preserving the case-sensitive local-part.
func normalizeEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return email
	}
	return email[:at] + "@" + strings.ToLower(email[at+1:])
}

// normalizePhoneNumber strips visual separators (spaces, dashes, parentheses,
// dots) leaving only digits and an optional leading "+", per RFC9493 §3.2.5.
func normalizePhoneNumber(phone string) string {
	var b strings.Builder
	for i, r := range strings.TrimSpace(phone) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}
