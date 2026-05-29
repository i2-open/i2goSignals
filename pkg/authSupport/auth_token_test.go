package authSupport

import "testing"

// TestScopeKeyExists asserts the narrow "key" scope is part of the scope
// vocabulary alongside reg/stream/admin/event/root. The "key" scope sits
// between reg and admin: it permits creating a new issuer signing key but
// must not grant stream administration or event delivery.
func TestScopeKeyExists(t *testing.T) {
    if ScopeKey != "key" {
        t.Fatalf("expected ScopeKey to be \"key\", got %q", ScopeKey)
    }

    // The key scope must be distinct from every other scope in the vocabulary.
    others := []string{ScopeStreamMgmt, ScopeEventDelivery, ScopeStreamAdmin, ScopeRegister, ScopeRoot}
    for _, s := range others {
        if s == ScopeKey {
            t.Fatalf("ScopeKey collides with existing scope %q", s)
        }
    }
}

// TestKeyScopeIsAuthorizedForKey verifies a token carrying only the key scope
// satisfies a key-scoped requirement but nothing broader.
func TestKeyScopeIsAuthorizedForKey(t *testing.T) {
    tkn := &EventAuthToken{Roles: []string{ScopeKey}}

    if !tkn.IsScopeMatch([]string{ScopeKey}) {
        t.Errorf("key token should match a key-scope requirement")
    }
    if tkn.IsScopeMatch([]string{ScopeStreamAdmin}) {
        t.Errorf("key token must NOT match a stream_admin requirement")
    }
    if tkn.IsScopeMatch([]string{ScopeEventDelivery}) {
        t.Errorf("key token must NOT match an event_delivery requirement")
    }
    if tkn.IsScopeMatch([]string{ScopeStreamMgmt}) {
        t.Errorf("key token must NOT match a stream_mgmt requirement")
    }
}
