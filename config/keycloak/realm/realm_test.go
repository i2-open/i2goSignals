// Package realm_test guards the bootstrap Keycloak realm that the demo and
// dev compose stacks import into keycloak-signals.
package realm_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type realmRole struct {
	Name string `json:"name"`
}

type realmUser struct {
	Username   string   `json:"username"`
	RealmRoles []string `json:"realmRoles"`
}

type bootstrapRealm struct {
	Roles struct {
		Realm []realmRole `json:"realm"`
	} `json:"roles"`
	Users []realmUser `json:"users"`
}

// TestSeededUsersHoldOperatorRole covers #344: admin requires the realm role
// "operator" on every /api/admin/* call (ADR-0073 clause 7), including in
// community mode, so the bootstrap realm must define it and grant it to both
// seeded users.
func TestSeededUsersHoldOperatorRole(t *testing.T) {
	raw, err := os.ReadFile("gosignals-realm.json")
	if err != nil {
		t.Fatalf("read realm: %v", err)
	}
	var realm bootstrapRealm
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatalf("parse realm: %v", err)
	}

	if !slices.ContainsFunc(realm.Roles.Realm, func(r realmRole) bool { return r.Name == "operator" }) {
		t.Error(`realm role "operator" is not defined in roles.realm`)
	}

	for _, want := range []string{"admin", "user"} {
		idx := slices.IndexFunc(realm.Users, func(u realmUser) bool { return u.Username == want })
		if idx < 0 {
			t.Errorf("seeded user %q is missing", want)
			continue
		}
		if !slices.Contains(realm.Users[idx].RealmRoles, "operator") {
			t.Errorf("seeded user %q does not hold realm role \"operator\"; has %v", want, realm.Users[idx].RealmRoles)
		}
	}
}
