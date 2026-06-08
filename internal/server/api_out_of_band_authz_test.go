package server

import (
    "testing"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
)

// TestKeyScopeOnly locks the create-only key guard across both caller shapes.
//
// The OAuth/STS rows are the important ones: before keyScopeOnly was migrated off
// a bare authCtx.Eat check it returned false for every OAuth caller (Eat==nil),
// which silently exempted an OAuth key-only caller from the create-only guard and
// granted full key takeover/upload — a privilege escalation (#150). After the
// migration to HasScope, an OAuth key-only caller is correctly restricted while
// an OAuth admin/root caller is not.
func TestKeyScopeOnly(t *testing.T) {
    tests := []struct {
        name string
        ctx  *authSupport.AuthContext
        want bool
    }{
        {name: "nil context", ctx: nil, want: false},
        // Local (EAT-backed) callers.
        {
            name: "local key-only is restricted",
            ctx:  &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{Roles: []string{authSupport.ScopeKey}}},
            want: true,
        },
        {
            name: "local admin is not restricted",
            ctx:  &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{Roles: []string{authSupport.ScopeStreamAdmin}}},
            want: false,
        },
        {
            name: "local root rides free (not restricted)",
            ctx:  &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{Roles: []string{authSupport.ScopeRoot}}},
            want: false,
        },
        {
            name: "local key+admin is not restricted",
            ctx:  &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{Roles: []string{authSupport.ScopeKey, authSupport.ScopeStreamAdmin}}},
            want: false,
        },
        // OAuth/STS callers — the regression-fix rows.
        {
            name: "OAuth key-only is restricted (privilege-escalation fix)",
            ctx:  &authSupport.AuthContext{IsOAuthClient: true, GrantedScopes: []string{authSupport.ScopeKey}},
            want: true,
        },
        {
            name: "OAuth admin is not restricted",
            ctx:  &authSupport.AuthContext{IsOAuthClient: true, GrantedScopes: []string{authSupport.ScopeStreamAdmin}},
            want: false,
        },
        {
            name: "OAuth key+admin is not restricted",
            ctx:  &authSupport.AuthContext{IsOAuthClient: true, GrantedScopes: []string{authSupport.ScopeKey, authSupport.ScopeStreamAdmin}},
            want: false,
        },
        {
            name: "OAuth foreign root does not bypass the guard (#144)",
            ctx:  &authSupport.AuthContext{IsOAuthClient: true, GrantedScopes: []string{authSupport.ScopeKey, authSupport.ScopeRoot}},
            want: true,
        },
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            if got := keyScopeOnly(tc.ctx); got != tc.want {
                t.Errorf("keyScopeOnly() = %v, want %v", got, tc.want)
            }
        })
    }
}
