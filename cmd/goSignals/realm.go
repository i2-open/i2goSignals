package main

import (
    "fmt"
    "sort"
    "strings"
    "time"
)

// serversTrustingIssuer returns, in stable alias order, the aliases of every
// configured server that trusts the given realm issuer. A server trusts a realm
// when the issuer appears in its advertised AuthorizationServers, or (as a
// fallback for servers that never cached PRM) when it is the server's
// ActiveIssuer pointer.
func serversTrustingIssuer(servers map[string]SsfServer, issuer string) []string {
    var out []string
    for alias, server := range servers {
        if serverTrustsIssuer(server, issuer) {
            out = append(out, alias)
        }
    }
    sort.Strings(out)
    return out
}

// serverTrustsIssuer reports whether a single server trusts the given realm.
func serverTrustsIssuer(server SsfServer, issuer string) bool {
    if issuer == "" {
        return false
    }
    for _, as := range server.AuthorizationServers {
        if as == issuer {
            return true
        }
    }
    return server.ActiveIssuer == issuer
}

// resolveLogoutIssuers maps logout inputs to the set of realm issuers to drop.
// Exactly one targeting mode applies, in precedence order: --all (every stored
// realm), --issuer (one named realm), or <alias> (the server's active issuer).
// Specifying no target is an error so an empty `logout` never silently wipes
// every session.
func resolveLogoutIssuers(store *CredentialStore, servers map[string]SsfServer, alias, issuer string, all bool) ([]string, error) {
    switch {
    case all:
        return store.Issuers(), nil
    case issuer != "":
        return []string{issuer}, nil
    case alias != "":
        server, ok := servers[alias]
        if !ok {
            return nil, fmt.Errorf("server alias %q is not defined", alias)
        }
        if server.ActiveIssuer == "" {
            return nil, fmt.Errorf("server %q is not logged in to any realm", alias)
        }
        return []string{server.ActiveIssuer}, nil
    default:
        return nil, fmt.Errorf("specify a target: <alias>, --issuer <url>, or --all")
    }
}

// renderWhoami produces a gcloud-`auth list`-style listing of every stored
// realm session: issuer, subject/email, scopes, expiry, and which server
// aliases trust the realm. It is a pure function over the credential store and
// the configured servers so the rendering is unit-testable.
func renderWhoami(store *CredentialStore, servers map[string]SsfServer) string {
    issuers := store.Issuers()
    if len(issuers) == 0 {
        return "No active realm sessions. Run 'login <alias>' to authenticate."
    }
    sort.Strings(issuers)

    var b strings.Builder
    b.WriteString(fmt.Sprintf("%d active realm session(s):\n", len(issuers)))
    for _, issuer := range issuers {
        sess := store.Get(issuer)
        who := sess.Subject
        if sess.Email != "" {
            if who != "" {
                who = fmt.Sprintf("%s <%s>", sess.Subject, sess.Email)
            } else {
                who = sess.Email
            }
        }
        if who == "" {
            who = "(unknown)"
        }
        exp := "no-expiry"
        if !sess.Expiry.IsZero() {
            exp = sess.Expiry.Format(time.RFC3339)
        }
        status := "valid"
        if sess.Expired() {
            status = "expired (will refresh on next call)"
        }
        trusting := serversTrustingIssuer(servers, issuer)
        trust := "(no configured server)"
        if len(trusting) > 0 {
            trust = strings.Join(trusting, ", ")
        }
        b.WriteString(fmt.Sprintf(
            "  issuer=%s  subject=%s  scopes=%v  expires=%s  status=%s  servers=[%s]\n",
            issuer, who, sess.Scopes, exp, status, trust,
        ))
    }
    return b.String()
}

// selectIssuerForServer resolves which realm session should authorize a call to
// the given server. The server's ActiveIssuer wins when it has a live session;
// otherwise the most-recently-logged-in trusted realm is chosen (last-login-
// wins). Returns "" when no trusted logged-in realm exists.
func selectIssuerForServer(store *CredentialStore, server *SsfServer) string {
    if server == nil {
        return ""
    }
    if server.ActiveIssuer != "" && store.Get(server.ActiveIssuer) != nil {
        return server.ActiveIssuer
    }
    best := ""
    for _, issuer := range store.Issuers() {
        if !serverTrustsIssuer(*server, issuer) {
            continue
        }
        if best == "" || store.Get(issuer).LoggedInAt.After(store.Get(best).LoggedInAt) {
            best = issuer
        }
    }
    return best
}
