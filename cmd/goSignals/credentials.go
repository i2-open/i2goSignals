package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "os/user"
    "path/filepath"
    "time"
)

// credentialsFileName is the secrets file living alongside config.json. It is
// kept separate from config.json so that OAuth secrets never land in the
// (potentially shared/checked-in) server configuration cache.
const credentialsFileName = "credentials.json"

// Session is a logged-in OAuth session keyed by issuer in the credential store.
// It holds the bearer material and the resolved identity returned by the IdP.
type Session struct {
    AccessToken  string    `json:"accessToken"`
    RefreshToken string    `json:"refreshToken,omitempty"`
    Expiry       time.Time `json:"expiry"`
    Subject      string    `json:"subject,omitempty"`
    Email        string    `json:"email,omitempty"`
    Scopes       []string  `json:"scopes,omitempty"`
    ClientId     string    `json:"clientId,omitempty"`
    // LoggedInAt records when this session was established. It drives
    // last-login-wins active-issuer defaulting when a server trusts several
    // logged-in realms.
    LoggedInAt time.Time `json:"loggedInAt,omitempty"`
}

// Expired reports whether the access token is at/after its expiry (with a small
// skew so we refresh slightly early rather than racing the edge).
func (s *Session) Expired() bool {
    if s == nil {
        return true
    }
    if s.Expiry.IsZero() {
        return false
    }
    return time.Now().Add(30 * time.Second).After(s.Expiry)
}

// CredentialStore is a 0600 on-disk map of issuer -> Session. Secrets live here
// only; config.json never holds tokens.
type CredentialStore struct {
    Path     string              `json:"-"`
    Sessions map[string]*Session `json:"sessions"`
}

// credentialsPath returns the default credentials.json location, resolved
// alongside the active config.json (honoring GOSIGNALS_HOME), else
// ~/.goSignals/credentials.json.
func credentialsPath(g *Globals) string {
    if g != nil && g.ConfigFile != "" {
        return filepath.Join(filepath.Dir(g.ConfigFile), credentialsFileName)
    }
    base := ".goSignals"
    if usr, err := user.Current(); err == nil {
        base = filepath.Join(usr.HomeDir, base)
    }
    return filepath.Join(base, credentialsFileName)
}

// LoadCredentialStore opens (or initializes) the credential store for the
// current Globals.
func LoadCredentialStore(g *Globals) (*CredentialStore, error) {
    store := &CredentialStore{Path: credentialsPath(g)}
    if err := store.Load(); err != nil {
        return nil, err
    }
    return store, nil
}

// Load reads the store from disk. A missing file yields an empty store.
func (c *CredentialStore) Load() error {
    if c.Sessions == nil {
        c.Sessions = map[string]*Session{}
    }
    if c.Path == "" {
        return errors.New("credential store path not set")
    }
    bytes, err := os.ReadFile(c.Path)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    if len(bytes) == 0 {
        return nil
    }
    return json.Unmarshal(bytes, c)
}

// Save writes the store to disk at 0600, creating the parent directory if
// necessary.
func (c *CredentialStore) Save() error {
    if c.Path == "" {
        return errors.New("credential store path not set")
    }
    dir := filepath.Dir(c.Path)
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return err
    }
    out, err := json.MarshalIndent(c, "", "  ")
    if err != nil {
        return err
    }
    // Write 0600 explicitly (and re-chmod in case the file pre-existed with
    // looser permissions).
    if err := os.WriteFile(c.Path, out, 0o600); err != nil {
        return err
    }
    return os.Chmod(c.Path, 0o600)
}

// Get returns the session for an issuer, or nil if none is stored.
func (c *CredentialStore) Get(issuer string) *Session {
    if c.Sessions == nil {
        return nil
    }
    return c.Sessions[issuer]
}

// Set stores (replacing any existing) a session for an issuer.
func (c *CredentialStore) Set(issuer string, sess *Session) {
    if c.Sessions == nil {
        c.Sessions = map[string]*Session{}
    }
    c.Sessions[issuer] = sess
}

// Issuers returns the set of issuers (realms) with a stored session.
func (c *CredentialStore) Issuers() []string {
    if c.Sessions == nil {
        return nil
    }
    out := make([]string, 0, len(c.Sessions))
    for iss := range c.Sessions {
        out = append(out, iss)
    }
    return out
}

// Delete removes the session for an issuer (single-realm logout).
func (c *CredentialStore) Delete(issuer string) {
    if c.Sessions != nil {
        delete(c.Sessions, issuer)
    }
}

// describe returns a human-readable one-line summary of the session for whoami.
func (s *Session) describe(issuer string) string {
    who := s.Subject
    if s.Email != "" {
        who = fmt.Sprintf("%s <%s>", s.Subject, s.Email)
    }
    exp := "no-expiry"
    if !s.Expiry.IsZero() {
        exp = s.Expiry.Format(time.RFC3339)
    }
    return fmt.Sprintf("issuer=%s subject=%s scopes=%v expires=%s clientId=%s", issuer, who, s.Scopes, exp, s.ClientId)
}
