package authUtil

import (
	"crypto/subtle"
	"os"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

// bootstrapTokenEnv is the environment variable holding the shared bootstrap
// secret. When set, a bearer equal to its value is granted the narrow "key"
// scope so an unattended deployment can mint an issuer signing key and an IAT
// without an anonymous endpoint. When unset, the bootstrap path is closed and
// no bearer is ever accepted through it.
const bootstrapTokenEnv = "I2SIG_BOOTSTRAP_TOKEN"

// resolveBootstrapBearer returns a key-scope AuthContext when the presented
// bearer constant-time-equals the configured bootstrap secret. It returns nil
// when the secret is unset (fail closed) or the bearer does not match, in which
// case the caller continues with normal JWT/kid classification.
//
// The comparison is constant-time to avoid leaking the secret length/prefix
// via timing. An unset (empty) secret short-circuits before any comparison so
// an empty presented bearer can never "match" an empty configured secret.
func (a *AuthIssuer) resolveBootstrapBearer(tokenString string) *AuthContext {
	secret := os.Getenv(bootstrapTokenEnv)
	if secret == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(tokenString), []byte(secret)) != 1 {
		return nil
	}

	authLog.Debug("Bootstrap bearer accepted; synthesizing key-scope context")
	return &AuthContext{
		Eat: &authSupport.EventAuthToken{
			Roles: []string{authSupport.ScopeKey},
		},
	}
}
