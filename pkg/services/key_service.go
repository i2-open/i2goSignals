package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var ksLog = logger.Sub("KEY_SERVICE")

// ErrKeyStatusInvalid is returned by SetKeyStatus when the requested status is
// not one of active/suspended/revoked. The HTTP surface maps it to 400.
var ErrKeyStatusInvalid = errors.New("invalid key status; must be active, suspended, or revoked")

// ErrKeyStatusTerminal is returned when a transition would move a record away
// from the terminal revoked state. The HTTP surface maps it to 400.
var ErrKeyStatusTerminal = errors.New("key is revoked (terminal); cannot transition to another status")

type KeyService struct {
	keyDAO      interfaces.KeyDAO
	tokenIssuer string
	tokenKid    string
	tokenKey    *rsa.PrivateKey
	tokenPubKey *keyfunc.JWKS
	authIssuer  *authSupport.AuthIssuer
}

// NewKeyService constructs a KeyService. oauthServersLookup supplies the OAuth
// Authorization Server discovery endpoints for the AuthIssuer; the caller (the
// wiring tree) owns where those come from (env, config, etc.) so this package
// stays free of internal/envcompat. A nil lookup leaves AuthIssuer with no
// OAuth servers configured.
func NewKeyService(keyDAO interfaces.KeyDAO, tokenIssuer string, tokenTracker authSupport.TokenTracker, oauthServersLookup func() string) *KeyService {
	return &KeyService{
		keyDAO:      keyDAO,
		tokenIssuer: tokenIssuer,
		authIssuer: &authSupport.AuthIssuer{
			TokenIssuer:        tokenIssuer,
			TokenTracker:       tokenTracker,
			OAuthServersLookup: oauthServersLookup,
		},
	}
}

// InitializeTokenKey loads or creates the token signing key for authentication
func (s *KeyService) InitializeTokenKey(ctx context.Context, defaultIssuer string) error {
	// Try to load existing key
	key, kid, err := s.GetPrivateKeyWithKeyname(ctx, s.tokenIssuer)
	if err == nil && key != nil {
		s.tokenKey = key
		s.tokenKid = kid
		// Use buildAuthJWKS with the loaded key so that, even when there are duplicate
		// kid=DEFAULT records in the DB (race between two nodes on first start), the
		// JWKS entry for this kid always reflects the private key we actually loaded.
		s.tokenPubKey = s.buildAuthJWKS(ctx, s.tokenIssuer, key, kid)
		if s.tokenPubKey == nil {
			return fmt.Errorf("failed to build public JWKS for token issuer %q; MongoDB may be temporarily unavailable", s.tokenIssuer)
		}
		s.authIssuer.UpdateTokenKey(s.tokenIssuer, s.tokenKid, s.tokenKey, s.tokenPubKey)
		return nil
	}

	// Only create a new key if the key genuinely does not exist in the database.
	// Any other error (e.g. a transient MongoDB failure) must propagate so that the
	// caller retries rather than accidentally inserting a duplicate kid=DEFAULT record,
	// which would cause non-deterministic JWKS construction and signature-mismatch 503s.
	if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
		return fmt.Errorf("failed to load token key %q: %w", s.tokenIssuer, err)
	}

	// Create new key. CreateKeyPair → storeKeyPair sets AuthIssuer atomically using
	// buildAuthJWKS with the signing key override. Do NOT re-query getInternalPublicJWKS
	// here — doing so would race with concurrent cluster nodes inserting their own
	// kid=DEFAULT key, causing the JWKS to contain a different node's public key while
	// this node's private key is used for signing.
	s.tokenKey, err = s.CreateKeyPair(ctx, s.tokenIssuer, "sig", "")
	if err != nil {
		return fmt.Errorf("failed to create token key: %v", err)
	}
	s.tokenKid = s.tokenIssuer
	s.tokenPubKey = s.authIssuer.PublicKey // already set correctly by storeKeyPair
	if s.tokenPubKey == nil {
		return fmt.Errorf("failed to build public JWKS for token issuer %q after key creation", s.tokenIssuer)
	}

	if defaultIssuer != s.tokenIssuer {
		// Also create default issuer signing key if different
		_, err = s.CreateKeyPair(ctx, defaultIssuer, "sig", "")
		if err != nil {
			ksLog.Error("Error creating default issuer key", "error", err)
		}
	}
	return nil
}

// CreateKeyPair generates a new RSA key pair identified by keyName with the given use ("sig" or "enc").
func (s *KeyService) CreateKeyPair(ctx context.Context, keyName string, use string, projectId string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ksLog.Error("Error generating key pair", "error", err)
		return nil, err
	}

	err = s.storeKeyPair(ctx, keyName, keyName, use, privateKey, projectId)
	if err != nil {
		ksLog.Error("Error storing key pair", "error", err)
		return nil, err
	}

	// storeKeyPair above already called buildAuthJWKS + UpdateTokenKey for the token
	// issuer key. No need to re-query the DB here; doing so would reintroduce the
	// race where a concurrent node's same-kid record overwrites our JWKS entry.

	return privateKey, nil
}

// EnsureSigningKey idempotently guarantees a "sig" key pair exists for keyName,
// creating one only when it is genuinely absent. It is the restart-safe
// provisioning primitive for an administrator-declared SSF issuer (strict mode,
// see goSsfServer.ProvisionStrictMode): unlike InitializeTokenKey — which seeds
// the default-issuer key only on first init and short-circuits once the token
// key already exists — EnsureSigningKey re-checks on every call, so an issuer
// added to an established deployment, or present only after a restart, is still
// backed by a signing key. It returns true when a new key was created.
//
// A transient DAO failure (anything other than ErrKeyNotFound) is returned
// rather than masked, so the caller surfaces it instead of inserting a duplicate
// key against a flaky backend (the same discipline InitializeTokenKey uses).
func (s *KeyService) EnsureSigningKey(ctx context.Context, keyName string, projectId string) (bool, error) {
	key, _, err := s.GetPrivateKeyWithKeyname(ctx, keyName)
	if err == nil && key != nil {
		return false, nil
	}
	if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
		return false, fmt.Errorf("failed to check signing key %q: %w", keyName, err)
	}
	// ErrKeyNotFound is ambiguous here: keyName may have no signing material at
	// all, or it may have a signing key an operator deliberately suspended/revoked.
	// Refuse to mint a fresh active key over a disabled one — silently recreating
	// it would resurrect the signing the operator just stopped (ADR 0028: no
	// auto-rotation, no fallback to an inactive kid).
	recs, ferr := s.keyDAO.FindByKeyName(ctx, keyName)
	if ferr != nil {
		return false, fmt.Errorf("failed to check signing key %q: %w", keyName, ferr)
	}
	if _, sawInactive := latestActiveSigningRec(recs); sawInactive {
		ksLog.Warn("Signing key exists but is suspended or revoked; not creating a replacement",
			"keyName", keyName,
			"remedy", "rotate a new key or reactivate the suspended key")
		return false, nil
	}
	if _, err := s.CreateKeyPair(ctx, keyName, "sig", projectId); err != nil {
		return false, fmt.Errorf("failed to create signing key %q: %w", keyName, err)
	}
	return true, nil
}

// RotateKey generates a new key pair for keyName with a unique kid.
func (s *KeyService) RotateKey(ctx context.Context, keyName string, projectId string) (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	kid := fmt.Sprintf("%s-%s", keyName, ids.NewObjectID())

	// Preserve the use from the existing key if available
	use := "sig"
	if existing, err2 := s.keyDAO.FindLatestByKeyName(ctx, keyName); err2 == nil {
		use = existing.Use
	}

	err = s.storeKeyPair(ctx, keyName, kid, use, privateKey, projectId)
	if err != nil {
		return nil, "", err
	}

	if keyName == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		jwks := s.buildAuthJWKS(ctx, keyName, privateKey, kid)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key rotation", "keyName", keyName)
		}
	}

	return privateKey, kid, nil
}

func (s *KeyService) storeKeyPair(ctx context.Context, keyName string, kid string, use string, privateKey *rsa.PrivateKey, projectId string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          ids.NewObjectID(),
		KeyName:     keyName,
		Kid:         kid,
		Use:         use,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && keyName == s.tokenIssuer {
		s.tokenKey = privateKey
		s.tokenKid = kid
		// Use buildAuthJWKS with the signing key override to guarantee that the JWKS
		// entry for this kid matches privateKey, regardless of concurrent inserts from
		// other cluster nodes with the same kid.
		jwks := s.buildAuthJWKS(ctx, keyName, privateKey, kid)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key store", "keyName", keyName)
		}
	}
	return err
}

// AddKey stores an externally-provided key (or key pair) identified by keyName.
func (s *KeyService) AddKey(ctx context.Context, keyName string, use string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	var privateKeyBytes []byte
	if privateKey != nil {
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
		if publicKey == nil {
			publicKey = &privateKey.PublicKey
		}
	}

	var pubKeyBytes []byte
	if publicKey != nil {
		pubKeyBytes = x509.MarshalPKCS1PublicKey(publicKey)
	}

	if kid == "" {
		kid = keyName
	}

	keyPairRec := &interfaces.JwkKeyRec{
		Id:          ids.NewObjectID(),
		KeyName:     keyName,
		Kid:         kid,
		Use:         use,
		ProjectId:   projectId,
		KeyBytes:    privateKeyBytes,
		PubKeyBytes: pubKeyBytes,
	}

	err := s.keyDAO.Insert(ctx, keyPairRec)
	if err == nil && keyName == s.tokenIssuer && privateKey != nil {
		s.tokenKey = privateKey
		s.tokenKid = kid
		jwks := s.getInternalPublicJWKS(ctx, keyName)
		if jwks != nil {
			s.tokenPubKey = jwks
			s.authIssuer.UpdateTokenKey(keyName, kid, privateKey, s.tokenPubKey)
		} else {
			ksLog.Error("Failed to build JWKS after key add", "keyName", keyName)
		}
	}
	return err
}

// DeleteKeysByName removes all key records with the given keyName.
func (s *KeyService) DeleteKeysByName(ctx context.Context, keyName string) error {
	return s.keyDAO.DeleteByKeyName(ctx, keyName)
}

// GetPrivateKey retrieves the latest private key for keyName.
func (s *KeyService) GetPrivateKey(ctx context.Context, keyName string) (*rsa.PrivateKey, error) {
	key, _, err := s.GetPrivateKeyWithKeyname(ctx, keyName)
	return key, err
}

// GetPrivateKeyWithKeyname retrieves the latest ACTIVE private key and its kid
// for keyName. Suspended and revoked records are never signing candidates. When
// keyName has records but none are active, it logs a loud ERROR naming the
// issuer and the remedy, and returns ErrKeyNotFound — there is deliberately no
// fallback to an older inactive kid and no auto-rotation (ADR 0028).
func (s *KeyService) GetPrivateKeyWithKeyname(ctx context.Context, keyName string) (*rsa.PrivateKey, string, error) {
	rec, err := s.findLatestActiveSigningRec(ctx, keyName)
	if err != nil {
		return nil, "", err
	}
	return parseSigningRec(rec)
}

// parseSigningRec parses a record's PKCS1 private key and derives its kid,
// falling back to the keyName when the record carries no explicit kid. It is the
// single signing-key materialization path shared by GetPrivateKeyWithKeyname and
// the token-issuer refresh so the two can never diverge (ADR 0028).
func parseSigningRec(rec *interfaces.JwkKeyRec) (*rsa.PrivateKey, string, error) {
	key, err := x509.ParsePKCS1PrivateKey(rec.KeyBytes)
	if err != nil {
		return nil, "", err
	}
	kid := rec.Kid
	if kid == "" {
		kid = rec.KeyName
	}
	return key, kid, nil
}

// findLatestActiveSigningRec returns the newest active record for keyName that
// carries private-key material. It returns ErrKeyNotFound when none qualifies,
// logging a loud ERROR (issuer + remedy) whenever the only candidates were
// filtered out because they are suspended or revoked.
func (s *KeyService) findLatestActiveSigningRec(ctx context.Context, keyName string) (*interfaces.JwkKeyRec, error) {
	recs, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		return nil, err
	}

	latest, sawInactiveSigningKey := latestActiveSigningRec(recs)
	if latest == nil {
		if sawInactiveSigningKey {
			ksLog.Error("No active signing key for issuer; all signing keys are suspended or revoked",
				"issuer", keyName,
				"remedy", "rotate a new key or reactivate a suspended key")
		}
		return nil, interfaces.ErrKeyNotFound
	}
	return latest, nil
}

// latestActiveSigningRec picks the newest active record carrying private-key
// material from recs. sawInactive reports whether at least one signing-capable
// record was skipped solely because it is suspended or revoked — this
// distinguishes "this keyName has a signing key that is currently disabled" from
// "this keyName has no signing material at all" (e.g. a verification-only
// external record). Pure: no I/O and no logging, so callers that use it as a
// predicate incur no side effects (ADR 0028).
func latestActiveSigningRec(recs []*interfaces.JwkKeyRec) (latest *interfaces.JwkKeyRec, sawInactive bool) {
	for _, rec := range recs {
		if len(rec.KeyBytes) == 0 {
			continue // public/external-only record has no private material to sign with
		}
		if !rec.IsActive() {
			sawInactive = true
			continue
		}
		if latest == nil || rec.Id > latest.Id {
			latest = rec
		}
	}
	return latest, sawInactive
}

// SetKeyStatus applies a lifecycle transition to the record(s) under keyName.
// When kid is non-empty only that record is affected and it must belong to
// keyName (otherwise ErrKeyNotFound). Transition rules (ADR 0028):
//   - status must be active/suspended/revoked (else ErrKeyStatusInvalid).
//   - revoked is terminal: a target already revoked may only be re-asserted
//     revoked (idempotent); any other requested status yields ErrKeyStatusTerminal.
//   - active clears SuspendedAt (reactivation); revoked/suspended are not signing
//     candidates thereafter.
//
// It returns the refreshed KeySummary and a non-empty warning when the
// transition leaves keyName with zero active signing keys (the operation still
// succeeds — subsequent signing attempts fail loudly, no auto-rotation).
func (s *KeyService) SetKeyStatus(ctx context.Context, keyName string, kid string, status string) (*interfaces.KeySummary, string, error) {
	switch status {
	case interfaces.KeyStatusActive, interfaces.KeyStatusSuspended, interfaces.KeyStatusRevoked:
	default:
		return nil, "", ErrKeyStatusInvalid
	}

	// Resolve the target records and enforce the kid-belongs-to-keyName rule.
	var targets []*interfaces.JwkKeyRec
	if kid != "" {
		rec, err := s.keyDAO.FindByKid(ctx, kid)
		if err != nil {
			return nil, "", err // ErrKeyNotFound propagates as 404
		}
		if rec.KeyName != keyName {
			return nil, "", interfaces.ErrKeyNotFound
		}
		targets = []*interfaces.JwkKeyRec{rec}
	} else {
		recs, err := s.keyDAO.FindByKeyName(ctx, keyName)
		if err != nil {
			return nil, "", err
		}
		if len(recs) == 0 {
			return nil, "", interfaces.ErrKeyNotFound
		}
		targets = recs
	}

	// Terminal guard: revoked is terminal, so a move away from revoked is refused
	// only when NO target can actually transition — an explicitly targeted revoked
	// kid, or a keyName-wide op whose every record is already revoked. When a
	// keyName-wide op still has at least one non-revoked record, the already-revoked
	// siblings are left untouched in their terminal state and the transition applies
	// to the rest; revoked wins over any stamp later written to those records, so the
	// op is a no-op on them (ADR 0028).
	if status != interfaces.KeyStatusRevoked {
		allRevoked := true
		for _, rec := range targets {
			if !rec.IsRevoked() {
				allRevoked = false
				break
			}
		}
		if allRevoked {
			return nil, "", ErrKeyStatusTerminal
		}
	}

	now := time.Now().UTC()
	var suspendedAt, revokedAt *time.Time
	switch status {
	case interfaces.KeyStatusActive:
		zero := time.Time{}
		suspendedAt = &zero // reactivation clears suspension
	case interfaces.KeyStatusSuspended:
		suspendedAt = &now
	case interfaces.KeyStatusRevoked:
		revokedAt = &now // write-once in the DAO
	}

	if _, err := s.keyDAO.SetKeyStatus(ctx, keyName, kid, suspendedAt, revokedAt); err != nil {
		return nil, "", err
	}

	// Keep the token-issuer signing key and verification JWKS consistent with
	// the new statuses (drop revoked from verification, re-select the signing
	// key, or surface the no-active-key condition).
	if keyName == s.tokenIssuer {
		s.refreshTokenIssuerKey(ctx)
	}

	summary, err := s.keyDAO.KeySummary(ctx, keyName)
	if err != nil {
		return nil, "", err
	}

	// Warn only when the keyName had signing material but no active key remains.
	// A verification-only keyName (external/public records, no private key) never
	// signs, so a "signing will fail" warning there would be misleading (ADR 0028).
	warning := ""
	if recs, ferr := s.keyDAO.FindByKeyName(ctx, keyName); ferr == nil {
		if latest, sawInactive := latestActiveSigningRec(recs); latest == nil && sawInactive {
			warning = fmt.Sprintf("no active signing key remains for issuer %q; signing will fail until you rotate a new key or reactivate a suspended key", keyName)
			ksLog.Warn(warning, "issuer", keyName)
		}
	}
	return summary, warning, nil
}

// refreshTokenIssuerKey re-derives the cached token signing key and verification
// JWKS after a status change on the token issuer's keyName. It reads the issuer's
// records once and either:
//   - installs the latest active record as the signing key and rebuilds the JWKS
//     around it when one remains; or
//   - clears the signing key (nil) and rebuilds the verification JWKS from the
//     surviving non-revoked records when no active key remains. Revoked kids are
//     dropped (an empty JWKS is the correct result when every record is revoked —
//     the revoked kid must stop verifying); suspended kids are kept so
//     already-issued tokens still verify. Clearing the signing key makes the next
//     issuance fail loudly rather than continuing to sign under a retired/revoked
//     kid (ADR 0028).
//
// A transient DAO read failure leaves the cached key and JWKS untouched so a blip
// does not lock admins out; the next status change or restart retries.
func (s *KeyService) refreshTokenIssuerKey(ctx context.Context) {
	recs, err := s.keyDAO.FindByKeyName(ctx, s.tokenIssuer)
	if err != nil {
		ksLog.Error("Failed to reload token issuer keys after status change",
			"issuer", s.tokenIssuer, "error", err)
		return
	}

	signingRec, _ := latestActiveSigningRec(recs)
	var signingKey *rsa.PrivateKey
	signingKid := ""
	if signingRec != nil {
		key, kid, perr := parseSigningRec(signingRec)
		if perr != nil {
			ksLog.Error("Failed to parse re-selected token signing key",
				"issuer", s.tokenIssuer, "error", perr)
			return
		}
		signingKey, signingKid = key, kid
	}

	// jwksFromRecs returns a (possibly empty) non-nil JWKS, so the revoked-only
	// case replaces the stale verification set instead of leaving the revoked kid
	// verifying. When a signing key remains its kid is force-matched to it.
	jwks := jwksFromRecs(recs, signingKey, signingKid)
	s.tokenKey = signingKey
	s.tokenKid = signingKid
	s.tokenPubKey = jwks
	s.authIssuer.UpdateTokenKey(s.tokenIssuer, signingKid, signingKey, jwks)

	if signingRec == nil {
		ksLog.Warn("Token issuer has no active signing key after status change; issuance will fail until you rotate or reactivate",
			"issuer", s.tokenIssuer)
	}
}

// GetPublicJWKS returns the JWKS JSON for the public keys associated with keyName.
func (s *KeyService) GetPublicJWKS(ctx context.Context, keyName string) *json.RawMessage {
	keys, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		ksLog.Error("Error retrieving keys", "keyName", keyName, "error", err)
		return nil
	}

	jwkstore := jwkset.NewMemoryStorage()

	for _, rec := range keys {
		// Revoked keys are excluded from JWKS immediately; suspended keys stay
		// published so already-issued tokens still verify (ADR 0028).
		if rec.IsRevoked() {
			continue
		}
		var jwkSet jwkset.JWK
		var err error
		if rec.ReceiverJwksUrl != "" {
			// key is an external key fetch the jwks and convert so it can be added to jwkstore
			srvLog.Debug("Fetching JWK from server", "url", rec.ReceiverJwksUrl)
			var jwksExtern *keyfunc.JWKS
			jwksExtern, err = goSet.GetJwks(rec.ReceiverJwksUrl)
			if err != nil {
				ksLog.Error("Error fetching JWKS from server", "url", rec.ReceiverJwksUrl, "error", err)
				continue
			}

			// Convert keyfunc.JWKS to jwkset.JWK and add to jwkstore
			rawJWKS := jwksExtern.RawJWKS()

			var jwksData struct {
				Keys []json.RawMessage `json:"keys"`
			}
			if err = json.Unmarshal(rawJWKS, &jwksData); err != nil {
				ksLog.Error("Error unmarshaling JWKS", "error", err)
				continue
			}

			for _, keyData := range jwksData.Keys {
				jwkSet, err = jwkset.NewJWKFromRawJSON(keyData, jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
				if err != nil {
					ksLog.Error("Error creating JWK from raw JSON", "error", err)
					continue
				}
				err = jwkstore.KeyWrite(context.Background(), jwkSet)
				if err != nil {
					ksLog.Error("Error adding external key to JWKS", "error", err)
				}
			}
			continue

		} else {
			pubKey, err := x509.ParsePKCS1PublicKey(rec.PubKeyBytes)
			if err != nil {
				ksLog.Error("Error parsing public key", "kid", rec.Kid, "error", err)
				continue
			}

			kid := rec.Kid
			if kid == "" {
				kid = rec.KeyName
			}

			metadata := jwkset.JWKMetadataOptions{
				KID: kid,
			}
			if rec.Use == "enc" {
				metadata.USE = jwkset.UseEnc
			} else {
				metadata.USE = jwkset.UseSig
			}
			jwkOptions := jwkset.JWKOptions{
				Metadata: metadata,
			}

			jwkSet, err = jwkset.NewJWKFromKey(pubKey, jwkOptions)
			if err != nil {
				ksLog.Error("Error parsing rsa key into jwk", "error", err)
				continue
			}
			err = jwkstore.KeyWrite(context.Background(), jwkSet)
			if err != nil {
				ksLog.Error("Error adding key to JWKS", "kid", kid, "error", err)
			}
		}

	}

	response, err := jwkstore.JSONPublic(context.Background())
	if err != nil {
		ksLog.Error("Error creating JWKS response", "error", err)
		return nil
	}

	return &response
}

func (s *KeyService) getInternalPublicJWKS(ctx context.Context, keyName string) *keyfunc.JWKS {
	return s.buildAuthJWKS(ctx, keyName, nil, "")
}

// buildAuthJWKS constructs a keyfunc.JWKS from all stored public keys for keyName.
// When signingKey/signingKid are provided, the map entry for signingKid is always
// set to signingKey's public component — overriding whatever the DB returned for
// that kid. This guarantees that the signing private key and the verification
// public key in the returned JWKS are always a matched pair, even when a concurrent
// cluster node has inserted a different key with the same kid.
func (s *KeyService) buildAuthJWKS(ctx context.Context, keyName string, signingKey *rsa.PrivateKey, signingKid string) *keyfunc.JWKS {
	keys, err := s.keyDAO.FindByKeyName(ctx, keyName)
	if err != nil {
		ksLog.Error("Error retrieving keys", "keyName", keyName, "error", err)
		return nil
	}

	if len(keys) == 0 && signingKey == nil {
		ksLog.Error("No keys found", "keyName", keyName)
		return nil
	}

	jwks := jwksFromRecs(keys, signingKey, signingKid)
	if len(jwks.KIDs()) == 0 {
		ksLog.Error("No valid keys found", "keyName", keyName)
		return nil
	}
	return jwks
}

// jwksFromRecs builds a verification JWKS from recs, excluding revoked records
// (suspended keys stay published so already-issued tokens still verify — ADR
// 0028). When signingKey/signingKid are supplied, that kid's entry is forced to
// signingKey's public half regardless of what the store held, guaranteeing the
// signing private key and its published verification key are a matched pair even
// when a concurrent cluster node inserted a different record under the same kid.
// Unlike buildAuthJWKS it returns a (possibly empty) non-nil JWKS, so a caller
// can install an empty verification set to stop a revoked kid from verifying.
func jwksFromRecs(recs []*interfaces.JwkKeyRec, signingKey *rsa.PrivateKey, signingKid string) *keyfunc.JWKS {
	// Copy before sorting so the caller's slice (which it may still be iterating)
	// is not mutated. Oldest-first so that when records share a kid the newest
	// public key overwrites older ones in the map — matching signing selection.
	sorted := make([]*interfaces.JwkKeyRec, len(recs))
	copy(sorted, recs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Id < sorted[j].Id
	})

	givenKeys := make(map[string]keyfunc.GivenKey)
	for _, rec := range sorted {
		if rec.IsRevoked() {
			continue
		}
		pubKey, err := x509.ParsePKCS1PublicKey(rec.PubKeyBytes)
		if err != nil {
			ksLog.Error("Error parsing public key", "kid", rec.Kid, "error", err)
			continue
		}

		kid := rec.Kid
		if kid == "" {
			kid = rec.KeyName
		}

		givenKeys[kid] = keyfunc.NewGivenRSA(pubKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
	}

	if signingKey != nil && signingKid != "" {
		givenKeys[signingKid] = keyfunc.NewGivenRSA(&signingKey.PublicKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
	}

	return keyfunc.NewGiven(givenKeys)
}

// ListKeyNames returns the distinct keyName values in the key store.
func (s *KeyService) ListKeyNames(ctx context.Context) ([]string, error) {
	return s.keyDAO.ListKeyNames(ctx)
}

// GetKeyIds returns all kid values in the key store.
func (s *KeyService) GetKeyIds(ctx context.Context) ([]string, error) {
	return s.keyDAO.ListKids(ctx)
}

// ListSummaries returns key summaries for all keys without exposing key material.
func (s *KeyService) ListSummaries(ctx context.Context) ([]interfaces.KeySummary, error) {
	return s.keyDAO.ListSummaries(ctx)
}

// GetKeySummary returns the summary for a specific kid.
func (s *KeyService) GetKeySummary(ctx context.Context, kid string) (*interfaces.KeySummary, error) {
	return s.keyDAO.KeySummary(ctx, kid)
}

// DeleteKey removes the key with the given kid.
func (s *KeyService) DeleteKey(ctx context.Context, kid string) error {
	return s.keyDAO.DeleteByKid(ctx, kid)
}

// GetPrivateKeyByKid retrieves a private key by its kid.
func (s *KeyService) GetPrivateKeyByKid(ctx context.Context, kid string) (*rsa.PrivateKey, error) {
	rec, err := s.keyDAO.FindByKid(ctx, kid)
	if err != nil {
		return nil, err
	}

	if len(rec.KeyBytes) == 0 {
		return nil, errors.New("no private key found for: " + kid)
	}

	return x509.ParsePKCS1PrivateKey(rec.KeyBytes)
}

// GetAuthValidatorPubKey returns the JWKS used to validate auth tokens issued by this server.
func (s *KeyService) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return s.tokenPubKey
}

// GetAuthIssuer returns the AuthIssuer used for signing auth tokens.
func (s *KeyService) GetAuthIssuer() *authSupport.AuthIssuer {
	return s.authIssuer
}

// StoreExternalKey stores a reference to an external JWKS URL for a receiver or encryption target.
// keyName identifies the entity (e.g. audience/receiver name), use is "sig" or "enc".
func (s *KeyService) StoreExternalKey(ctx context.Context, keyName string, kids []string, streamID string, use string, jwksUri string) error {
	kid := keyName
	if kids != nil && len(kids) > 0 {
		kid = kids[0]
	}
	keyPairRec := &interfaces.JwkKeyRec{
		Id:              ids.NewObjectID(),
		KeyName:         keyName,
		Kid:             kid,
		Use:             use,
		StreamId:        streamID,
		ReceiverJwksUrl: jwksUri,
	}
	return s.keyDAO.Insert(ctx, keyPairRec)
}

// GetKeyByStreamID retrieves the key record associated with a stream.
func (s *KeyService) GetKeyByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	return s.keyDAO.FindByStreamID(ctx, streamID)
}
