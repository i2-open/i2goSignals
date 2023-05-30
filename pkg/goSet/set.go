package goSet

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/segmentio/ksuid"
)

type UsernameIdentifier struct {
	Username string `json:"username,omitempty"`
}

type ExternalIdentifier struct {
	ExternalId string `json:"externalId,omitempty"`
}

type EmailIdentifier struct {
	Email string `json:"email,omitempty"`
}

type IssuerSubjectIdentifier struct {
	Issuer string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
}

type OpaqueIdentifier struct {
	Id string `json:"id,omitempty"`
}

type PhoneNumberIdentifier struct {
	PhoneNumber string `json:"phone_number,omitempty"`
}

type DecentralizedIdentifier struct {
	Url string `json:"url,omitempty"`
}

type UniformResourceIdentifier struct {
	// Note: this may cause issues as "Uri" is the same JSON attribute as AccountIdentifier Uri
	Uri string `json:"uri,omitempty"`
}

type SubIdentifier struct {
	// This is here to allow top-level sub claim
	Sub string `json:"sub,omitempty"`
}

type EventSubject struct {
	SubIdentifier     // Supports top-level sub claim
	SubjectIdentifier // Used for draft-ietf-secevent-subject-identifier format
}

type SubjectIdentifier struct {
	Format string `json:"format,omitempty"`
	UsernameIdentifier
	EmailIdentifier
	IssuerSubjectIdentifier
	OpaqueIdentifier
	PhoneNumberIdentifier
	DecentralizedIdentifier
	UniformResourceIdentifier
	ExternalIdentifier
}

func (sid *SubjectIdentifier) AddUsername(username string) *SubjectIdentifier {
	sid.Username = username
	return sid
}

func (sid *SubjectIdentifier) AddEmail(email string) *SubjectIdentifier {
	sid.Email = email
	return sid
}

func (sid *SubjectIdentifier) AddExternalId(id string) *SubjectIdentifier {
	sid.ExternalId = id
	return sid
}

func NewScimSubjectIdentifier(path string) *SubjectIdentifier {
	return &SubjectIdentifier{
		Format:                    "scim",
		UniformResourceIdentifier: UniformResourceIdentifier{Uri: path},
	}
}

type SecurityEventToken struct {
	jwt.RegisteredClaims

	TimeOfEvent   *jwt.NumericDate   `json:"toe,omitempty"`
	TransactionId string             `json:"txn,omitempty"`
	SubjectId     *SubjectIdentifier `json:"sub_id,omitempty"`

	Events map[string]interface{} `json:"events"`
}

/*
CreateSet is used to create a SecurityEventToken object that can be used to generate a JWT or JWS token. 'subject'
allows the specification of a "sub" or "sub-id" top-level JWT claim. If 'subject' is nil, no top-level claim is created
which may be useful for OpenID RISC and CAEP events.
*/
func CreateSet(subject *EventSubject, issuer string, audience []string) SecurityEventToken {
	jti := GenerateJti()
	if subject == nil {
		// Assume subject is part of event payload and will
		return SecurityEventToken{
			Events: make(map[string]interface{}),
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       jti,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Issuer:   issuer,
				Audience: audience,
			},
		}
	}
	if subject.Sub != "" {
		// Subject is to be specified using the "sub" claim
		return SecurityEventToken{
			Events: make(map[string]interface{}),
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       jti,
				Subject:  subject.Sub,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Issuer:   issuer,
				Audience: audience,
			},
		}
	}

	// Subject is expressed using the Sub-ID claim
	return SecurityEventToken{
		Events: make(map[string]interface{}),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Issuer:   issuer,
			Audience: audience,
		},
		SubjectId: &subject.SubjectIdentifier,
	}

}

func (set *SecurityEventToken) String() string {

	jsonByte, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		log.Printf("Error encoding token: %s", err.Error())
	}
	return string(jsonByte)
}

func (set *SecurityEventToken) JsonBytes() []byte {
	var jsonBuf bytes.Buffer
	err := json.NewEncoder(&jsonBuf).Encode(set)
	if err != nil {
		log.Printf("Error encoding token: %s", err.Error())
	}
	return jsonBuf.Bytes()
}

func (set *SecurityEventToken) AddEventPayload(eventUri string, eventClaims map[string]interface{}) {
	set.Events[eventUri] = eventClaims
}

func (set *SecurityEventToken) GetEventIds() []string {
	if len(set.Events) == 0 {
		return []string{}
	}

	var keys []string
	for key := range set.Events {
		keys = append(keys, key)
	}
	return keys
}

func (set *SecurityEventToken) JWT() *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, set)
	token.Header["typ"] = "secevent+jwt"
	return token
}

func (set *SecurityEventToken) JWS(signingMethod jwt.SigningMethod, key *rsa.PrivateKey) (string, error) {
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodES256
	}
	token := jwt.NewWithClaims(signingMethod, set)
	token.Header["typ"] = "secevent+jwt"

	// publicKey := key.PublicKey

	// givenKey := keyfunc.NewGivenRSA(&publicKey)

	//	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
	//		"issuer": givenKey,
	//	})

	token.Header["kid"] = set.Issuer
	return token.SignedString(key)
}

func Parse(tokenString string, issuerPublicJwks *keyfunc.JWKS) (*SecurityEventToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SecurityEventToken{}, issuerPublicJwks.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
		return nil, err
	}
	if token.Header["typ"] != "secevent+jwt" {
		log.Printf("token is not a security event type(secevent+jwt)")
		return nil, errors.New("token type is not `secevent+jwt`")
	}

	jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	claimString := string(jsonByte)
	log.Println(claimString)
	if claims, ok := token.Claims.(*SecurityEventToken); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}

func GenerateJti() string {

	// return xid.New().String()
	ksuid.New()
	return ksuid.New().String()
}

func (set *SecurityEventToken) IsBefore(jtiVal []byte) (bool, error) {
	return set.ID < string(jtiVal), nil
}
