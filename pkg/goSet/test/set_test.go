package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	model2 "i2goSignals/internal/model"
	dbProviders "i2goSignals/internal/providers/dbProviders/mongo_provider"
	"i2goSignals/pkg/goSet"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"log"
	"testing"
)

var testStream model2.StreamConfiguration = model2.StreamConfiguration{
	Id:              primitive.NewObjectID().Hex(),
	Iss:             "TestIssuer",
	Aud:             []string{"TestAudience"},
	EventsSupported: dbProviders.GetSupportedEvents(),
	EventsRequested: dbProviders.GetSupportedEvents(),
	EventsDelivered: dbProviders.GetSupportedEvents(),
	Delivery: &model2.OneOfStreamConfigurationDelivery{
		PollDeliveryMethod: &model2.PollDeliveryMethod{
			Method:      "https://schemas.openid.net/secevent/risc/delivery-method/poll",
			EndpointUrl: "/streams/"},
	},
	MinVerificationInterval: 15,
}

var testSet *goSet.SecurityEventToken

/*
TestCreateSetForStream creates a SET using the 3 variabions of subjects (sub, sub_id, and none) using a
streamconfiguration to supply issuer and audience values.
*/
func TestCreateSetForStream(t *testing.T) {
	log.Println("Testing createStream with 'sub' subject...")
	subject := &goSet.EventSubject{
		SubIdentifier: goSet.SubIdentifier{Sub: "1234"},
	}

	set := goSet.CreateSetForStream(subject, testStream)

	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}
	set.AddEventPayload("uri:testevent", payload_claims)

	jsonString := set.String()

	assert.NotContainsf(t, jsonString, "sub_id", "sub_id detected")
	assert.Contains(t, jsonString, "\"sub\"", "sub claim detected")
	log.Println("\n", jsonString)

	log.Println("Testing createStream with 'sub_id' subject...")
	subject = &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/1234").AddUsername("huntp").AddEmail("phil.hunt@hexa.org"),
	}
	set = goSet.CreateSetForStream(subject, testStream)
	set.AddEventPayload("uri:testevent", payload_claims)
	jsonString = set.String()

	jsonBytes := set.JsonBytes()
	var tkn goSet.SecurityEventToken
	err := json.Unmarshal(jsonBytes, &tkn)
	assert.NoError(t, err, "check token bytes parsed")
	compString, err := json.MarshalIndent(tkn, "", "  ")
	assert.NoError(t, err, "Marshalling token")

	assert.Contains(t, jsonString, "sub_id", "sub_id detected")
	assert.NotContains(t, jsonString, "\"sub\"", "sub claim detected")
	assert.Equal(t, jsonString, string(compString), "check that JsonBytes is the same")
	log.Println("\n", jsonString)

	// No subject
	log.Println("Testing createStream with 'nil' subject...")
	set = goSet.CreateSetForStream(nil, testStream)
	set.AddEventPayload("uri:testevent", payload_claims)
	jsonString = set.String()

	assert.NotContains(t, jsonString, "sub_id", "sub_id detected")
	assert.NotContains(t, jsonString, "\"sub\"", "sub claim detected")
	log.Println("\n", jsonString)

}

/*
TestCreateSet builds on the previous test to also check JWT functionality
*/
func TestCreateSet(t *testing.T) {

	// As CreateSetForStream already calls CreateSet, we do not need to test all variations
	log.Println("Testing CreateSet with 'sub_id' subject...")
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "?Users/1234"},
		},
	}
	set := goSet.CreateSet(subject, "TestIssuer", []string{"TestAudience"})

	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}
	set.AddEventPayload("uri:testevent", payload_claims)

	token := set.JWT()

	println("JWT Header:")
	jsonByte, _ := json.MarshalIndent(token.Header, "", "  ")
	headerString := string(jsonByte)
	assert.Contains(t, headerString, "\"secevent+jwt\"", "Header contains correct type")
	println(string(jsonByte))

	println("JWT Claims:")
	jsonByte, _ = json.MarshalIndent(token.Claims, "", "  ")
	claimString := string(jsonByte)
	println(claimString)

	assert.Contains(t, claimString, "\"TestAudience", "Contains TestAudience")
	assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Header["alg"])

	testSet = &set
}

func TestSetJws(t *testing.T) {
	log.Println("Testing SET JWT Signature and Validation...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey

	// NewGivenRSACustomWithOptions(key *rsa.PublicKey, options GivenKeyOptions) (givenKey GivenKey
	givenKey := keyfunc.NewGivenRSACustomWithOptions(&publicKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})

	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		"issuer": givenKey,
	})

	signString, err := testSet.JWS(jwt.SigningMethodRS256, privateKey)
	assert.Nil(t, err, "Signing is error free")
	log.Println("Signed value")
	log.Println(signString)

	newSet, err := goSet.Parse(signString, jwks)
	assert.Nil(t, err, "Assert that token was valid and parsed")
	if err != nil {
		log.Println("Parsed Signed token")
		println(newSet.String())
	}

	altPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	altPublicKey := altPrivateKey.PublicKey

	altGivenKey := keyfunc.NewGivenRSACustomWithOptions(&altPublicKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})

	altJwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		"issuer": altGivenKey,
	})

	// Test with Wrong Public Key
	badSet, err := goSet.Parse(signString, altJwks)
	assert.NotNilf(t, err, "Check not valid")
	assert.IsTypef(t, &jwt.ValidationError{}, err, "Should be a jwt.ValidationError")
	assert.Error(t, err, "Error should be jwt.ValidationError", jwt.ValidationError{})
	assert.Nil(t, badSet, "No set should be returned - wrong key")

	// Test with corrupt signed message
	badSign := signString + "aaaa"
	badSet, err = goSet.Parse(badSign, jwks)
	assert.NotNilf(t, err, "Check not valid")
	assert.IsTypef(t, &jwt.ValidationError{}, err, "Should be a jwt.ValidationError")
	assert.Nil(t, badSet, "No set should be returned - bad signature")

	// Test for a bad token type
	testToken := jwt.NewWithClaims(jwt.SigningMethodRS256, testSet)
	testToken.Header["typ"] = "jwt"
	testToken.Header["kid"] = "issuer"
	badSignText, err := testToken.SignedString(privateKey)

	badSet, err = goSet.Parse(badSignText, jwks)
	assert.Error(t, err, "token type is not `secevent+jwt`")
	assert.Equal(t, err.Error(), "token type is not `secevent+jwt`")
}

/*
func TestSetJws(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	set := CreateSet("1234", "TestIssuer", []string{"TestAudience"})

	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}
	set.AddEventPayload("uri:testevent", payload_claims)

	log.Println(set.String())

	set.JWS(nil, privateKey)

}

*/
