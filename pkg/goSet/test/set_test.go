package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	model2 "github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"testing"
)

var testStream model2.StreamConfiguration = model2.StreamConfiguration{
	Id:              primitive.NewObjectID().Hex(),
	Iss:             "TestIssuer",
	Aud:             []string{"TestAudience"},
	EventsSupported: model2.GetSupportedEvents(),
	EventsRequested: model2.GetSupportedEvents(),
	EventsDelivered: model2.GetSupportedEvents(),
	Delivery: &model2.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model2.PollTransmitMethod{
			Method:      model2.DeliveryPoll,
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
	fmt.Println("Testing createStream with 'sub' subject...")
	subject := &goSet.EventSubject{
		SubIdentifier: goSet.SubIdentifier{Sub: "1234"},
	}

	set := goSet.CreateSet(subject, testStream.Iss, testStream.Aud)

	payload_claims := map[string]interface{}{
		"aclaim": "avalue",
	}
	set.AddEventPayload("uri:testevent", payload_claims)

	jsonString := set.String()

	assert.NotContainsf(t, jsonString, "sub_id", "sub_id detected")
	assert.Contains(t, jsonString, "\"sub\"", "sub claim detected")
	fmt.Println("\n", jsonString)

	fmt.Println("Testing createStream with 'sub_id' subject...")
	subject = &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/1234").AddUsername("huntp").AddEmail("phil.hunt@hexa.org"),
	}
	set = goSet.CreateSet(subject, testStream.Iss, testStream.Aud)
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
	fmt.Println("\n", jsonString)

	// No subject
	fmt.Println("Testing createStream with 'nil' subject...")
	set = goSet.CreateSet(nil, testStream.Iss, testStream.Aud)
	set.AddEventPayload("uri:testevent", payload_claims)
	jsonString = set.String()

	assert.NotContains(t, jsonString, "sub_id", "sub_id detected")
	assert.NotContains(t, jsonString, "\"sub\"", "sub claim detected")
	fmt.Println("\n", jsonString)

}

/*
TestCreateSet builds on the previous test to also check JWT functionality
*/
func TestCreateSet(t *testing.T) {

	// As CreateSetForStream already calls CreateSet, we do not need to test all variations
	fmt.Println("Testing CreateSet with 'sub_id' subject...")
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "?Users/1234"},
		},
	}
	set := goSet.CreateSet(subject, "TestIssuer", []string{"cluster.example.com", "monitor.example.com"})

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

	assert.Contains(t, claimString, "monitor.example.com", "Contains TestAudience")
	assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Header["alg"])
	assert.Truef(t, set.VerifyAudience("cluster.example.com", false), "Contains audience")
	testSet = &set
}

func TestSetJws(t *testing.T) {
	fmt.Println("Testing SET JWT Signature and Validation...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	kid := testSet.Issuer

	publicKey := privateKey.PublicKey

	// NewGivenRSACustomWithOptions(key *rsa.PublicKey, options GivenKeyOptions) (givenKey GivenKey
	givenKey := keyfunc.NewGivenRSACustomWithOptions(&publicKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})

	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		kid: givenKey,
	})

	signString, err := testSet.JWS(jwt.SigningMethodRS256, privateKey)
	assert.Nil(t, err, "Signing is error free")
	fmt.Println("Signed value")
	fmt.Println(signString)

	newSet, err := goSet.Parse(signString, jwks)
	assert.Nil(t, err, "Assert that token was valid and parsed")
	if err != nil {
		fmt.Println("Parsed Signed token")
		println(newSet.String())
	}

	assert.Truef(t, newSet.VerifyAudience("cluster.example.com", false), "Contains audience")

	unsignedString, err := testSet.JWS(jwt.SigningMethodNone, nil)
	fmt.Println("Alg=None unsigned value")
	fmt.Println(unsignedString)

	newUnSignedSet, err := goSet.Parse(unsignedString, nil)
	assert.Nil(t, err, "Assert that unsigned token was valid and parsed")
	if err != nil {
		fmt.Println("Parsed Unsigned token")
		println(newUnSignedSet.String())
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
	testToken.Header["kid"] = kid
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

	fmt.Println(set.String())

	set.JWS(nil, privateKey)

}

*/
