package authUtil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type testTokensSet struct {
	iat            string
	client         string
	streamToken    string
	altStreamToken string
	expToken       string
}

var auth = initMockIssuer()
var altAuth = initMockIssuer()

func initMockIssuer() *AuthIssuer {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Unexpected crypto error generating keys: " + err.Error())
		os.Exit(-1)
	}

	publicKey := privateKey.PublicKey
	givenKey := keyfunc.NewGivenRSACustomWithOptions(&publicKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys["tester"] = givenKey

	return &AuthIssuer{
		TokenIssuer: "tester",
		PublicKey:   keyfunc.NewGiven(givenKeys),
		PrivateKey:  privateKey,
	}
}

var testTokens = newTestTokens()

func newTestTokens() testTokensSet {
	iat, err := auth.IssueProjectIat(nil)
	if err != nil {
		fmt.Printf("Failed to issue iat token: %s", err.Error())
		os.Exit(-1)
	}
	client, err := auth.IssueStreamClientToken(model.SsfClient{
		Id:            primitive.NewObjectID(),
		ProjectIds:    []string{"abc", "def"},
		AllowedScopes: []string{ScopeStreamAdmin, ScopeStreamMgmt, ScopeEventDelivery},
		Email:         "test@example.com",
		Description:   "Test auth_token",
	}, "abc", true)
	if err != nil {
		fmt.Printf("Failed to issue stream client token: %s\n", err.Error())
		os.Exit(-1)
	}
	streamToken, err := auth.IssueStreamToken("1", "abc")
	if err != nil {
		fmt.Printf("Failed to issue stream event token: %s\n", err.Error())
		os.Exit(-1)
	}

	streamTokenBad, err := altAuth.IssueStreamToken("1", "abc")
	if err != nil {
		fmt.Printf("Failed to issue alt stream event token: %s\n", err.Error())
		os.Exit(-1)
	}

	expiredToken, err := auth.generateTestToken(time.Now(), []string{ScopeEventDelivery}, "abc", "123")
	if err != nil {
		fmt.Printf("Failed to issue expired token: %s\n", err.Error())
		os.Exit(-1)
	}

	return testTokensSet{
		iat:            iat,
		client:         client,
		streamToken:    streamToken,
		altStreamToken: streamTokenBad,
		expToken:       expiredToken,
	}
}

func TestEventAuthToken_IsAuthorized(t1 *testing.T) {

	standardClaims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 0, 90)),
		Audience:  []string{"DEFAULT"},
		Issuer:    "DEFAULT",
		ID:        goSet.GenerateJti(),
	}

	type fields struct {
		StreamIds        []string
		ProjectId        string
		Scopes           []string
		ClientId         string
		RegisteredClaims jwt.RegisteredClaims
	}
	type args struct {
		streamId       string
		scopesAccepted []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Test authorize simple",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Scopes:           []string{ScopeEventDelivery},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test authorize multi scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Scopes:           []string{ScopeEventDelivery, ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test eauthorize bad scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Scopes:           []string{ScopeEventDelivery, ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{ScopeStreamAdmin},
			},
			want: false,
		},
		{
			name: "Test event bad stream",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Scopes:           []string{ScopeEventDelivery, ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "4321",
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &EventAuthToken{
				StreamIds:        tt.fields.StreamIds,
				ProjectId:        tt.fields.ProjectId,
				Scopes:           tt.fields.Scopes,
				ClientId:         tt.fields.ClientId,
				RegisteredClaims: tt.fields.RegisteredClaims,
			}
			if got := t.IsAuthorized(tt.args.streamId, tt.args.scopesAccepted); got != tt.want {
				t1.Errorf("IsAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventAuthToken_IsScopeMatch(t1 *testing.T) {
	standardClaims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 0, 90)),
		Audience:  []string{"DEFAULT"},
		Issuer:    "DEFAULT",
		ID:        goSet.GenerateJti(),
	}

	type fields struct {
		StreamIds        []string
		ProjectId        string
		Scopes           []string
		ClientId         string
		RegisteredClaims jwt.RegisteredClaims
	}
	type args struct {
		scopesAccepted []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Test wrong scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Scopes:           []string{"wrong"},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: false,
		},
		{
			name: "Test good single scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Scopes:           []string{ScopeEventDelivery},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test good multi scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Scopes:           []string{"bleh", ScopeEventDelivery},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test root super power",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Scopes:           []string{ScopeRoot},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{ScopeEventDelivery},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &EventAuthToken{
				StreamIds:        tt.fields.StreamIds,
				ProjectId:        tt.fields.ProjectId,
				Scopes:           tt.fields.Scopes,
				ClientId:         tt.fields.ClientId,
				RegisteredClaims: tt.fields.RegisteredClaims,
			}
			if got := t.IsScopeMatch(tt.args.scopesAccepted); got != tt.want {
				t1.Errorf("IsScopeMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

/*
*
TestIssueProjectIat tests the ability for a stream mgmt client token to issue a new IAT within the current project
*/
func TestIssueProjectIat(t1 *testing.T) {
	clientToken := testTokens.client
	eat, err := auth.ParseAuthToken(clientToken)
	assert.NoError(t1, err, "Parsing client token was valid")

	projId1 := eat.ProjectId
	fmt.Println("ProjectId1:\t" + projId1)

	testRequest, err := http.NewRequest(http.MethodGet, "http://example.com/iat", nil)
	testRequest.Header.Set("Authorization", "Bearer "+clientToken)

	authCtx, stat := auth.ValidateAuthorization(testRequest, []string{ScopeStreamAdmin})
	assert.Equal(t1, 200, stat, "Should be status 200")

	projId2 := authCtx.ProjectId
	fmt.Println("ProjectID2:\t" + projId2)

	assert.Equal(t1, projId1, projId2, "Client token id and authctx id are equal")

	newIat, err := auth.IssueProjectIat(authCtx)
	assert.NoError(t1, err, "New IAT issued with projectid")

	testRequest2, err := http.NewRequest(http.MethodGet, "http://example.com/iat", nil)
	testRequest2.Header.Set("Authorization", "Bearer "+newIat)

	authCtx2, stat := auth.ValidateAuthorization(testRequest2, []string{ScopeRegister})
	assert.Equal(t1, 200, stat, "Should be status 200")

	fmt.Println("ProjectID3:\t" + authCtx2.ProjectId)

	assert.Equal(t1, projId1, authCtx2.ProjectId, "ProjectId shoudl all be same")

	regUrl := "http://example.com/register"
	clientReg := model.RegisterParameters{
		Scopes:      []string{ScopeStreamAdmin, ScopeStreamMgmt},
		Email:       "joe@example.com",
		Description: "just another test",
	}
	regBytes, _ := json.Marshal(&clientReg)
	testRequest3, err := http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(regBytes))
	testRequest3.Header.Set("Authorization", "Bearer "+newIat)

	authCtx3, stat := auth.ValidateAuthorization(testRequest3, []string{ScopeRegister})
	assert.Equal(t1, 200, stat, "Should be status 200")
	assert.NotNil(t1, authCtx3, "Should be authenticated")

	fmt.Println("ProjectID4:\t" + authCtx3.ProjectId)

}

func TestParseAuthToken(t *testing.T) {

	tests := []struct {
		name        string
		tokenString string
		want        func(token *EventAuthToken) bool
		wantErr     bool
	}{
		{
			name:        "Straight parse iat",
			tokenString: testTokens.iat,
			want: func(token *EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Scopes[0] == ScopeRegister &&
					len(token.Scopes) == 1 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Straight parse client",
			tokenString: testTokens.client,
			want: func(token *EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Scopes[0] == ScopeStreamAdmin &&
					len(token.Scopes) == 2 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Straight parse stream",
			tokenString: testTokens.streamToken,
			want: func(token *EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Scopes[0] == ScopeEventDelivery &&
					len(token.Scopes) == 1 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Parse stream token bad",
			tokenString: testTokens.altStreamToken,
			want: func(token *EventAuthToken) bool {
				return token == nil // token should have crypto error and result should be nil
			},
			wantErr: true,
		},
		{
			name:        "Parse stream token expired",
			tokenString: testTokens.expToken,
			want: func(token *EventAuthToken) bool {
				return token == nil // token should have crypto error and result should be nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.ParseAuthToken(tt.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAuthToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.want(got) {
				t.Error("ParseAuthToken() got = false, want true")
			}
		})
	}
}

func TestValidateAuthorization(t *testing.T) {

	testRequest, err := http.NewRequest(http.MethodPost, "http://example.com/events/1", nil)
	testRequest.Header.Set("Authorization", "Bearer "+testTokens.streamToken)
	if err != nil {
		t.Fatal(err.Error())
	}
	vars := map[string]string{
		"id": "1",
	}
	reqWithVars := mux.SetURLVars(testRequest, vars)

	testRequest2, err := http.NewRequest(http.MethodPost, "http://example.com/events/1", nil)
	testRequest2.Header.Set("Authorization", "Bearer "+testTokens.expToken)
	reqWithVars2 := mux.SetURLVars(testRequest2, vars)

	testRequest3, err := http.NewRequest(http.MethodPost, "http://example.com/events/1", nil)
	reqWithVars3 := mux.SetURLVars(testRequest3, vars)

	testRequest4, err := http.NewRequest(http.MethodPost, "http://example.com/streams?stream_id=1", nil)
	testRequest4.Header.Set("Authorization", "Bearer "+testTokens.streamToken)

	streamEat, err := auth.ParseAuthToken(testTokens.streamToken)

	type args struct {
		r      *http.Request
		scopes []string
	}
	tests := []struct {
		name  string
		args  args
		want  *AuthContext
		want1 int
	}{
		{
			name: "Test event good stream",

			args: args{
				r:      reqWithVars,
				scopes: []string{ScopeEventDelivery},
			},
			want: &AuthContext{
				StreamId:  "1",
				ProjectId: "abc",
				Eat:       streamEat,
			},
			want1: 200,
		},
		{
			name: "Test event bad scope",

			args: args{
				r:      reqWithVars,
				scopes: []string{ScopeStreamMgmt},
			},
			want:  nil,
			want1: http.StatusUnauthorized,
		},
		{
			name: "Test event expired token",

			args: args{
				r:      reqWithVars2,
				scopes: []string{ScopeEventDelivery},
			},
			want:  nil,
			want1: http.StatusUnauthorized,
		},
		{
			name: "Test event no authorization",

			args: args{
				r:      reqWithVars3,
				scopes: []string{ScopeEventDelivery},
			},
			want:  nil,
			want1: http.StatusUnauthorized,
		},
		{
			name: "Test event good stream query",

			args: args{
				r:      testRequest4,
				scopes: []string{ScopeEventDelivery},
			},
			want: &AuthContext{
				StreamId:  "1",
				ProjectId: "abc",
				Eat:       streamEat,
			},
			want1: 200,
		},
	}

	/*
		Route{
					"ReceivePushEvent",
					strings.ToUpper("Post"),
					"/events/{id}",
					h.sa.ReceivePushEvent,
					false,
				},
	*/

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := auth.ValidateAuthorization(tt.args.r, tt.args.scopes)
			if got1 != tt.want1 {
				t.Errorf("ValidateAuthorization() got1 = %v, want %v", got1, tt.want1)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateAuthorization() got = %v, want %v", got, tt.want)
			}

		})
	}
}

// --- OAuth/OIDC validation tests for new functionality ---

// helper to spin up a local OIDC discovery + JWKS server for tests
func startOIDCTestServer(t *testing.T) (*httptest.Server, string, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating rsa key: %v", err)
	}
	pub := &priv.PublicKey
	// base64url-encode modulus and exponent
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// exponent is usually 65537
	eBytes := []byte{0x01, 0x00, 0x01} // 65537 big-endian
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	kid := "oauth-kid-1"

	var jwksURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			disc := map[string]string{"jwks_uri": jwksURL}
			_ = json.NewEncoder(w).Encode(disc)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			jwks := map[string]any{
				"keys": []map[string]string{
					{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   n,
						"e":   e,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(handler)
	jwksURL = srv.URL + "/jwks"
	return srv, kid, priv
}

func mintOAuthToken(t *testing.T, priv *rsa.PrivateKey, kid string, roles []string) string {
	t.Helper()
	claims := OidcClaims{
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{Roles: roles},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "http://example-issuer",
			Audience:  []string{"gosignals"},
			ID:        goSet.GenerateJti(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("failed signing oauth token: %v", err)
	}
	return s
}

func TestValidateAuthorizationAny_withOAuthToken_success(t *testing.T) {
	srv, kid, priv := startOIDCTestServer(t)
	defer srv.Close()

	// Point OAUTH_SERVERS to the discovery endpoint
	prev := os.Getenv("OAUTH_SERVERS")
	_ = os.Setenv("OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")
	defer os.Setenv("OAUTH_SERVERS", prev)

	// Reset caches on issuer
	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil

	// Create an OAuth token with role that maps to ScopeEventDelivery
	tok := mintOAuthToken(t, priv, kid, []string{ScopeEventDelivery})

	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorizationAny(req, []string{ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorizationAny, got %d", code)
	}
	if got == nil || got.StreamId != "1" {
		t.Fatalf("expected non-nil AuthContext with StreamId=1, got %+v", got)
	}
}

func TestValidateAuthorization_withOAuthFallback_success(t *testing.T) {
	srv, kid, priv := startOIDCTestServer(t)
	defer srv.Close()

	prev := os.Getenv("OAUTH_SERVERS")
	_ = os.Setenv("OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")
	defer os.Setenv("OAUTH_SERVERS", prev)

	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil

	// Token signed with external key (not local), so local ParseAuthToken should fail
	tok := mintOAuthToken(t, priv, kid, []string{ScopeEventDelivery})

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/events/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorization(req, []string{ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorization via OAuth fallback, got %d", code)
	}
	if got == nil || got.StreamId != "1" {
		t.Fatalf("expected non-nil AuthContext with StreamId=1, got %+v", got)
	}
}

func Test_oidcRolesMatchScopes(t *testing.T) {
	cases := []struct {
		roles  []string
		scopes []string
		want   bool
	}{
		{[]string{"stream"}, []string{ScopeStreamMgmt}, true},
		{[]string{"EVENT"}, []string{ScopeEventDelivery}, true},
		{[]string{"root"}, []string{"anything"}, true},
		{[]string{"viewer"}, []string{ScopeStreamAdmin}, false},
	}
	for _, c := range cases {
		if got := oidcRolesMatchScopes(c.roles, c.scopes); got != c.want {
			t.Fatalf("oidcRolesMatchScopes(%v,%v)=%v want %v", c.roles, c.scopes, got, c.want)
		}
	}
}

func TestValidateAuthorization_oauthRoleMismatch_unauthorized(t *testing.T) {
	srv, kid, priv := startOIDCTestServer(t)
	defer srv.Close()

	prev := os.Getenv("OAUTH_SERVERS")
	_ = os.Setenv("OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")
	defer os.Setenv("OAUTH_SERVERS", prev)

	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil

	tok := mintOAuthToken(t, priv, kid, []string{"viewer"})
	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorizationAny(req, []string{ScopeStreamMgmt})
	if code != http.StatusUnauthorized || got != nil {
		t.Fatalf("expected Unauthorized with nil context, got code=%d ctx=%+v", code, got)
	}
}

func (a *AuthIssuer) generateTestToken(exp time.Time, scopes []string, projectId string, clientId string) (string, error) {
	eat := EventAuthToken{
		ProjectId: projectId,
		Scopes:    scopes,
		ClientId:  clientId,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{a.TokenIssuer},
			Issuer:    a.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
}
