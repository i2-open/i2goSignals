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
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
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
	givenKey := keyfunc.NewGivenRSA(&publicKey, keyfunc.GivenKeyOptions{
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
		Id:            bson.NewObjectID(),
		ProjectIds:    []string{"abc", "def"},
		AllowedScopes: []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery},
		Email:         "test@example.com",
		Description:   "Test auth_token",
	}, "abc", true, "")
	if err != nil {
		fmt.Printf("Failed to issue stream client token: %s\n", err.Error())
		os.Exit(-1)
	}
	streamToken, err := auth.IssueStreamToken("1", "abc", nil)
	if err != nil {
		fmt.Printf("Failed to issue stream event token: %s\n", err.Error())
		os.Exit(-1)
	}

	streamTokenBad, err := altAuth.IssueStreamToken("1", "abc", nil)
	if err != nil {
		fmt.Printf("Failed to issue alt stream event token: %s\n", err.Error())
		os.Exit(-1)
	}

	expiredToken, err := auth.generateTestToken(time.Now(), []string{authSupport.ScopeEventDelivery}, "abc", "123")
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
		Roles            []string
		Scope            string
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
				Roles:            []string{authSupport.ScopeEventDelivery},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test authorize multi scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Roles:            []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test eauthorize bad scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Roles:            []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "1234",
				scopesAccepted: []string{authSupport.ScopeStreamAdmin},
			},
			want: false,
		},
		{
			name: "Test event bad stream",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "a123",
				Roles:            []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt},
				ClientId:         "aaa",
				RegisteredClaims: standardClaims,
			},
			args: args{
				streamId:       "4321",
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &authSupport.EventAuthToken{
				StreamIds:        tt.fields.StreamIds,
				ProjectId:        tt.fields.ProjectId,
				Roles:            tt.fields.Roles,
				Scope:            tt.fields.Scope,
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
		Roles            []string
		Scope            string
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
				Roles:            []string{"wrong"},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: false,
		},
		{
			name: "Test good single scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Roles:            []string{authSupport.ScopeEventDelivery},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test good multi scope",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Roles:            []string{"bleh", authSupport.ScopeEventDelivery},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test root super power",
			fields: fields{
				StreamIds:        []string{"1234"},
				ProjectId:        "1234",
				Roles:            []string{authSupport.ScopeRoot},
				ClientId:         "1234",
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test OAuth scope single",
			fields: fields{
				Scope:            authSupport.ScopeEventDelivery,
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test OAuth scope multi",
			fields: fields{
				Scope:            "bleh " + authSupport.ScopeEventDelivery,
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
		{
			name: "Test OAuth scope root",
			fields: fields{
				Scope:            authSupport.ScopeRoot,
				RegisteredClaims: standardClaims,
			},
			args: args{
				scopesAccepted: []string{authSupport.ScopeEventDelivery},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &authSupport.EventAuthToken{
				StreamIds:        tt.fields.StreamIds,
				ProjectId:        tt.fields.ProjectId,
				Roles:            tt.fields.Roles,
				Scope:            tt.fields.Scope,
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

	authCtx, stat := auth.ValidateAuthorizationAny(testRequest, []string{authSupport.ScopeStreamAdmin})
	assert.Equal(t1, 200, stat, "Should be status 200")

	projId2 := authCtx.ProjectId
	fmt.Println("ProjectID2:\t" + projId2)

	assert.Equal(t1, projId1, projId2, "Client token id and authctx id are equal")

	newIat, err := auth.IssueProjectIat(authCtx)
	assert.NoError(t1, err, "New IAT issued with projectid")

	testRequest2, err := http.NewRequest(http.MethodGet, "http://example.com/iat", nil)
	testRequest2.Header.Set("Authorization", "Bearer "+newIat)

	authCtx2, stat := auth.ValidateAuthorizationAny(testRequest2, []string{authSupport.ScopeRegister})
	assert.Equal(t1, 200, stat, "Should be status 200")

	fmt.Println("ProjectID3:\t" + authCtx2.ProjectId)

	assert.Equal(t1, projId1, authCtx2.ProjectId, "ProjectId shoudl all be same")

	regUrl := "http://example.com/register"
	clientReg := model.RegisterParameters{
		Scopes:      []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
		Email:       "joe@example.com",
		Description: "just another test",
	}
	regBytes, _ := json.Marshal(&clientReg)
	testRequest3, err := http.NewRequest(http.MethodPost, regUrl, bytes.NewReader(regBytes))
	testRequest3.Header.Set("Authorization", "Bearer "+newIat)

	authCtx3, stat := auth.ValidateAuthorizationAny(testRequest3, []string{authSupport.ScopeRegister})
	assert.Equal(t1, 200, stat, "Should be status 200")
	assert.NotNil(t1, authCtx3, "Should be authenticated")

	fmt.Println("ProjectID4:\t" + authCtx3.ProjectId)

}

func TestParseAuthToken(t *testing.T) {

	tests := []struct {
		name        string
		tokenString string
		want        func(token *authSupport.EventAuthToken) bool
		wantErr     bool
	}{
		{
			name:        "Straight parse iat",
			tokenString: testTokens.iat,
			want: func(token *authSupport.EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Roles[0] == authSupport.ScopeRegister &&
					len(token.Roles) == 1 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Straight parse client",
			tokenString: testTokens.client,
			want: func(token *authSupport.EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Roles[0] == authSupport.ScopeStreamAdmin &&
					len(token.Roles) == 2 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Straight parse stream",
			tokenString: testTokens.streamToken,
			want: func(token *authSupport.EventAuthToken) bool {
				return token != nil &&
					token.ProjectId != "" &&
					token.Roles[0] == authSupport.ScopeEventDelivery &&
					len(token.Roles) == 1 &&
					strings.EqualFold(auth.TokenIssuer, token.Issuer)
			},
			wantErr: false,
		},
		{
			name:        "Parse stream token bad",
			tokenString: testTokens.altStreamToken,
			want: func(token *authSupport.EventAuthToken) bool {
				return token == nil // token should have crypto error and result should be nil
			},
			wantErr: true,
		},
		{
			name:        "Parse stream token expired",
			tokenString: testTokens.expToken,
			want: func(token *authSupport.EventAuthToken) bool {
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
				scopes: []string{authSupport.ScopeEventDelivery},
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
				scopes: []string{authSupport.ScopeStreamMgmt},
			},
			want:  nil,
			want1: http.StatusForbidden,
		},
		{
			name: "Test event expired token",

			args: args{
				r:      reqWithVars2,
				scopes: []string{authSupport.ScopeEventDelivery},
			},
			want:  nil,
			want1: http.StatusUnauthorized,
		},
		{
			name: "Test event no authorization",

			args: args{
				r:      reqWithVars3,
				scopes: []string{authSupport.ScopeEventDelivery},
			},
			want:  nil,
			want1: http.StatusUnauthorized,
		},
		{
			name: "Test event good stream query",

			args: args{
				r:      testRequest4,
				scopes: []string{authSupport.ScopeEventDelivery},
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
			got, got1 := auth.ValidateAuthorizationAny(tt.args.r, tt.args.scopes)
			if got1 != tt.want1 {
				t.Errorf("ValidateAuthorization() got1 = %v, want %v", got1, tt.want1)
			}
			if got != nil && got.IsOAuthClient == true {
				t.Errorf("ValidateAuthorization() IsOAuth got = %v, want %v", true, false)
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
	claims := authSupport.OidcClaims{
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

	// Point I2SIG_AUTH_OAUTH_SERVERS to the discovery endpoint

	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")

	// Reset caches on issuer
	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil

	// Create an OAuth token with role that maps to authSupport.ScopeEventDelivery
	tok := mintOAuthToken(t, priv, kid, []string{authSupport.ScopeEventDelivery})

	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorizationAny, got %d", code)
	}
	if got == nil || got.StreamId != "1" {
		t.Fatalf("expected non-nil AuthContext with StreamId=1, got %+v", got)
	}
	if got.IsOAuthClient != true {
		t.Fatalf("expected AuthContext with isOAuthClient=true, got %+v", got)
	}

}

func TestValidateAuthorization_withOAuthFallback_success(t *testing.T) {
	srv, kid, priv := startOIDCTestServer(t)
	defer srv.Close()

	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")

	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil

	// Token signed with external key (not local), so local ParseAuthToken should fail
	tok := mintOAuthToken(t, priv, kid, []string{authSupport.ScopeEventDelivery})

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/events/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorization via OAuth fallback, got %d", code)
	}
	if got == nil || got.StreamId != "1" {
		t.Fatalf("expected non-nil AuthContext with StreamId=1, got %+v", got)
	}
	if got.IsOAuthClient != true {
		t.Fatalf("expected AuthContext with isOAuthClient=true, got %+v", got)
	}
}

func Test_oidcRolesMatchScopes(t *testing.T) {
	cases := []struct {
		roles  []string
		scopes []string
		want   bool
	}{
		{[]string{"stream"}, []string{authSupport.ScopeStreamMgmt}, true},
		{[]string{"EVENT"}, []string{authSupport.ScopeEventDelivery}, true},
		{[]string{"root"}, []string{"anything"}, true},
		{[]string{"viewer"}, []string{authSupport.ScopeStreamAdmin}, false},
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

	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")

	auth.OAuthServer = nil
	auth.mu.Lock()
	auth.OAuthPubKeys = nil
	auth.mu.Unlock()

	tok := mintOAuthToken(t, priv, kid, []string{"viewer"})
	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	got, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeStreamMgmt})
	if code != http.StatusForbidden || got != nil {
		t.Fatalf("expected Unauthorized with nil context, got code=%d ctx=%+v", code, got)
	}
}

func TestValidateAuthorizationAny_DynamicKeys(t *testing.T) {
	// Generate a new key and token
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating rsa key: %v", err)
	}
	pub := &priv.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := []byte{0x01, 0x00, 0x01}
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	kid := "dynamic-kid"

	var mu sync.Mutex
	hasKey := false
	var jwksURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			disc := map[string]string{"jwks_uri": jwksURL}
			_ = json.NewEncoder(w).Encode(disc)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			currentHasKey := hasKey
			mu.Unlock()
			jwks := map[string]any{
				"keys": []map[string]string{},
			}
			if currentHasKey {
				jwks["keys"] = []map[string]string{
					{
						"kty": "RSA",
						"kid": kid,
						"use": "sig",
						"alg": "RS256",
						"n":   n,
						"e":   e,
					},
				}
			}
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	jwksURL = srv.URL + "/jwks"

	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")

	// Reset caches on issuer
	auth.OAuthServer = nil
	auth.mu.Lock()
	auth.OAuthPubKeys = nil
	auth.mu.Unlock()

	tok := mintOAuthToken(t, priv, kid, []string{authSupport.ScopeEventDelivery})
	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	// 1. Initial attempt - key is missing in JWKS
	_, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (Service Unavailable) from ValidateAuthorizationAny when key is missing (refresh in progress), got %d", code)
	}

	// 2. Enable key in OIDC server
	mu.Lock()
	hasKey = true
	mu.Unlock()

	// 3. Second attempt - key should be picked up via RefreshUnknownKID
	// Need to wait for RefreshRateLimit (which I set to 1s in the code for testing? No, I should use a smaller value in the test if possible, or just wait)
	time.Sleep(1200 * time.Millisecond)
	_, code = auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorizationAny after key is enabled, got %d", code)
	}
}

// TestValidateAuthorizationAny_WaitsForJWKSRefresh is a regression test for issue #115.
// When keyfunc reports an unknown kid, validateOAuthToken must briefly wait for the
// in-flight background JWKS refresh to land before returning 503. The kid becomes
// available mid-grace; validation must observe it and return 200.
func TestValidateAuthorizationAny_WaitsForJWKSRefresh(t *testing.T) {
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	encodeKey := func(pub *rsa.PublicKey, kid string) map[string]string {
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := []byte{0x01, 0x00, 0x01}
		e := base64.RawURLEncoding.EncodeToString(eBytes)
		return map[string]string{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e,
		}
	}

	const oldKid = "old-kid"
	const newKid = "new-kid"

	var mu sync.Mutex
	includeNew := false
	var jwksURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": jwksURL})
		case "/jwks":
			mu.Lock()
			showNew := includeNew
			mu.Unlock()
			keys := []map[string]string{encodeKey(&priv1.PublicKey, oldKid)}
			if showNew {
				keys = append(keys, encodeKey(&priv2.PublicKey, newKid))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	jwksURL = srv.URL + "/jwks"

	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv.URL+"/.well-known/openid-configuration")

	auth.OAuthServer = nil
	auth.mu.Lock()
	auth.OAuthPubKeys = nil
	auth.mu.Unlock()

	// The new kid lands on the JWKS endpoint partway through the grace window,
	// mimicking a Keycloak that finishes coming up shortly after the request arrives.
	go func() {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		includeNew = true
		mu.Unlock()
	}()

	tok := mintOAuthToken(t, priv2, newKid, []string{authSupport.ScopeEventDelivery})
	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Authorization", "Bearer "+tok)

	start := time.Now()
	_, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	elapsed := time.Since(start)
	if code != http.StatusOK {
		t.Fatalf("expected 200 after JWKS refresh grace, got %d (elapsed %v)", code, elapsed)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("expected validation to wait for refresh, returned in %v", elapsed)
	}
}

func TestAuthIssuer_TokenKid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	issuer := "test-issuer"
	kid := "test-kid"

	a := &AuthIssuer{
		TokenIssuer: issuer,
		TokenKid:    kid,
		PrivateKey:  privateKey,
	}

	tokenString, err := a.IssueStreamToken("stream1", "proj1", nil)
	assert.NoError(t, err)

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	assert.NoError(t, err)

	assert.Equal(t, kid, token.Header["kid"])
	assert.Equal(t, issuer, token.Claims.(jwt.MapClaims)["iss"])
}

func TestAuthIssuer_TokenKidFallback(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	issuer := "test-issuer"

	a := &AuthIssuer{
		TokenIssuer: issuer,
		PrivateKey:  privateKey,
	}

	tokenString, err := a.IssueStreamToken("stream1", "proj1", nil)
	assert.NoError(t, err)

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	assert.NoError(t, err)

	assert.Equal(t, issuer, token.Header["kid"])
	assert.Equal(t, issuer, token.Claims.(jwt.MapClaims)["iss"])
}
func (a *AuthIssuer) generateTestToken(exp time.Time, scopes []string, projectId string, clientId string) (string, error) {
	a.mu.RLock()
	issuer := a.TokenIssuer
	kid := a.TokenKid
	if kid == "" {
		kid = issuer
	}
	privateKey := a.PrivateKey
	a.mu.RUnlock()

	eat := authSupport.EventAuthToken{
		ProjectId: projectId,
		Roles:     scopes,
		ClientId:  clientId,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{issuer},
			Issuer:    issuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = kid

	return token.SignedString(privateKey)
}

func TestValidateAuthorizationAny_PartialOAuthFailure(t *testing.T) {
	// 1. Setup a working OIDC server
	srv1, kid1, priv1 := startOIDCTestServer(t)
	defer srv1.Close()

	// 2. Setup a failing OIDC server (returns 500)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv2.Close()

	// Configure both servers
	t.Setenv("I2SIG_AUTH_OAUTH_SERVERS", srv1.URL+"/.well-known/openid-configuration,"+srv2.URL+"/.well-known/openid-configuration")

	// Reset caches on issuer
	auth.mu.Lock()
	auth.OAuthServer = nil
	auth.OAuthPubKeys = nil
	auth.mu.Unlock()

	// Create a token from a THIRD (not configured) source to ensure it fails validation
	priv3, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok3 := mintOAuthToken(t, priv3, "kid3", []string{authSupport.ScopeEventDelivery})

	req, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req.Header.Set("Authorization", "Bearer "+tok3)

	// Should return 503 because one server failed to load
	_, code := auth.ValidateAuthorizationAny(req, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from ValidateAuthorizationAny when partial load fails, got %d", code)
	}

	// Now try a token from the WORKING server (srv1)
	tok1 := mintOAuthToken(t, priv1, kid1, []string{authSupport.ScopeEventDelivery})
	req1, _ := http.NewRequest(http.MethodGet, "http://example/streams/1", nil)
	req1.Header.Set("Authorization", "Bearer "+tok1)

	// Should return 200 because it validated successfully even if other server failed to load
	_, code = auth.ValidateAuthorizationAny(req1, []string{authSupport.ScopeEventDelivery})
	if code != http.StatusOK {
		t.Fatalf("expected 200 from ValidateAuthorizationAny for valid token even with partial load failure, got %d", code)
	}
}
