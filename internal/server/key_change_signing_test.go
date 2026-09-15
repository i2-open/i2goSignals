package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

// Issue #313: the node that handles a rotate or a replace, on the create path
// and on the key-load path, signs with the result the next time it signs. Its
// key cache is cleared as part of the change rather than left to expire.

const keyChangeIssuer = "https://key-change-signing.example"

type KeyChangeSigningSuite struct {
	suite.Suite
	app *SignalsApplication
	sid string
}

func TestKeyChangeSigningSuite(t *testing.T) {
	suite.Run(t, new(KeyChangeSigningSuite))
}

func (s *KeyChangeSigningSuite) SetupTest() {
	ctx := context.Background()
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "key-change-signing")
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(ctx, "DEFAULT"))
	_, err = persistence.KeyService.CreateKeyPair(ctx, keyChangeIssuer, "sig", "proj-A")
	s.Require().NoError(err)
	s.app = newTestApplication(persistence)
	s.app.DefIssuer = "DEFAULT"
	s.app.EventRouter = eventRouter.NewRouter(eventRouter.RouterDeps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
	}, "key-change-node")

	// A poll transmitter signing as keyChangeIssuer with one event queued.
	s.sid = "key-change-poll"
	rec := &model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:        s.sid,
			Iss:       keyChangeIssuer,
			Aud:       []string{"https://receiver.example.com"},
			RouteMode: model.RouteModePublish,
			Delivery:  &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: model.StreamStateEnabled,
	}
	s.Require().NoError(persistence.StreamService.PersistStreamStateRecord(ctx, rec))
	stored, err := persistence.StreamService.GetStreamState(ctx, s.sid)
	s.Require().NoError(err)
	s.app.EventRouter.UpdateStreamState(stored)
	token := &goSet.SecurityEventToken{}
	token.ID = "key-change-jti"
	event, err := persistence.EventService.AddEvent(ctx, token, s.sid, "")
	s.Require().NoError(err)
	s.Require().NoError(persistence.EventService.AddEventToStream(ctx, event.Jti, s.sid))
}

func (s *KeyChangeSigningSuite) TearDownTest() {
	if s.app != nil && s.app.EventRouter != nil {
		s.app.EventRouter.Shutdown()
	}
}

func (s *KeyChangeSigningSuite) adminToken() string {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	tok, err := s.app.GetAuth().IssueStreamClientToken(client, "proj-A", true, "")
	s.Require().NoError(err)
	return tok
}

// post issues POST /key/{keyChangeIssuer}?{query} through the CreateKey handler,
// which routes a request with a body to the key-load path.
func (s *KeyChangeSigningSuite) post(query string, body []byte, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/key/issuer?"+query, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.adminToken())
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r = mux.SetURLVars(r, map[string]string{"keyName": keyChangeIssuer})
	rr := httptest.NewRecorder()
	s.app.CreateKey(rr, r)
	return rr
}

// polled polls the transmitter and returns the one SET's kid and whether it
// verifies with pub.
func (s *KeyChangeSigningSuite) polled(pub crypto.PublicKey) (string, bool) {
	sets, _, status := s.app.EventRouter.PollStreamHandler(s.sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	s.Require().Equal(http.StatusOK, status)
	s.Require().Len(sets, 1)
	for _, set := range sets {
		token, _, err := jwt.NewParser().ParseUnverified(set, jwt.MapClaims{})
		s.Require().NoError(err)
		kid, _ := token.Header["kid"].(string)
		_, err = jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(set, func(*jwt.Token) (interface{}, error) { return pub, nil })
		return kid, err == nil
	}
	return "", false
}

// selected is the key the key store signs with now.
func (s *KeyChangeSigningSuite) selected() (crypto.Signer, string) {
	key, kid, err := s.app.KeyService.GetSigner(context.Background(), keyChangeIssuer, "")
	s.Require().NoError(err)
	return key, kid
}

// warm waits until a poll returns the queued event, so this node has the
// current key cached and the event in its poll buffer, and returns the key.
func (s *KeyChangeSigningSuite) warm() (crypto.Signer, string) {
	s.Require().Eventually(func() bool {
		sets, _, status := s.app.EventRouter.PollStreamHandler(s.sid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
		return status == http.StatusOK && len(sets) == 1
	}, 5*time.Second, 10*time.Millisecond, "the queued event reaches the poll buffer")
	key, kid := s.selected()
	got, verifies := s.polled(key.Public())
	s.Require().Equal(kid, got)
	s.Require().True(verifies)
	return key, kid
}

func privateKeyPEM(rr *httptest.ResponseRecorder) crypto.Signer {
	block, _ := pem.Decode(rr.Body.Bytes())
	if block == nil {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	signer, _ := key.(crypto.Signer)
	return signer
}

// rotateSelects sends one rotate request and returns the key the key store
// selects after it, which is no longer the one with kid from: the store signs
// with the active key whose record id is highest, and record ids sort in mint
// order, so the rotated key is selected at once.
func (s *KeyChangeSigningSuite) rotateSelects(from string, send func() *httptest.ResponseRecorder) (crypto.Signer, string) {
	rr := send()
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	key, kid := s.selected()
	s.Require().NotEqual(from, kid, "the key store selects the rotated key")
	return key, kid
}

func (s *KeyChangeSigningSuite) TestRotateSignsWithTheNewKeyAtOnce() {
	for _, query := range []string{"force=rotate", "rotate"} {
		_, oldKid := s.warm()

		key, kid := s.rotateSelects(oldKid, func() *httptest.ResponseRecorder { return s.post(query, nil, "") })

		got, verifies := s.polled(key.Public())
		s.Equal(kid, got, "%s: the handling node signs with the new kid the next time it signs", query)
		s.True(verifies, query)
	}
}

func (s *KeyChangeSigningSuite) TestReplaceOnCreateSignsWithTheReplacementAtOnce() {
	oldKey, oldKid := s.warm()

	rr := s.post("force=replace", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	replacement := privateKeyPEM(rr)
	s.Require().NotNil(replacement)

	kid, verifies := s.polled(replacement.Public())
	s.True(verifies, "the handling node signs with the replacement the next time it signs")
	s.Equal(oldKid, kid, "the replacement keeps the kid")
	_, verifiesOld := s.polled(oldKey.Public())
	s.False(verifiesOld, "nothing is signed with the deleted key")
}

func (s *KeyChangeSigningSuite) TestReplaceOnKeyLoadSignsWithTheUploadedKeyAtOnce() {
	oldKey, _ := s.warm()

	uploaded, pemBody := rsaPrivateKeyPEM(s.T())
	rr := s.post("force=replace", pemBody, "application/x-pem-file")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	_, verifies := s.polled(uploaded)
	s.True(verifies, "the handling node signs with the uploaded key the next time it signs")
	_, verifiesOld := s.polled(oldKey.Public())
	s.False(verifiesOld, "nothing is signed with the deleted key")
}

func (s *KeyChangeSigningSuite) TestRotateOnKeyLoadSignsWithTheNewKeyAtOnce() {
	_, oldKid := s.warm()

	key, kid := s.rotateSelects(oldKid, func() *httptest.ResponseRecorder {
		_, pemBody := rsaPrivateKeyPEM(s.T())
		return s.post("force=rotate", pemBody, "application/x-pem-file")
	})

	got, verifies := s.polled(key.Public())
	s.Equal(kid, got, "the handling node signs with the new kid the next time it signs")
	s.True(verifies)
}
