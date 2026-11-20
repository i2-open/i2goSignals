package goSsfServer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type SsfServerTestSuite struct {
	suite.Suite
	app         *SsfApplication
	server      *httptest.Server
	persistence *dbProviders.Persistence
}

func (suite *SsfServerTestSuite) SetupSuite() {
	// Use a memory database
	suite.T().Setenv("MEM_DIRECTORY", suite.T().TempDir())
	dbUrl := "memorydb:"
	persistence, err := dbProviders.OpenPersistence(dbUrl, "ssf_test")
	suite.Require().NoError(err)
	suite.persistence = persistence

	suite.app = NewApplication(persistence, "http://localhost:8889/")
	suite.server = httptest.NewServer(suite.app.Handler)
}

func (suite *SsfServerTestSuite) TearDownSuite() {
	suite.server.Close()
	if suite.persistence != nil && suite.persistence.Storage != nil {
		_ = suite.persistence.Storage.Close()
	}
}

func (suite *SsfServerTestSuite) TestWellKnownSSFConfiguration() {
	resp, err := http.Get(suite.server.URL + "/.well-known/ssf-configuration")
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)

	var config model.TransmitterConfiguration
	err = json.NewDecoder(resp.Body).Decode(&config)
	suite.NoError(err)
	suite.Equal("", config.GoSignalsVersion, "Go Signals Version should be empty")
	suite.Equal(3, len(config.DeliveryMethodsSupported), "SSF: 2 transmit methods + SSTP advertised unconditionally")

}

func (suite *SsfServerTestSuite) TestIndex() {
	resp, err := http.Get(suite.server.URL + "/")
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)
}

func (suite *SsfServerTestSuite) TestStreamCreateUnauthorized() {
	resp, err := http.Post(suite.server.URL+"/stream", "application/json", nil)
	suite.NoError(err)
	suite.Equal(http.StatusUnauthorized, resp.StatusCode)
}

// TestPollDelivers pins that a single-node goSsfServer, whose router serves
// claims (#365), still delivers: a SET pending on a POLL stream is returned by
// POST /poll/{id}.
func (suite *SsfServerTestSuite) TestPollDelivers() {
	const iss = "https://poll-transmitter.example.com"
	ctx := context.Background()
	_, err := suite.app.KeyService.EnsureSigningKey(ctx, iss, "")
	suite.Require().NoError(err)

	const project = "proj-poll"
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{project}}
	streamToken, err := suite.app.GetAuth().IssueStreamClientToken(client, project, false, "")
	suite.Require().NoError(err)
	cfg := model.StreamStateRecord{}
	cfg.Iss = iss
	cfg.Aud = []string{"https://poll-receiver.example.com"}
	cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
	}
	created := suite.post("/stream", streamToken, cfg, http.StatusCreated)
	var stream model.StreamConfiguration
	suite.Require().NoError(json.Unmarshal(created, &stream))
	sid := stream.Id

	jti := goSet.GenerateJti()
	set := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{ID: jti, Issuer: iss, IssuedAt: jwt.NewNumericDate(time.Now())},
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
		},
	}
	rec, err := suite.app.EventService.AddEvent(ctx, set, sid, "")
	suite.Require().NoError(err)
	suite.Require().NoError(suite.app.EventService.AddEventToStream(ctx, interfaces.PendingRef{Jti: rec.Jti, AckJti: rec.Jti}, sid))

	pollToken, err := suite.app.GetAuth().IssueStreamToken(sid, project, nil)
	suite.Require().NoError(err)
	body := suite.post("/poll/"+sid, pollToken, map[string]any{"returnImmediately": true}, http.StatusOK)
	var polled struct {
		Sets map[string]string `json:"sets"`
	}
	suite.Require().NoError(json.Unmarshal(body, &polled))
	suite.Len(polled.Sets, 1, "the pending SET is delivered by POST /poll/{id}")
}

func (suite *SsfServerTestSuite) post(path, bearer string, payload any, want int) []byte {
	raw, err := json.Marshal(payload)
	suite.Require().NoError(err)
	req, err := http.NewRequest(http.MethodPost, suite.server.URL+path, bytes.NewReader(raw))
	suite.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	suite.Require().Equal(want, resp.StatusCode, out.String())
	return out.Bytes()
}

func TestSsfServerTestSuite(t *testing.T) {
	suite.Run(t, new(SsfServerTestSuite))
}
