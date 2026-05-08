package goSsfServer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
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
	suite.Equal(2, len(config.DeliveryMethodsSupported), "SSF only supports 2 transmit methods")

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

func TestSsfServerTestSuite(t *testing.T) {
	suite.Run(t, new(SsfServerTestSuite))
}
