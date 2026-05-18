package test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SubjectFilteringSuite exercises the SSF subject-filtering configuration
// surface: discovery gating and the Add/Remove Subject endpoints. The feature
// is governed by the I2SIG_SUBJECT_FILTERING env var, read per request, so
// each test sets the state it needs and restores the default afterward.
type SubjectFilteringSuite struct {
	suite.Suite
	instance *ssfInstance
}

func (suite *SubjectFilteringSuite) SetupSuite() {
	_ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
	instance, err := createServer(suite.T(), "subject_filtering_test", true)
	assert.NoError(suite.T(), err)
	suite.instance = instance
}

func (suite *SubjectFilteringSuite) TearDownSuite() {
	_ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
	if suite.instance != nil {
		suite.instance.app.Shutdown()
		suite.instance.ts.Close()
	}
}

func TestSubjectFilteringSuite(t *testing.T) {
	suite.Run(t, new(SubjectFilteringSuite))
}

// getDiscovery fetches and decodes the SSF discovery document.
func (suite *SubjectFilteringSuite) getDiscovery() model.TransmitterConfiguration {
	resp, err := http.Get(suite.instance.ts.URL + "/.well-known/ssf-configuration")
	assert.NoError(suite.T(), err)
	body, _ := io.ReadAll(resp.Body)
	var config model.TransmitterConfiguration
	_ = json.Unmarshal(body, &config)
	return config
}

// TestDiscoveryHidesSubjectEndpointsWhenDisabled verifies the SSF discovery
// document omits the Add/Remove Subject endpoints while subject filtering is
// disabled, so discovery never advertises a capability the server won't honor.
func (suite *SubjectFilteringSuite) TestDiscoveryHidesSubjectEndpointsWhenDisabled() {
	_ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
	config := suite.getDiscovery()
	assert.Empty(suite.T(), config.AddSubjectEndpoint, "add_subject_endpoint must be omitted when filtering disabled")
	assert.Empty(suite.T(), config.RemoveSubjectEndpoint, "remove_subject_endpoint must be omitted when filtering disabled")
}

// TestDiscoveryShowsSubjectEndpointsWhenEnabled verifies the SSF discovery
// document advertises the Add/Remove Subject endpoints once subject filtering
// is enabled server-wide.
func (suite *SubjectFilteringSuite) TestDiscoveryShowsSubjectEndpointsWhenEnabled() {
	_ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()
	config := suite.getDiscovery()
	assert.Contains(suite.T(), config.AddSubjectEndpoint, "/add-subject", "add_subject_endpoint must be advertised when filtering enabled")
	assert.Contains(suite.T(), config.RemoveSubjectEndpoint, "/remove-subject", "remove_subject_endpoint must be advertised when filtering enabled")
}

// TestSubjectHandlersReturn404WhenDisabled verifies the Add/Remove Subject
// handlers return 404 while subject filtering is disabled, so "not advertised"
// in discovery and "not reachable" at the endpoint agree.
func (suite *SubjectFilteringSuite) TestSubjectHandlersReturn404WhenDisabled() {
	_ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
	for _, path := range []string{"/add-subject", "/remove-subject"} {
		resp, err := http.Post(suite.instance.ts.URL+path, "application/json", strings.NewReader("{}"))
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode, "handler %s must return 404 when filtering disabled", path)
	}
}
