package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// newFilterTestStream creates a transmitter stream with the given baseline and
// returns its id together with a stream-scoped bearer token.
func (suite *SubjectFilteringSuite) newFilterTestStream(defaultSubjects string) (string, string) {
	t := suite.T()
	instance := suite.instance
	ctx := context.WithValue(context.Background(), authUtil.AuthContextKey,
		&authUtil.AuthContext{ProjectId: instance.projectId})

	created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss: "DEFAULT",
			Aud: []string{"https://receiver.example.com"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
			},
		},
		DefaultSubjects: defaultSubjects,
	}, instance.projectId, nil)
	require.NoError(t, err)

	token, err := instance.GetAuthIssuer().IssueStreamToken(created.Id, instance.projectId, nil)
	require.NoError(t, err)
	return created.Id, token
}

// postSubject sends an Add/Remove Subject request for the given stream token.
func (suite *SubjectFilteringSuite) postSubject(path, token, body string) *http.Response {
	req, _ := http.NewRequest(http.MethodPost, suite.instance.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := suite.instance.client.Do(req)
	require.NoError(suite.T(), err)
	return resp
}

// TestAddSubjectReturns200 verifies Add Subject on the caller's authenticated
// stream returns 200 and the subject becomes deliverable on a NONE stream
// (#92 acceptance criteria 1, 3).
func (suite *SubjectFilteringSuite) TestAddSubjectReturns200() {
	_ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()
	t := suite.T()
	instance := suite.instance

	sid, token := suite.newFilterTestStream(model.DefaultSubjectsNone)
	body := `{"stream_id":"` + sid + `","subject":{"format":"email","email":"alice@example.com"}}`
	resp := suite.postSubject("/add-subject", token, body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Add Subject must return 200")

	state, err := instance.GetStreamState(sid)
	require.NoError(t, err)
	subject := &goSet.SubjectIdentifier{Format: "email"}
	subject.AddEmail("alice@example.com")
	event := &model.AgEventRecord{Event: goSet.SecurityEventToken{SubjectId: subject}}
	assert.True(t, instance.persistence.SubjectFilterService.Allows(context.Background(), state, event),
		"after Add Subject the NONE stream must deliver the added subject")
}

// TestRemoveSubjectReturns204 verifies Remove Subject on the caller's
// authenticated stream returns 204 (#92 acceptance criterion 3).
func (suite *SubjectFilteringSuite) TestRemoveSubjectReturns204() {
	_ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()
	t := suite.T()

	sid, token := suite.newFilterTestStream(model.DefaultSubjectsAll)
	body := `{"stream_id":"` + sid + `","subject":{"format":"email","email":"bob@example.com"}}`
	resp := suite.postSubject("/remove-subject", token, body)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "Remove Subject must return 204")
}

// TestAddSubjectMalformedSubjectReturns400 verifies a subject that cannot be
// canonicalized is rejected with 400 rather than silently stored.
func (suite *SubjectFilteringSuite) TestAddSubjectMalformedSubjectReturns400() {
	_ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()
	t := suite.T()

	sid, token := suite.newFilterTestStream(model.DefaultSubjectsNone)
	body := `{"stream_id":"` + sid + `","subject":{"format":"email"}}`
	resp := suite.postSubject("/add-subject", token, body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"an uncanonicalizable subject must return 400")
}
