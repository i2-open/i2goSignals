package test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (suite *ServerSuite) TestF_JwksSummaries() {
	baseUrl := fmt.Sprintf("http://%s/keys", suite.servers[0].host)

	// 1. Unauthorized access
	suite.T().Log("Testing unauthorized access to /keys")
	req, _ := http.NewRequest(http.MethodGet, baseUrl, nil)
	resp, err := suite.servers[0].client.Do(req)
	suite.NoError(err)
	suite.Equal(http.StatusUnauthorized, resp.StatusCode)

	// 2. Forbidden access (insufficient scope)
	suite.T().Log("Testing forbidden access to /keys (insufficient scope)")

	// Create a token with only ScopeEventDelivery
	lowScopeToken, err := suite.servers[0].app.GetAuth().IssueStreamClientToken(model.SsfClient{
		Id:            bson.NewObjectID(),
		ProjectIds:    []string{suite.servers[0].projectId},
		AllowedScopes: []string{authSupport.ScopeEventDelivery},
		Email:         "lowscope@test.com",
		Description:   "low scope test client",
	}, suite.servers[0].projectId, false, "")
	suite.NoError(err)

	req, _ = http.NewRequest(http.MethodGet, baseUrl, nil)
	req.Header.Set("Authorization", "Bearer "+lowScopeToken)
	resp, err = suite.servers[0].client.Do(req)
	suite.NoError(err)
	suite.Equal(http.StatusForbidden, resp.StatusCode)

	// 3. Success with ScopeStreamAdmin (contained in streamMgmtToken)
	suite.T().Log("Testing successful access to /keys with ScopeStreamAdmin")
	req, _ = http.NewRequest(http.MethodGet, baseUrl, nil)
	req.Header.Set("Authorization", "Bearer "+suite.servers[0].streamMgmtToken)
	resp, err = suite.servers[0].client.Do(req)
	suite.NoError(err)
	suite.Equal(http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var summaries []interfaces.KeySummary
	err = json.Unmarshal(body, &summaries)
	suite.NoError(err, "Failed to unmarshal summaries JSON")
	suite.NotNil(summaries)

	// Given previous tests in ServerSuite create keys, we should have some.
	suite.GreaterOrEqual(len(summaries), 1, "Expected at least one key summary")

	for _, summary := range summaries {
		suite.NotEmpty(summary.Kids)
		suite.NotEmpty(summary.KeyName)
		suite.NotEmpty(summary.Type)
	}
}
