package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestRegisterClientHandler(t *testing.T) {
	instance, err := createServer(t, "register_client_test", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()
	ts := instance.ts
	iat := instance.iatToken

	// 2. Register client
	regReq := model.RegisterParameters{
		Email:       "client@example.com",
		Description: "test client",
		Scopes:      []string{authSupport.ScopeStreamMgmt},
	}
	body, _ := json.Marshal(regReq)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/register", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+iat)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var regResp model.RegisterResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	assert.NoError(t, err)
	assert.NotEmpty(t, regResp.Token)
}
