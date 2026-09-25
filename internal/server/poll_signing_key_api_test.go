package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Issue #312: a poll to a signing poll transmitter whose issuer has no active
// signing key is a 503 whose plain-text body names the issuer and algorithm. The
// stream is then paused with the key-unavailable marker, so later polls get the
// ordinary paused 503.
func (s *ServerProvisioningAuthzSuite) TestPollEvents_NoActiveSigningKeyIs503NamingTheIssuer() {
	const iss = "http://transmitter.example.com" // SetupTest gives it a key
	cfg := model.StreamStateRecord{}
	cfg.Iss = iss
	cfg.Aud = []string{"http://receiver.example.com"}
	cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
	}
	body, _ := json.Marshal(cfg)
	rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), body, nil)
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	var created model.StreamConfiguration
	s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &created))
	sid := created.Id
	pollToken, err := s.app.GetAuth().IssueStreamToken(sid, "proj-A", nil)
	s.Require().NoError(err)

	_, _, err = s.app.KeyService.SetKeyStatus(context.Background(), iss, "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	s.app.EventRouter.(interface{ InvalidateIssuerKey(string) }).InvalidateIssuerKey(iss)

	pollBody := []byte(`{"returnImmediately":true}`)
	rr = s.do(s.app.PollEvents, http.MethodPost, "/poll/"+sid, pollToken, pollBody, nil)
	s.Equal(http.StatusServiceUnavailable, rr.Code)
	s.Contains(rr.Header().Get("Content-Type"), "text/plain")
	s.Contains(rr.Body.String(), "no active signing key for issuer "+iss+" (RS256)")

	stored, err := s.app.StreamService.GetStreamState(context.Background(), sid)
	s.Require().NoError(err)
	s.Equal(model.StreamStatePause, stored.Status)
	s.NotNil(stored.KeyUnavailableSince)

	rr = s.do(s.app.PollEvents, http.MethodPost, "/poll/"+sid, pollToken, pollBody, nil)
	s.Equal(http.StatusServiceUnavailable, rr.Code, "a later poll gets the paused 503")
}

// Issue #318: when the issuer's only key has expired, the refused poll's 503
// body says so, with the key and its expiry time, as the stream's paused
// reason does: a receiver can tell an expiry from a missing key.
func (s *ServerProvisioningAuthzSuite) TestPollEvents_ExpiredSigningKeyIs503NamingTheExpiry() {
	const iss = "http://transmitter.example.com" // SetupTest gives it a key
	ctx := context.Background()
	cfg := model.StreamStateRecord{}
	cfg.Iss = iss
	cfg.Aud = []string{"http://receiver.example.com"}
	cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
	}
	body, _ := json.Marshal(cfg)
	rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), body, nil)
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	var created model.StreamConfiguration
	s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &created))
	sid := created.Id
	pollToken, err := s.app.GetAuth().IssueStreamToken(sid, "proj-A", nil)
	s.Require().NoError(err)

	_, _, err = s.app.KeyService.SetKeyStatus(ctx, iss, "", interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	_, kid, err := s.app.KeyService.CreateKeyPairForAlg(ctx, iss, "", "sig", "proj-A", services.WithLifetime(time.Hour))
	s.Require().NoError(err)
	later := time.Now().Add(2 * time.Hour)
	s.app.KeyService.SetClock(func() time.Time { return later })
	defer s.app.KeyService.SetClock(time.Now)
	s.app.EventRouter.(interface{ InvalidateIssuerKey(string) }).InvalidateIssuerKey(iss)

	rr = s.do(s.app.PollEvents, http.MethodPost, "/poll/"+sid, pollToken, []byte(`{"returnImmediately":true}`), nil)
	s.Equal(http.StatusServiceUnavailable, rr.Code)
	s.Contains(rr.Body.String(), "no active signing key for issuer "+iss+" (RS256)")
	s.Contains(rr.Body.String(), "the signing key "+kid+" expired at ")
}
