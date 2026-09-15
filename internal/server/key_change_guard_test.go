package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

// Issue #311: a key suspend or replace that would leave a signing transmitter
// with no active key for its iss and signing_alg is refused with a 409 listing
// the affected streams, unless the caller resends with ?confirm=true. A revoke,
// a reactivate and a rotate are never refused.

const guardIssuer = "https://guard.example"

type KeyChangeGuardSuite struct {
	suite.Suite
	app *SignalsApplication
}

func TestKeyChangeGuardSuite(t *testing.T) {
	suite.Run(t, new(KeyChangeGuardSuite))
}

func (s *KeyChangeGuardSuite) SetupTest() {
	persistence, err := dbProviders.OpenPersistence("memorydb:", "key-change-guard-"+s.T().Name())
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	s.app = newTestApplication(persistence)
	s.app.DefIssuer = "DEFAULT"
	_, err = persistence.KeyService.CreateKeyPair(context.Background(), guardIssuer, "sig", "proj-A")
	s.Require().NoError(err)
}

func (s *KeyChangeGuardSuite) adminToken() string {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	tok, err := s.app.GetAuth().IssueStreamClientToken(client, "proj-A", true, "")
	s.Require().NoError(err)
	return tok
}

// setStatus posts {status, kid} to /key/{guardIssuer}/status with the query.
func (s *KeyChangeGuardSuite) setStatus(query string, req model.SetKeyStatusRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/key/guard/status"+query, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.adminToken())
	r = mux.SetURLVars(r, map[string]string{"keyName": guardIssuer})
	rr := httptest.NewRecorder()
	s.app.SetKeyStatus(rr, r)
	return rr
}

// pollTransmitter stores a poll transmitter signing as guardIssuer.
func (s *KeyChangeGuardSuite) pollTransmitter(sid, signingAlg, routeMode, status string) {
	s.persist(&model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:          sid,
			Description: "stream " + sid,
			Iss:         guardIssuer,
			SigningAlg:  signingAlg,
			RouteMode:   routeMode,
			Delivery:    &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: status,
	})
}

func (s *KeyChangeGuardSuite) persist(rec *model.StreamStateRecord) {
	s.Require().NoError(s.app.StreamService.PersistStreamStateRecord(context.Background(), rec))
}

func (s *KeyChangeGuardSuite) keyStatuses() map[string]string {
	summary, err := s.app.KeyService.GetKeySummary(context.Background(), guardIssuer)
	s.Require().NoError(err)
	out := map[string]string{}
	for _, ks := range summary.KeyStates {
		out[ks.Kid] = ks.Status
	}
	return out
}

// conflict decodes a 409 body.
func (s *KeyChangeGuardSuite) conflict(rr *httptest.ResponseRecorder) KeyChangeConflict {
	s.Require().Equal(http.StatusConflict, rr.Code, rr.Body.String())
	s.Contains(rr.Header().Get("Content-Type"), "application/json")
	var body KeyChangeConflict
	s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	return body
}

func (s *KeyChangeGuardSuite) TestSuspendOnlyKeyOfEnabledSigningTransmitterIs409() {
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)

	body := s.conflict(s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended}))
	s.Contains(body.Error, guardIssuer)
	s.Contains(body.Error, "RS256")
	s.Equal([]services.StrandedStream{{StreamId: "rs-1", Description: "stream rs-1", SigningAlg: "RS256"}}, body.Streams)
	s.Equal(map[string]string{guardIssuer: interfaces.KeyStatusActive}, s.keyStatuses(), "the key stays active")
}

func (s *KeyChangeGuardSuite) TestSuspendWithConfirmSuspendsTheKey() {
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)

	s.conflict(s.setStatus("?confirm=yes", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended}))
	s.Equal(map[string]string{guardIssuer: interfaces.KeyStatusActive}, s.keyStatuses(), "only confirm=true confirms")

	rr := s.setStatus("?confirm=true", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	var resp KeyStatusResponse
	s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &resp))
	s.NotEmpty(resp.Warning, "the confirmed suspend still warns that no active key remains")
	s.Equal(map[string]string{guardIssuer: interfaces.KeyStatusSuspended}, s.keyStatuses())
}

func (s *KeyChangeGuardSuite) TestSuspendOneKidWhileAnotherActiveKeyOfTheAlgRemainsIs200() {
	s.pollTransmitter("rs-1", "RS256", "", model.StreamStateEnabled)
	_, rotatedKid, err := s.app.KeyService.RotateKey(context.Background(), guardIssuer, "RS256", "proj-A")
	s.Require().NoError(err)

	rr := s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended, Kid: guardIssuer})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	// The rotated key is now the last active RS256 key.
	body := s.conflict(s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended, Kid: rotatedKid}))
	s.Equal([]services.StrandedStream{{StreamId: "rs-1", Description: "stream rs-1", SigningAlg: "RS256"}}, body.Streams)
	s.Equal(interfaces.KeyStatusActive, s.keyStatuses()[rotatedKid])
}

func (s *KeyChangeGuardSuite) TestSuspendKeyNoSigningTransmitterNeedsIs200() {
	ctx := context.Background()
	_, err := s.app.KeyService.EnsureSigningKeyForAlg(ctx, guardIssuer, "ES256", "proj-A")
	s.Require().NoError(err)
	s.pollTransmitter("es-1", "ES256", "", model.StreamStateEnabled)
	_, err = s.app.KeyService.CreateKeyPair(ctx, "https://other.example", "sig", "proj-A")
	s.Require().NoError(err)
	other := &model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:       "other-rs",
			Iss:      "https://other.example",
			Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: model.StreamStateEnabled,
	}
	s.persist(other)

	// guardIssuer's RSA key signs nothing: its only transmitter uses ES256, and
	// the RS256 transmitter belongs to another issuer.
	rr := s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended, Kid: guardIssuer})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	// Suspending every key strands the ES256 transmitter, and lists only it.
	body := s.conflict(s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended}))
	s.Equal([]services.StrandedStream{{StreamId: "es-1", Description: "stream es-1", SigningAlg: "ES256"}}, body.Streams)
	s.Contains(body.Error, "ES256")
	s.NotContains(body.Error, "RS256", "no signing transmitter of this issuer loses RS256")
}

func (s *KeyChangeGuardSuite) TestOnlySigningTransmittersThatAreNotDisabledAreListed() {
	s.pollTransmitter("poll-paused", "", model.RouteModePublish, model.StreamStatePause)
	s.pollTransmitter("poll-disabled", "", "", model.StreamStateDisable)
	s.pollTransmitter("poll-forward", "", model.RouteModeForward, model.StreamStateEnabled)
	s.persist(&model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:          "push-enabled",
			Description: "push",
			Iss:         guardIssuer,
			Delivery: &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: &model.PushTransmitMethod{
				Method: model.DeliveryPush, EndpointUrl: "https://receiver.example/events"}},
		},
		Status: model.StreamStateEnabled,
	})
	s.persist(&model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:       "poll-receiver",
			Iss:      guardIssuer,
			Delivery: &model.OneOfStreamConfigurationDelivery{PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll}},
		},
		Status: model.StreamStateEnabled,
	})
	s.persist(&model.StreamStateRecord{
		ProjectId: "proj-A",
		PairId:    "pair-1",
		StreamConfiguration: model.StreamConfiguration{
			Id:          "pair-tx",
			Description: "pair",
			Iss:         guardIssuer,
			Delivery:    &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       "pair-rx",
			Iss:      "https://peer.example",
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleInitiator, EndpointUrl: "https://peer.example/sstp/p", PeerPairId: "p"},
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	})

	body := s.conflict(s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended}))
	s.Equal([]services.StrandedStream{
		{StreamId: "pair-tx", Description: "pair", SigningAlg: "RS256"},
		{StreamId: "poll-paused", Description: "stream poll-paused", SigningAlg: "RS256"},
		{StreamId: "push-enabled", Description: "push", SigningAlg: "RS256"},
	}, body.Streams)
}

func (s *KeyChangeGuardSuite) TestOnlyDisabledForwardAndReceiveStreamsDoNotBlockASuspend() {
	s.pollTransmitter("poll-disabled", "", "", model.StreamStateDisable)
	s.pollTransmitter("poll-forward", "", model.RouteModeForward, model.StreamStateEnabled)
	s.persist(&model.StreamStateRecord{
		ProjectId: "proj-A",
		StreamConfiguration: model.StreamConfiguration{
			Id:       "poll-receiver",
			Iss:      guardIssuer,
			Delivery: &model.OneOfStreamConfigurationDelivery{PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll}},
		},
		Status: model.StreamStateEnabled,
	})

	rr := s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
}

// createKey posts to /key/{guardIssuer} with the query and body (a key load
// when body is non-empty).
func (s *KeyChangeGuardSuite) createKey(query, contentType string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/key/guard"+query, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.adminToken())
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r = mux.SetURLVars(r, map[string]string{"keyName": guardIssuer})
	rr := httptest.NewRecorder()
	s.app.CreateKey(rr, r)
	return rr
}

// dualAlgIssuer gives guardIssuer an ES256 key beside its RSA key, and an
// enabled RS256 and ES256 signing transmitter.
func (s *KeyChangeGuardSuite) dualAlgIssuer() {
	_, err := s.app.KeyService.EnsureSigningKeyForAlg(context.Background(), guardIssuer, "ES256", "proj-A")
	s.Require().NoError(err)
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)
	s.pollTransmitter("es-1", "ES256", model.RouteModePublish, model.StreamStateEnabled)
	s.pollTransmitter("es-2", "ES256", "", model.StreamStatePause)
}

func (s *KeyChangeGuardSuite) signs(alg string) bool {
	_, _, err := s.app.KeyService.GetSigner(context.Background(), guardIssuer, alg)
	return err == nil
}

// Since #314 a replace on create deletes and recreates one algorithm, so it
// never drops one: neither a plain replace nor alg=ES256 is refused, and the
// issuer keeps signing with both algorithms.
func (s *KeyChangeGuardSuite) TestPerAlgorithmReplaceOnADualAlgIssuerIsNotRefused() {
	s.dualAlgIssuer()

	for _, query := range []string{"?force=replace", "?force=replace&alg=ES256"} {
		rr := s.createKey(query, "", nil)
		s.Require().Equal(http.StatusCreated, rr.Code, "%s: %s", query, rr.Body.String())
		s.True(s.signs("RS256"), query)
		s.True(s.signs("ES256"), query)
	}
}

// Dropping one algorithm of a dual-algorithm issuer (here by suspending its
// ES256 key) is refused listing only that algorithm's streams, until confirmed.
func (s *KeyChangeGuardSuite) TestDroppingOneAlgInUseIs409ListingOnlyItsStreamsUntilConfirmed() {
	s.dualAlgIssuer()
	_, esKid, err := s.app.KeyService.GetSigner(context.Background(), guardIssuer, "ES256")
	s.Require().NoError(err)

	body := s.conflict(s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended, Kid: esKid}))
	s.Equal([]services.StrandedStream{
		{StreamId: "es-1", Description: "stream es-1", SigningAlg: "ES256"},
		{StreamId: "es-2", Description: "stream es-2", SigningAlg: "ES256"},
	}, body.Streams)
	s.Contains(body.Error, guardIssuer)
	s.Contains(body.Error, "ES256")
	s.NotContains(body.Error, "RS256")
	s.True(s.signs("ES256"), "a refused suspend changes nothing")

	rr := s.setStatus("?confirm=true", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended, Kid: esKid})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	s.False(s.signs("ES256"), "the confirmed suspend went through")
	s.True(s.signs("RS256"))
}

// rsaPEM is a fresh RSA key as a PKCS#1 private or public PEM block.
func (s *KeyChangeGuardSuite) rsaPEM(private bool) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	if private {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
}

// Since #314 a key-load replace deletes only RSA keys. A private RSA upload
// keeps RS256 covered and is not refused; a public-only upload drops RS256, so
// it is refused listing only the RS256 stream, until confirmed. ES256 is kept.
func (s *KeyChangeGuardSuite) TestKeyLoadReplaceDroppingAnAlgInUseIs409UntilConfirmed() {
	s.dualAlgIssuer()

	rr := s.createKey("?force=replace", "application/x-pem-file", s.rsaPEM(true))
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	s.True(s.signs("RS256"))
	s.True(s.signs("ES256"), "a key-load replace keeps the ES256 key")

	upload := s.rsaPEM(false)
	body := s.conflict(s.createKey("?force=replace", "application/x-pem-file", upload))
	s.Equal([]services.StrandedStream{{StreamId: "rs-1", Description: "stream rs-1", SigningAlg: "RS256"}}, body.Streams)
	s.Contains(body.Error, "RS256")
	s.NotContains(body.Error, "ES256")
	s.True(s.signs("RS256"), "a refused replace deletes nothing")

	rr = s.createKey("?force=replace&confirm=true", "application/x-pem-file", upload)
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	s.False(s.signs("RS256"), "the confirmed replace went through")
	s.True(s.signs("ES256"))
}

// A public key signs nothing, so a replace that uploads one leaves the RS256
// transmitter without a key.
func (s *KeyChangeGuardSuite) TestKeyLoadReplaceWithAPublicKeyStrandsRS256() {
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)
	upload := s.rsaPEM(false)

	r := httptest.NewRequest(http.MethodPost, "/key/guard?force=replace", bytes.NewReader(upload))
	r.Header.Set("Authorization", "Bearer "+s.adminToken())
	r.Header.Set("Content-Type", "application/x-pem-file")
	r = mux.SetURLVars(r, map[string]string{"keyName": guardIssuer})
	rr := httptest.NewRecorder()
	s.app.LoadKey(rr, r)

	body := s.conflict(rr)
	s.Equal([]services.StrandedStream{{StreamId: "rs-1", Description: "stream rs-1", SigningAlg: "RS256"}}, body.Streams)
	s.True(s.signs("RS256"), "a refused replace deletes nothing")
}

func (s *KeyChangeGuardSuite) TestReplaceKeepingTheAlgCoveredIs201() {
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)

	rr := s.createKey("?force=replace", "", nil)
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	rr = s.createKey("?force=replace", "application/x-pem-file", s.rsaPEM(true))
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	s.True(s.signs("RS256"))
}

func (s *KeyChangeGuardSuite) TestRevokeReactivateAndRotateAreNeverRefused() {
	s.pollTransmitter("rs-1", "", "", model.StreamStateEnabled)

	rr := s.setStatus("?confirm=true", model.SetKeyStatusRequest{Status: interfaces.KeyStatusSuspended})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	rr = s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusActive})
	s.Require().Equal(http.StatusOK, rr.Code, "reactivate: %s", rr.Body.String())

	for _, rotate := range []string{"?force=rotate", "?rotate"} {
		rr = s.createKey(rotate, "", nil)
		s.Require().Equal(http.StatusOK, rr.Code, "%s: %s", rotate, rr.Body.String())
	}

	// Revoking every key, the last active ones included, is never held.
	rr = s.setStatus("", model.SetKeyStatusRequest{Status: interfaces.KeyStatusRevoked})
	s.Require().Equal(http.StatusOK, rr.Code, "revoke: %s", rr.Body.String())
	s.False(s.signs("RS256"))
	for _, status := range s.keyStatuses() {
		s.Equal(interfaces.KeyStatusRevoked, status)
	}
}
