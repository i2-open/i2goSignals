package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var errStoreDown = errors.New("simulated event store outage")

// toggleFailEventDAO wraps the live EventDAO and, while fail is set, refuses
// every insert as a store outage would (issue #333).
type toggleFailEventDAO struct {
	interfaces.EventDAO
	fail atomic.Bool
}

func (d *toggleFailEventDAO) Insert(ctx context.Context, record *model.EventRecord) error {
	if d.fail.Load() {
		return errStoreDown
	}
	return d.EventDAO.Insert(ctx, record)
}

func (d *toggleFailEventDAO) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	if d.fail.Load() {
		return nil, errStoreDown
	}
	return d.EventDAO.InsertMany(ctx, records)
}

func (d *toggleFailEventDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]string) ([]error, error) {
	if d.fail.Load() {
		return nil, errStoreDown
	}
	return d.EventDAO.InsertWithPending(ctx, records, pending)
}

// createStoreFailureServer starts a server whose event store can be switched
// into an outage through the returned DAO.
func createStoreFailureServer(t *testing.T, dbName string) (*ssfInstance, *toggleFailEventDAO) {
	t.Helper()
	var dao *toggleFailEventDAO
	instance, err := createServerWithHook(t, dbName, true, func(p *dbProviders.Persistence) {
		dao = &toggleFailEventDAO{EventDAO: p.EventDAO}
		p.EventService = services.NewEventService(dao)
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	})
	return instance, dao
}

// TestPushIngestStoreFailureStatus pins the RFC8935 push receiver's status
// codes: a SET that cannot be durably stored answers 503 + Retry-After (never
// 400, which would tell the transmitter to drop it — ADR 0038), validation
// failures stay 400, and a duplicate JTI stays 202 (ADR 0017).
func TestPushIngestStoreFailureStatus(t *testing.T) {
	t.Setenv("I2SIG_INGEST_RETRY_AFTER", "7")
	instance, dao := createStoreFailureServer(t, "push_ingest_store_failure_test")

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksUrl := evJwksServer(t, signingKey)
	stream := createEvPushReceiver(t, instance, jwksUrl, model.EventValidationEnforce)
	endpoint := stream.Delivery.PushReceiveMethod.EndpointUrl

	post := func(t *testing.T, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(token))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/secevent+jwt")
		resp, err := instance.client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("store failure answers 503 with Retry-After", func(t *testing.T) {
		dao.fail.Store(true)
		defer dao.fail.Store(false)

		jti, token := evSignedSet(t, signingKey, stream.Id, evValidPayload)
		resp := post(t, token)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "body: %s", body)
		assert.Equal(t, "7", resp.Header.Get("Retry-After"))

		var deliveryErr struct {
			Err         string `json:"err"`
			Description string `json:"description"`
		}
		require.NoError(t, json.Unmarshal(body, &deliveryErr))
		assert.Equal(t, goSetPush.ErrTemporarilyUnavailable, deliveryErr.Err)
		assert.NotEmpty(t, deliveryErr.Description)
		assert.Nil(t, instance.GetEvent(jti), "a refused SET must not be persisted")
	})

	t.Run("retry after recovery is accepted", func(t *testing.T) {
		_, token := evSignedSet(t, signingKey, stream.Id, evValidPayload)
		dao.fail.Store(true)
		resp := post(t, token)
		resp.Body.Close()
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

		dao.fail.Store(false)
		resp = post(t, token)
		resp.Body.Close()
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	})

	t.Run("validation failure stays 400", func(t *testing.T) {
		_, token := evSignedSet(t, signingKey, stream.Id, evMalformedPayload)
		resp := post(t, token)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Retry-After"))
	})

	t.Run("duplicate JTI stays 202", func(t *testing.T) {
		_, token := evSignedSet(t, signingKey, stream.Id, evValidPayload)
		for i := 0; i < 2; i++ {
			resp := post(t, token)
			resp.Body.Close()
			assert.Equal(t, http.StatusAccepted, resp.StatusCode, "delivery %d", i+1)
		}
	})
}

// TestSstpIngestStoreFailureStatus pins the SSTP acceptor's counterpart: a
// store failure refuses the whole exchange with 503 + Retry-After, so no SET in
// it is acked and the peer resends; a resend after recovery is acked.
func TestSstpIngestStoreFailureStatus(t *testing.T) {
	instance, dao := createStoreFailureServer(t, "sstp_ingest_store_failure_test")
	pair := newSstpEventValidationPair(t, instance, model.EventValidationEnforce)
	jti, set := sstpEvSignedSet(t, instance, sstpEvValidPayload)

	dao.fail.Store(true)
	resp := pair.postSets(t, instance, map[string]string{jti: set})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "body: %s", body)
	assert.Equal(t, "2", resp.Header.Get("Retry-After"), "default Retry-After is 2 seconds")
	assert.Contains(t, string(body), goSetPush.ErrTemporarilyUnavailable)
	assert.Nil(t, instance.GetEvent(jti))

	dao.fail.Store(false)
	for i := 0; i < 2; i++ {
		resp = pair.postSets(t, instance, map[string]string{jti: set})
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "resend %d body: %s", i+1, body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(body, &msg))
		assert.Contains(t, msg.Ack, jti, "resend %d: stored (or duplicate) SET is acked", i+1)
		assert.NotContains(t, msg.SetErrs, jti)
	}
}
