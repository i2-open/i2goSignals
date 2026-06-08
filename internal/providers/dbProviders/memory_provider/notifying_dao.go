package memory_provider

import (
	"context"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// notifyingDAO wrappers attach a single after-mutation callback to each
// memory DAO. They live only inside the memory adapter — Mongo carries no
// decorator and pays no overhead.
//
// They replace the BaseProvider WriteHook plumbing (#44): instead of
// threading notifyWrite through every façade method, the memory adapter
// wraps its DAOs once at composition time and lets every successful write
// fire MarkDirty at the lowest level. Read methods pass through unchanged.
//
// Errors from the underlying DAO are returned verbatim; notify is only
// invoked on a successful mutation.

type notifyingStreamDAO struct {
	inner  interfaces.StreamDAO
	notify func()
}

func newNotifyingStreamDAO(inner interfaces.StreamDAO, notify func()) *notifyingStreamDAO {
	return &notifyingStreamDAO{inner: inner, notify: notify}
}

func (d *notifyingStreamDAO) Create(ctx context.Context, state *model.StreamStateRecord) error {
	if err := d.inner.Create(ctx, state); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingStreamDAO) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	return d.inner.FindByID(ctx, id)
}

func (d *notifyingStreamDAO) Update(ctx context.Context, state *model.StreamStateRecord) error {
	if err := d.inner.Update(ctx, state); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingStreamDAO) Delete(ctx context.Context, id string) error {
	if err := d.inner.Delete(ctx, id); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingStreamDAO) List(ctx context.Context) ([]model.StreamStateRecord, error) {
	return d.inner.List(ctx)
}

func (d *notifyingStreamDAO) FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error) {
	return d.inner.FindByProjectID(ctx, projectID)
}

func (d *notifyingStreamDAO) FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	return d.inner.FindByInboundSID(ctx, sid)
}

func (d *notifyingStreamDAO) FindByPairId(ctx context.Context, pairId string) (*model.StreamStateRecord, error) {
	return d.inner.FindByPairId(ctx, pairId)
}

func (d *notifyingStreamDAO) UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error {
	if err := d.inner.UpdateStatus(ctx, id, status, errorMsg); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingStreamDAO) UpdateRemoteAddress(ctx context.Context, id string, addr *model.RemoteIP) error {
	if err := d.inner.UpdateRemoteAddress(ctx, id, addr); err != nil {
		return err
	}
	d.notify()
	return nil
}

type notifyingEventDAO struct {
	inner  interfaces.EventDAO
	notify func()
}

func newNotifyingEventDAO(inner interfaces.EventDAO, notify func()) *notifyingEventDAO {
	return &notifyingEventDAO{inner: inner, notify: notify}
}

func (d *notifyingEventDAO) Insert(ctx context.Context, record *model.AgEventRecord) error {
	if err := d.inner.Insert(ctx, record); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingEventDAO) FindByJTI(ctx context.Context, jti string) (*model.AgEventRecord, error) {
	return d.inner.FindByJTI(ctx, jti)
}

func (d *notifyingEventDAO) FindByJTIs(ctx context.Context, jtis []string) ([]*model.AgEventRecord, error) {
	return d.inner.FindByJTIs(ctx, jtis)
}

func (d *notifyingEventDAO) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.AgEventRecord) bool) ([]*model.AgEventRecord, error) {
	return d.inner.FindByTimeRange(ctx, from, to, filter)
}

func (d *notifyingEventDAO) AddPending(ctx context.Context, jti string, streamID string) error {
	if err := d.inner.AddPending(ctx, jti, streamID); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingEventDAO) GetPendingForStream(ctx context.Context, streamID string, limit int32) ([]string, int64, error) {
	return d.inner.GetPendingForStream(ctx, streamID, limit)
}

func (d *notifyingEventDAO) RemovePending(ctx context.Context, jti string, streamID string) (*interfaces.DeliverableEvent, error) {
	ev, err := d.inner.RemovePending(ctx, jti, streamID)
	if err != nil {
		return ev, err
	}
	d.notify()
	return ev, nil
}

func (d *notifyingEventDAO) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	n, err := d.inner.ClearPendingForStream(ctx, streamID)
	if err != nil {
		return n, err
	}
	d.notify()
	return n, nil
}

func (d *notifyingEventDAO) MarkDelivered(ctx context.Context, event *interfaces.DeliverableEvent, ackDate time.Time) error {
	if err := d.inner.MarkDelivered(ctx, event, ackDate); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingEventDAO) WatchPending(ctx context.Context, callback func(jti string, streamID string)) error {
	return d.inner.WatchPending(ctx, callback)
}

type notifyingKeyDAO struct {
	inner  interfaces.KeyDAO
	notify func()
}

func newNotifyingKeyDAO(inner interfaces.KeyDAO, notify func()) *notifyingKeyDAO {
	return &notifyingKeyDAO{inner: inner, notify: notify}
}

func (d *notifyingKeyDAO) Insert(ctx context.Context, keyRec *interfaces.JwkKeyRec) error {
	if err := d.inner.Insert(ctx, keyRec); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingKeyDAO) FindByKid(ctx context.Context, kid string) (*interfaces.JwkKeyRec, error) {
	return d.inner.FindByKid(ctx, kid)
}

func (d *notifyingKeyDAO) FindByKeyName(ctx context.Context, keyName string) ([]*interfaces.JwkKeyRec, error) {
	return d.inner.FindByKeyName(ctx, keyName)
}

func (d *notifyingKeyDAO) FindLatestByKeyName(ctx context.Context, keyName string) (*interfaces.JwkKeyRec, error) {
	return d.inner.FindLatestByKeyName(ctx, keyName)
}

func (d *notifyingKeyDAO) FindByStreamID(ctx context.Context, streamID string) (*interfaces.JwkKeyRec, error) {
	return d.inner.FindByStreamID(ctx, streamID)
}

func (d *notifyingKeyDAO) DeleteByKid(ctx context.Context, kid string) error {
	if err := d.inner.DeleteByKid(ctx, kid); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingKeyDAO) DeleteByKeyName(ctx context.Context, keyName string) error {
	if err := d.inner.DeleteByKeyName(ctx, keyName); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingKeyDAO) ListKids(ctx context.Context) ([]string, error) {
	return d.inner.ListKids(ctx)
}

func (d *notifyingKeyDAO) ListKeyNames(ctx context.Context) ([]string, error) {
	return d.inner.ListKeyNames(ctx)
}

func (d *notifyingKeyDAO) KeySummary(ctx context.Context, keyName string) (*interfaces.KeySummary, error) {
	return d.inner.KeySummary(ctx, keyName)
}

func (d *notifyingKeyDAO) ListSummaries(ctx context.Context) ([]interfaces.KeySummary, error) {
	return d.inner.ListSummaries(ctx)
}

type notifyingClientDAO struct {
	inner  interfaces.ClientDAO
	notify func()
}

func newNotifyingClientDAO(inner interfaces.ClientDAO, notify func()) *notifyingClientDAO {
	return &notifyingClientDAO{inner: inner, notify: notify}
}

func (d *notifyingClientDAO) Insert(ctx context.Context, client *model.SsfClient) error {
	if err := d.inner.Insert(ctx, client); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingClientDAO) FindByID(ctx context.Context, id string) (*model.SsfClient, error) {
	return d.inner.FindByID(ctx, id)
}

func (d *notifyingClientDAO) FindByProjectID(ctx context.Context, projectID string) ([]*model.SsfClient, error) {
	return d.inner.FindByProjectID(ctx, projectID)
}

func (d *notifyingClientDAO) Delete(ctx context.Context, id string) error {
	if err := d.inner.Delete(ctx, id); err != nil {
		return err
	}
	d.notify()
	return nil
}

type notifyingServerDAO struct {
	inner  interfaces.ServerDAO
	notify func()
}

func newNotifyingServerDAO(inner interfaces.ServerDAO, notify func()) *notifyingServerDAO {
	return &notifyingServerDAO{inner: inner, notify: notify}
}

func (d *notifyingServerDAO) Create(ctx context.Context, server *model.Server) error {
	if err := d.inner.Create(ctx, server); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingServerDAO) FindByID(ctx context.Context, id string) (*model.Server, error) {
	return d.inner.FindByID(ctx, id)
}

func (d *notifyingServerDAO) FindByAlias(ctx context.Context, alias string) (*model.Server, error) {
	return d.inner.FindByAlias(ctx, alias)
}

func (d *notifyingServerDAO) Update(ctx context.Context, server *model.Server) error {
	if err := d.inner.Update(ctx, server); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingServerDAO) Delete(ctx context.Context, id string) error {
	if err := d.inner.Delete(ctx, id); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingServerDAO) List(ctx context.Context) ([]model.Server, error) {
	return d.inner.List(ctx)
}

type notifyingTokenDAO struct {
	inner  interfaces.TokenDAO
	notify func()
}

func newNotifyingTokenDAO(inner interfaces.TokenDAO, notify func()) *notifyingTokenDAO {
	return &notifyingTokenDAO{inner: inner, notify: notify}
}

func (d *notifyingTokenDAO) Insert(ctx context.Context, record *model.TokenRecord) error {
	if err := d.inner.Insert(ctx, record); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingTokenDAO) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
	return d.inner.FindByJTI(ctx, jti)
}

func (d *notifyingTokenDAO) Revoke(ctx context.Context, jti string) error {
	if err := d.inner.Revoke(ctx, jti); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingTokenDAO) RecordRedemption(ctx context.Context, jti string, ip string, at time.Time) error {
	if err := d.inner.RecordRedemption(ctx, jti, ip, at); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingTokenDAO) DeleteExpired(ctx context.Context) error {
	if err := d.inner.DeleteExpired(ctx); err != nil {
		return err
	}
	d.notify()
	return nil
}

func (d *notifyingTokenDAO) FindByProjectID(ctx context.Context, projectID string) ([]*model.TokenRecord, error) {
	return d.inner.FindByProjectID(ctx, projectID)
}

func (d *notifyingTokenDAO) FindByClientID(ctx context.Context, clientID string) ([]*model.TokenRecord, error) {
	return d.inner.FindByClientID(ctx, clientID)
}

func (d *notifyingTokenDAO) FindAll(ctx context.Context) ([]*model.TokenRecord, error) {
	return d.inner.FindAll(ctx)
}
