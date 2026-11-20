package model

import "time"

// ClusterLease is stored in MongoDB and used for cross-node ownership.
// _id is the resource identifier, e.g. "poll-receiver:<streamId>" or "push-transmitter:<streamId>".
type ClusterLease struct {
	Id           string    `bson:"_id" json:"id"`
	OwnerNodeId  string    `bson:"ownerNodeId" json:"ownerNodeId"`
	LeaseUntil   time.Time `bson:"leaseUntil" json:"leaseUntil"`
	CreatedAt    time.Time `bson:"createdAt" json:"createdAt"`
	UpdatedAt    time.Time `bson:"updatedAt" json:"updatedAt"`
	FencingToken int64     `bson:"fencingToken" json:"fencingToken"`
	// LastPurgeAt is set only on the maintenance:ping-purge row: the time of
	// the cluster's last completed ping purge (ADR 0048).
	LastPurgeAt time.Time `bson:"lastPurgeAt,omitempty" json:"lastPurgeAt,omitzero"`
}

type ClusterNode struct {
	Id         string    `bson:"_id" json:"id"`
	Address    string    `bson:"address" json:"address"`
	Version    string    `bson:"version" json:"version"`
	StartedAt  time.Time `bson:"startedAt" json:"startedAt"`
	LastSeenAt time.Time `bson:"lastSeenAt" json:"lastSeenAt"`
}
