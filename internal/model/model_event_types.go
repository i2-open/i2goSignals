package model

var CaepEvents = []string{
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
	"https://schemas.openid.net/secevent/caep/event-type/credential-change",
	"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
	"https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
}

var RiscEvents = []string{
	"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
	"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
	"https://schemas.openid.net/secevent/risc/event-type/account-purged",
	"https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
	"https://schemas.openid.net/secevent/risc/event-type/recovery-activated",
	"https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed",
	"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
	"https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
	"https://schemas.openid.net/secevent/risc/event-type/identifier-recycled",
}

const (
	EventScimFeedAdd      = "urn:ietf:params:scim:event:feed:add"
	EventScimFeedRemove   = "urn:ietf:params:scim:event:feed:remove"
	EventScimCreateFull   = "urn:ietf:params:scim:event:prov:create:full"
	EventScimPutFull      = "urn:ietf:params:scim:event:prov:put:full"
	EventScimPatchFull    = "urn:ietf:params:scim:event:prov:patch:full"
	EventScimCreateNotice = "urn:ietf:params:scim:event:prov:create:notice"
	EventScimPatchNotice  = "urn:ietf:params:scim:event:prov:patch:notice"
	EventScimPutNotice    = "urn:ietf:params:scim:event:prov:put:notice"
	EventScimDelete       = "urn:ietf:params:scim:event:prov:delete"
	EventScimActivate     = "urn:ietf:params:scim:event:prov:activate"
	EventScimDeactivate   = "urn:ietf:params:scim:event:prov:deactivate"
	EventScimAsyncResp    = "urn:ietf:params:scim:event:misc:asyncResp"
)

func GetSupportedEvents() []string {
	events := []string{
		EventScimFeedAdd,
		EventScimFeedRemove,
		EventScimCreateFull,
		EventScimPutFull,
		EventScimPatchFull,
		EventScimCreateNotice,
		EventScimPatchNotice,
		EventScimPutNotice,
		EventScimDelete,
		EventScimActivate,
		EventScimDeactivate,

		EventScimAsyncResp,
	}

	events = append(events, CaepEvents...)
	events = append(events, RiscEvents...)
	return events
}
