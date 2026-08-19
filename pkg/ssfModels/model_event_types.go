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

// WiseEvents are the WISE (workload identity) event types this transmitter
// supports. The WISE draft defines many more — the credential-issued /
// credential-rotated, workload-lifecycle, policy, supply-chain and
// anomalous-behavior families — which are deliberately absent: the catalog
// advertises only what the pkg/goSetValidate WISE pack can actually vouch for,
// so an advertised type is never one that resolves as Unsupported and gets
// rejected by a STRICT receiver.
var WiseEvents = []string{
	"https://schemas.openid.net/secevent/wise/event-type/credential-revoked",
	"https://schemas.openid.net/secevent/wise/event-type/credential-compromise",
	"https://schemas.openid.net/secevent/wise/event-type/trust-anchor-changed",
	"https://schemas.openid.net/secevent/wise/event-type/workload-compromised",
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
	EventScimAsyncResp    = "urn:ietf:params:scim:event:misc:asyncresp"
)

// GetSupportedEvents returns the event type URIs this transmitter advertises in
// events_supported and negotiates events_requested against: the compiled-in
// SCIM/CAEP/RISC/WISE packs plus any catalog extension configured through
// EnvEventTypesExtra (issue #261).
func GetSupportedEvents() []string {
	return append(builtinEventTypes(), extraEventTypes()...)
}

// builtinEventTypes is the compiled-in half of the catalog — the packs
// pkg/goSetValidate can actually vouch for, which is what the per-pack drift
// guards in this package assert against.
func builtinEventTypes() []string {
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
	events = append(events, WiseEvents...)
	return events
}
