package model

const (
	EventScimFeedAdd       = "urn:ietf:params:SCIM:event:feed:add"
	EventScimFeedRemove    = "urn:ietf:params:SCIM:event:feed:remove"
	EventScimCreateFull    = "urn:ietf:params:SCIM:event:prov:create:full"
	EventScimPutFull       = "urn:ietf:params:SCIM:event:prov:put:full"
	EventScimPatchFull     = "urn:ietf:params:SCIM:event:prov:patch:full"
	EventScimCreateNotice  = "urn:ietf:params:SCIM:event:prov:create:notice"
	EventScimPatchNotice   = "urn:ietf:params:SCIM:event:prov:patch:notice"
	EventScimPutNotice     = "urn:ietf:params:SCIM:event:prov:put:notice"
	EventScimDelete        = "urn:ietf:params:SCIM:event:prov:delete"
	EventScimActivate      = "urn:ietf:params:SCIM:event:prov:activate"
	EventScimDeactivate    = "urn:ietf:params:SCIM:event:prov:deactivate"
	EventScimSigAuthMethod = "urn:ietf:params:SCIM:event:sig:authMethod"
	EventScimSigPwdReset   = "urn:ietf:params:SCIM:event:sig:pwdReset"
	EventScimAsyncResp     = "urn:ietf:params:SCIM:event:misc:asyncResp"
)

func GetSupportedEvents() []string {
	return []string{
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
		EventScimSigAuthMethod,
		EventScimSigPwdReset,
		EventScimAsyncResp,
	}
}
