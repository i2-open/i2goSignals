package resource

import (
	"github.com/fatih/structs"
)

func CreateFullEventPayload(resource ScimResource) map[string]interface{} {
	return map[string]interface{}{
		// RFC 9967 §2.4 names the full-form payload attribute "data" — the
		// receiver's validator keys on the exact spelling.
		"data": resource,
	}
}

func CreateNoticeEventPaylaod(resource ScimResource) map[string]interface{} {

	var userAttrs []string
	for _, f := range structs.Fields(resource.User) {
		if f.IsZero() {
			continue
		}
		userAttrs = append(userAttrs, f.Name())
	}
	var grpAttrs []string
	for _, f := range structs.Fields(resource.Group) {
		if f.IsZero() {
			continue
		}
		grpAttrs = append(grpAttrs, f.Name())
	}

	attrs := append(userAttrs, grpAttrs...)
	return map[string]interface{}{
		"attributes": attrs,
	}
}
