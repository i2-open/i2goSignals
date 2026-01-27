package events

import "github.com/i2-open/i2goSignals/pkg/goSet"

type VerifyPayload struct {
	State string `json:"state,omitempty"`
}

const VerificationEventUri = "https://schemas.openid.net/secevent/ssf/event-type/verification"

func CreateVerifyEvent(streamId string, state string, issuer string, audience []string) *goSet.SecurityEventToken {
	var subject *goSet.EventSubject
	if streamId != "" {
		subject = &goSet.EventSubject{
			SubjectIdentifier: goSet.SubjectIdentifier{
				Format: "opaque",
				OpaqueIdentifier: goSet.OpaqueIdentifier{
					Id: streamId,
				},
			},
		}
	}

	set := goSet.CreateSet(subject, issuer, audience)

	payload := VerifyPayload{
		State: state,
	}
	set.AddEventPayload(VerificationEventUri, payload)

	return &set
}
