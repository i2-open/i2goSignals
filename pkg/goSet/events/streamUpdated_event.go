package events

import "github.com/i2-open/i2goSignals/pkg/goSet"

type StreamUpdatePayload struct {
	Status string  `json:"status,omitempty"`
	Reason *string `json:"reason,omitempty"`
}

const StatusUpdatedEventUri = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"

func CreateStatusUpdatedEvent(streamId string, status string, reason string, issuer string, audience []string) *goSet.SecurityEventToken {
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

	var reasonPay *string
	if reason != "" {
		reasonPay = &reason
	}

	payload := StreamUpdatePayload{
		Status: status,
		Reason: reasonPay,
	}
	set.AddEventPayload(StatusUpdatedEventUri, payload)

	return &set
}
