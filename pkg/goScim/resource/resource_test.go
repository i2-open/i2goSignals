package resource

import (
	"fmt"
	"i2goSignals/pkg/goSet"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
)

func TestUserResource(t *testing.T) {
	person := gofakeit.Person()
	job := person.Job
	address := person.Address
	contact := person.Contact
	creditCard := person.CreditCard

	fmt.Println(person.FirstName)
	fmt.Println(person.LastName)
	fmt.Println(person.Gender)
	fmt.Println(person.SSN)
	fmt.Println(person.Image)
	fmt.Println(person.Hobby)

	fmt.Println(job.Company)
	fmt.Println(job.Title)
	fmt.Println(job.Descriptor)
	fmt.Println(job.Level)

	fmt.Println(address.Address)
	fmt.Println(address.Street)
	fmt.Println(address.City)
	fmt.Println(address.State)
	fmt.Println(address.Zip)
	fmt.Println(address.Country)
	fmt.Println(address.Latitude)
	fmt.Println(address.Longitude)

	fmt.Println(contact.Phone)
	fmt.Println(contact.Email)

	fmt.Println(creditCard.Type)
	fmt.Println(creditCard.Number)
	fmt.Println(creditCard.Exp)
	fmt.Println(creditCard.Cvv)

}

func TestCreateEvent(t *testing.T) {
	user := GenerateFakeUser("ascim.example.com/Users")

	fullPayload := CreateFullEventPayload(user)
	noticePayload := CreateNoticeEventPaylaod(user)

	subId := goSet.NewScimSubjectIdentifier(user.Meta.Location)
	var subject goSet.EventSubject
	subject.SubjectIdentifier = *subId
	createEvent := goSet.CreateSet(&subject, "ascim.example.com", []string{"aud.example.com"})
	createEvent.AddEventPayload("urn:ietf:params:SCIM:event:prov:create:full", fullPayload)

	fmt.Println("Create Event:\n" + createEvent.String())
	createEventNotice := goSet.CreateSet(&subject, "ascim.example.com", []string{"aud.example.com"})

	createEventNotice.AddEventPayload("urn:ietf:params:SCIM:event:prov:create:notice", noticePayload)

	fmt.Println("Create Notice Event:\n" + createEventNotice.String())
}
