package resource

import (
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
)

type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      time.Time
	LastModified time.Time
	Version      string
	Location     string
}

type Extensions map[string]interface{}

type ScimResource struct {
	Schemas    []string `json:"schemas"`
	Id         string
	ExternalId string
	Meta       Meta
	User       User
	Group      Group
	Extensions Extensions
}

func GenerateFakeUser(basePath string) ScimResource {
	person := gofakeit.Person()
	address := person.Address

	scimAddr := Address{
		StreetAddress: address.Street,
		Locality:      address.City,
		Region:        address.State,
		Country:       address.Country,
		PostalCode:    address.Zip,
	}

	scimName := Name{
		FamilyName: person.LastName,
		GivenName:  person.FirstName,
		MiddleName: gofakeit.MiddleName(),
	}

	createdTime := time.Now()

	ident := ids.NewObjectID()

	resource := ScimResource{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		Id:         ident,
		ExternalId: "",
		Meta: Meta{
			Created:      createdTime,
			LastModified: createdTime,
			Location:     basePath + "/" + ident,
		},
		User: User{
			Name:      scimName,
			UserName:  gofakeit.Username(),
			Addresses: []Address{scimAddr},
			Emails: []MultiValuedAttribute{
				{
					Value:   gofakeit.Email(),
					Type:    "work",
					Primary: false,
				},
			},
			DisplayName: person.FirstName + " " + person.LastName,
			ProfileUrl:  person.Image,
		},

		Extensions: nil,
	}
	return resource
}
