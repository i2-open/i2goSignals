package resource

type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

type Address struct {
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Formatted     string `json:"formatted,omitempty"`
	Type          string `json:"type,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

type MultiValuedAttribute struct {
	Value   string
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type GroupValue struct {
	Value   string
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

type User struct {
	Name              Name
	UserName          string `json:"userName,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	ProfileUrl        string `json:"profileUrl,omitempty"`
	Emails            []MultiValuedAttribute
	Addresses         []Address
	PhoneNumbers      []MultiValuedAttribute
	Photos            []MultiValuedAttribute
	UserType          string `json:"userType,omitempty"`
	Title             string `json:"title,omitempty"`
	PreferredLanguage string `json:"preferredLanguage,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	Active            bool   `json:"active,omitempty"`
	Password          string `json:"password,omitempty"`
	Groups            []GroupValue
	X509Certificates  []MultiValuedAttribute
}
