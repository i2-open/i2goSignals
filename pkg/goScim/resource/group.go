package resource

type Group struct {
	DisplayName string `json:"displayName,omitempty"`
	Members     []GroupValue
}
