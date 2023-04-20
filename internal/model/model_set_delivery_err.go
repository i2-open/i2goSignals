package model

type SetDeliveryErr struct {
	ErrCode     string `json:"err"`
	Description string `json:"description""`
}
