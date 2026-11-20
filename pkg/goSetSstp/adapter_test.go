package goSetSstp

import (
	"errors"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/stretchr/testify/assert"
)

// TestClassifyFromGoSetPushError covers each goSetPush RFC8935 error class, confirming it maps
// to the corresponding SSTP §2.3 ErrCode so inbound ingestion can emit a per-JTI setErr without
// re-deriving the vocabulary (Q6.1).
func TestClassifyFromGoSetPushError(t *testing.T) {
	tests := []struct {
		name    string
		in      error
		wantErr ErrCode
	}{
		{"invalid_request -> setParse", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrInvalidRequest, Description: "bad"}, ErrSetParse},
		{"invalid_issuer -> jwtIss", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrInvalidIssuer}, ErrJwtIss},
		{"invalid_audience -> jwtAud", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrInvalidAudience}, ErrJwtAud},
		{"invalid_key -> jwtCrypto", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrInvalidKey}, ErrJwtCrypto},
		{"jws_signature_failed -> jws", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrJwsSignatureFailed}, ErrJws},
		{"jwe_decryption_failed -> jwe", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrJweDecryptionFailed}, ErrJwe},
		{"access_denied -> setData", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrAccessDenied}, ErrSetData},
		{"authentication_failed -> setData", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrAuthenticationFailed}, ErrSetData},
		{"not_found -> setData", &goSetPush.DeliveryErr{ErrCode: goSetPush.ErrNotFound}, ErrSetData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyFromGoSetPushError(tt.in)
			assert.Equal(t, tt.wantErr, got.Err)
			// Description from the source DeliveryErr is preserved when present.
			var de *goSetPush.DeliveryErr
			if errors.As(tt.in, &de) && de.Description != "" {
				assert.Equal(t, de.Description, got.Description)
			}
		})
	}
}

// TestClassifyFromGoSetPushError_NilAndUnknown: nil yields no error; an unrecognized error maps
// to the generic setParse code so ingestion never crashes on an unexpected shape.
func TestClassifyFromGoSetPushError_NilAndUnknown(t *testing.T) {
	none, ok := classifyOrNil(nil)
	assert.False(t, ok)
	assert.Equal(t, SetErr{}, none)

	got := ClassifyFromGoSetPushError(errors.New("some non-DeliveryErr failure"))
	assert.Equal(t, ErrSetParse, got.Err)
	assert.Equal(t, "some non-DeliveryErr failure", got.Description)
}

// classifyOrNil is a test helper expressing the "nil error -> no SetErr" contract via the public
// adapter; ClassifyFromGoSetPushError(nil) returns the zero SetErr.
func classifyOrNil(err error) (SetErr, bool) {
	if err == nil {
		return ClassifyFromGoSetPushError(nil), false
	}
	return ClassifyFromGoSetPushError(err), true
}
