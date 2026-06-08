package goSetSstp

import (
	"errors"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
)

// ClassifyFromGoSetPushError adapts an error produced by the RFC8935 ingestion path
// (goSetPush.ParseReceivedSET, which returns a *goSetPush.DeliveryErr) into an SSTP per-JTI
// SetErr using the §2.3 vocabulary. This keeps inbound ingestion clean: the SSTP server reuses
// goSetPush to parse each SET (they are byte-identical on the wire) and translates any rejection
// here into the one place the SSTP error vocabulary lives (Q6.1).
//
// A nil error yields the zero SetErr. An error that is not a *goSetPush.DeliveryErr (or carries
// an unrecognized RFC8935 code) maps to ErrSetParse with the error's message as the description,
// so ingestion never crashes on an unexpected shape.
func ClassifyFromGoSetPushError(err error) SetErr {
	if err == nil {
		return SetErr{}
	}

	var de *goSetPush.DeliveryErr
	if !errors.As(err, &de) {
		return SetErr{Err: ErrSetParse, Description: err.Error()}
	}

	return SetErr{Err: pushErrToSstpErr(de.ErrCode), Description: de.Description}
}

// pushErrToSstpErr maps an RFC8935 §2.4 error code to its closest SSTP §2.3 Table 1 keyword.
func pushErrToSstpErr(code string) ErrCode {
	switch code {
	case goSetPush.ErrInvalidIssuer:
		return ErrJwtIss
	case goSetPush.ErrInvalidAudience:
		return ErrJwtAud
	case goSetPush.ErrInvalidKey:
		return ErrJwtCrypto
	case goSetPush.ErrJwsSignatureFailed:
		return ErrJws
	case goSetPush.ErrJweDecryptionFailed:
		return ErrJwe
	case goSetPush.ErrAccessDenied, goSetPush.ErrAuthenticationFailed, goSetPush.ErrNotFound:
		// No directional/authorization SSTP keyword exists; the rejection is about the SET's
		// claims/eligibility, which setData best describes.
		return ErrSetData
	case goSetPush.ErrInvalidRequest:
		return ErrSetParse
	default:
		return ErrSetParse
	}
}
