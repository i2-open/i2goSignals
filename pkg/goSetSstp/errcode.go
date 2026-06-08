package goSetSstp

// ErrCode is an SSTP per-JTI error keyword carried under "setErrs" (draft-hunt-secevent-sstp-00
// §2.3, Table 1). These are reserved strictly for per-JTI errors after a successful body parse;
// non-protocol failures (auth/path/content-type/JSON-parse) are signaled via HTTP status, not
// via this vocabulary.
type ErrCode = string

// SSTP §2.3 Table 1 "SET Errors", mirrored verbatim. The string values are the on-wire keywords.
const (
	// ErrJson: Invalid JSON object.
	ErrJson ErrCode = "json"
	// ErrJwtParse: Invalid or unparsable JWT or JSON structure.
	ErrJwtParse ErrCode = "jwtParse"
	// ErrJwtHdr: An invalid JWT header was detected.
	ErrJwtHdr ErrCode = "jwtHdr"
	// ErrJwtCrypto: Unable to parse due to unsupported algorithm.
	ErrJwtCrypto ErrCode = "jwtCrypto"
	// ErrJws: Signature was not validated.
	ErrJws ErrCode = "jws"
	// ErrJwe: Unable to decrypt JWE encoded data.
	ErrJwe ErrCode = "jwe"
	// ErrJwtAud: Invalid audience value.
	ErrJwtAud ErrCode = "jwtAud"
	// ErrJwtIss: Issuer not recognized.
	ErrJwtIss ErrCode = "jwtIss"
	// ErrSetType: An unexpected Event type was received.
	ErrSetType ErrCode = "setType"
	// ErrSetParse: Invalid structure was encountered such as an inability to parse or an
	// incomplete set of event claims.
	ErrSetParse ErrCode = "setParse"
	// ErrSetData: SET event claims incomplete or invalid.
	ErrSetData ErrCode = "setData"
	// ErrDirectional: The SSTP does not support transfer of SETs in the requested direction.
	ErrDirectional ErrCode = "directional"
)
