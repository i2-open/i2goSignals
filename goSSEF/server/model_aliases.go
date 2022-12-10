/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification. 
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package server

// [Spec](https://datatracker.ietf.org/doc/html/draft-ietf-secevent-subject-identifiers#section-3.2.2)  The Aliases Identifier Format describes a subject that is identified with a list of different Subject Identifiers.  It is intended for use when a variety of identifiers have been shared with the party that will be interpreting the Subject Identifier, and it is unknown which of those identifiers they will recognize or support.  Subject Identifiers in this format MUST contain an \"identifiers\" member whose value is a JSON array containing one or more Subject Identifiers. Each Subject Identifier in the array MUST identify the same entity. The \"identifiers\" member is REQUIRED and MUST NOT be null or empty. It MAY contain multiple instances of the same Identifier Format (e.g., multiple Email Subject Identifiers), but SHOULD NOT contain exact duplicates.  This format is identified by the name \"aliases\".  \"alias\" Subject Identifiers MUST NOT be nested; i.e., the \"identifiers\" member of an \"alias\" Subject Identifier MUST NOT contain a Subject Identifier in the \"aliases\" format.'
type Aliases struct {

	Format string `json:"format"`

	Identifiers []SimpleSubject `json:"identifiers"`
}
