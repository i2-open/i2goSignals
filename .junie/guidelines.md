### i2goSignals AI Development Guidelines

#### General Principles
- **Clean State**: When requested, a clean development environment. Do not rely on artifacts or state from previous sessions unless explicitly instructed.
- **Minimalism**: Make the smallest change necessary to achieve the goal.
- **Related Standards**: The following compliance standards documents apply to this project. The project may extend beyond these standards but should remain compatible with the following:
  - **RFC8417 Security Event Token or SET** : [RFC8417: Guidelines for Writing RFCs and Related Documents](https://tools.ietf.org/html/rfc8417)
  - **RFC8935 Push Delivery of SETs using HTTP**: [RFC8935](https://www.rfc-editor.org/rfc/rfc8935.txt)
  - **RFC8936 Poll Delivery of SETs using HTTP**: [RFC8936](https://www.rfc-editor.org/rfc/rfc8936.txt)
  - **SSF**: [Shared Signals Framework Specification](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.txt)
  - SET Token Event Types
    - **SCIM**: [SCIM Profile for Security Event Tokens](https://www.ietf.org/archive/id/draft-ietf-scim-events-16.txt)
    - **RISC**: [OpenID RISC Profile Specification](https://openid.net/specs/openid-risc-1_0-final.txt)
    - **CAEP**: [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.txt)

#### Planning and Communication
- **Mandatory Planning**: Before making any changes, you MUST create a detailed plan that includes the scope of work.
- **User Confirmation**: You MUST request and receive explicit confirmation from the user before proceeding with the plan.
- **Status Updates**: Use `update_status` frequently to keep the user informed of progress.

#### Testing
- **Test-Driven Enhancements**: For every enhancement, feature, or bug fix, you MUST create or update a corresponding test to validate the change.
- **Test Framework**: Use `github.com/stretchr/testify/suite` for integration tests, especially for server and stream logic.
- **Coverage**: Ensure that new logic is covered by unit or integration tests.
- **Race**: When testing concurrent code, use `go test -race` to detect potential race conditions, but ensure reasonable timeouts or lock detections to ensure tests finish within 5 minutes.

#### Coding Standards
- **Logging**: Use the internal logging package (`github.com/i2-open/i2goSignals/internal/logger`) which uses `slog`. Use `logger.Sub("Component")` to create sub-loggers for specific components.
- **Database**: When interacting with MongoDB, follow existing patterns in `internal/providers/dbProviders/mongo_provider`.
- **Go Version**: The project uses Go 1.25. Ensure all code is compatible.
- **Error Handling**: Use standard Go error handling. Wrap errors with context where appropriate.
- **Quality**: Review probable bugs such as locks passed by value, malformed struct tags, and unhandled errors.
- **Threading**: Check that locks are used to prevent threading issues

#### Artifact Management
- **Cleanup**: Always clean up any debug binaries (`__debug_bin*`), temporary output files, or other artifacts created during the session.
- **Sensitive Info**: Do not commit or log sensitive information (keys, tokens, etc.).

