### Task 2: Internal Wake-up API & HMAC Auth

#### Objective
Implement the `POST /_cluster/wake-transmitter` endpoint and secure it with HMAC authentication.

#### Requirements
1.  Implement HMAC middleware for inter-node communication.
    - Uses `CLUSTER_INTERNAL_TOKEN` as the secret.
    - Validates incoming requests on the cluster wake port.
2.  Add `POST /_cluster/wake-transmitter` to the server logic in `pkg/goSignals/server/application.go` or a dedicated internal router.
    - Request body: `{ "sid": "string", "mode": "push"|"poll" }`
    - Response: `202 Accepted`.
3.  The handler should call `router.WakeTransmitter(sid, mode)`.
4.  Implement rate-limiting/de-duplication for incoming wake-ups (e.g., coalesce requests for the same `sid`+`mode` within 250ms).
5.  Add unit/integration tests for the endpoint and HMAC auth.

#### Definition of Done
- HMAC middleware implemented and tested.
- Wake-up endpoint active and reachable.
- Rate limiting works as expected.
- Handler correctly calls the router.
