### Task 3: Router Refactoring - Wake-up Logic

#### Objective
Refactor `HandleEvent` in the router to consult leases and send wake-up calls when necessary.

#### Requirements
1.  Add `WakeTransmitter(sid string, mode string)` to `EventRouter` interface and implement in `router`.
2.  In `HandleEvent`:
    - After `AddEventToStream`, look up the owner node ID of the transmitter lease:
        - `push-transmitter:<sid>` for push streams.
    - If the owner node ID is this node, enqueue to local buffer.
    - If the owner node ID is different, call `POST /_cluster/wake-transmitter` on that node.
    - Use HMAC to sign the wake-up request.
3.  Implement rate-limiting/coalescing for outbound wake-ups (within 250ms).
4.  Handle poll streams: Waking a poll transmitter is optional but useful to end long polls (`pollBuffer.Wakeup()`).
5.  Add unit tests for `HandleEvent` with lease lookup and wake-up.

#### Definition of Done
- Lease-aware routing implemented.
- Outbound wake-up calls made correctly.
- Rate limiting for outbound wake-ups works.
- Local enqueuing still works.
