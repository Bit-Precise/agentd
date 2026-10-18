# agents connection protocol v3

This package accepts a `net.Conn` supplied by the transport adapter. It neither
establishes TLS nor dials business destinations. The application must authenticate
its Edge/CDN endpoint before sending a token.

The connection starts with a 4-byte big-endian length followed by bounded JSON:
`Hello` then `Welcome`. Unknown JSON fields, unsupported roles/versions and
oversized metadata fail closed. The server must supply `AuthenticateFunc` and
derive `Principal` from a trusted store. Claimed workspace/agent/connector/role
must match that principal. Generation and session ID are assigned by the server.
Version 3 removes the approval revision and provider declarations from Hello:
each flow is authorized by content, from the Control-computed effective
configuration and the receiver's local policy, so an unrelated configuration
change never requires a new session. `OpenRequest.Revision` records the
effective revision the opener decided on and is informational. Older peers are
rejected at handshake; rebuild agents and agentd together when upgrading.

Only after authentication do the peers start yamux. The client opens a reserved
control stream; both sides finish its handshake before exposing `Session`.
Business streams use bounded `OpenRequest` and an authorized `OpenClaims` reply,
then plain business bytes. The receiver must supply `AuthorizeOpenFunc`; a missing
callback rejects all streams. No capability signature scheme is implemented:
`Capability` is an opaque field whose verification belongs to that callback.

| Session | Allowed business direction | Purpose |
|---|---|---|
| access | client to Edge | `access`: untrusted candidate TLS destination |
| provider | Edge to agentd | `serve`: authorized resource name, no arbitrary target |
| provider | Edge to agentd | `egress`: authorized TLS destination and resource |

`Open` returns after logical admission, not after a target socket has connected.
The runtime owns dialing and application-level success/error responses. Its
context only bounds opening, like `net.Dialer`; cancelling it after success does
not close the flow. `Deadline` is the immutable hard lifetime, bounded by session
expiry. `LeaseExpiresAt`, when supplied, is a shorter renewable authorization
lease. Expiration of either closes the stream's Context and both peers' flow.
`Request()` preserves the original proposal; `Claims()` exposes the current
acknowledged lease. A zero LeaseExpiresAt retains fixed-deadline SDK operation
and cannot subsequently be upgraded to renewable mode. Production Edge always
issues a short lease.

Only the server/Edge side may call `Stream.RenewLease(ctx, expiresAt)`. RENEW and
RENEW_ACK use a strictly increasing per-flow sequence on the authenticated control
stream. The receiver cannot change resource, Agent/session, destination, protocol,
revision, or hard Deadline. Provider receivers invoke the existing AuthorizeOpen
callback again to check their current local and effective capabilities. Access clients
accept only the already authenticated Edge's lease for their existing flow.

An ACK must arrive before the previous lease expires. Missing/rejected ACK closes
that flow; the sender never extends its lease optimistically. A receiver whose
ACK is lost may hold only the newly validated bounded lease and then expires
locally, even if CANCEL also cannot arrive. Replayed sequences, closed/expired
flows and late timer callbacks cannot resurrect a flow. Renewal preserves shorter
caller-specified IO deadlines. Both endpoints enforce a configurable
MaxLeaseDuration with a strict upper bound of 60 seconds for leases they issue,
plus `MaxClockSkew` for leases stamped by the peer.

`CloseWrite` sends yamux FIN and preserves response reads. `Close` also sends a
bounded control `CANCEL`, cancels the peer stream's `Context`, and immediately
unblocks local IO. Target handlers must watch that context and close their real
sockets. This avoids confusing normal request half-close with authorization
revocation. Slow control writes or exhausted control queues fail the session
closed. Session expiry actively closes the transport and every stream; changing
IO deadlines cannot extend a lease.

Defaults: 5-minute maximum session lifetime, 10-second handshake/OPEN timeouts,
128 active business streams, 16 KiB metadata, and a replay ledger of 65,536
active or recently closed flow IDs per session. A closed or cancelled flow ID
stays in the ledger for `FlowTombstoneTTL` (5 minutes, at least twice the OPEN
timeout and lease maximum) and is then forgotten, so a long-lived session keeps
admitting flows; the ledger limit only bounds the rate. Session expiry itself is
not renewed. The generic SDK still defaults to a 5-minute hard session; the
agents runtime explicitly requests up to 24 hours, bounded by its identity and
effective configuration. The Edge's default flow hard limit is 12 hours, with a
55-second renewable lease. AuthorizeOpen callbacks must be safe for repeated
renewal checks, honor their context, and never log secrets. A lease stamped by
the peer's clock is accepted up to `MaxLeaseDuration + MaxClockSkew` (60 + 30
seconds by default); a side never issues a lease beyond its own strict maximum.
Clocks should still be synchronized: skew larger than the allowance rejects
OPEN and renewal, and a fast receiver clock shortens its local view of a lease.

Run `go test -mod=readonly -race ./connection`. Tests use real yamux sessions over
`net.Pipe`, including concurrent large flows, invalid authentication, direction
checks, metadata limits, replay rejection, half-close, cancellation, renewal
reauthorization, missing ACK, explicit IO deadlines and expiry.
