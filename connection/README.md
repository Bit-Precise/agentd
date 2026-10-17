# agents connection protocol v1

This package accepts a `net.Conn` supplied by the transport adapter. It neither
establishes TLS nor dials business destinations. The application must authenticate
its Edge/CDN endpoint before sending a token.

The connection starts with a 4-byte big-endian length followed by bounded JSON:
`Hello` then `Welcome`. Unknown JSON fields, unsupported roles/versions and
oversized metadata fail closed. The server must supply `AuthenticateFunc` and
derive `Principal` from a trusted store. Claimed workspace/agent/connector/role
must match that principal. Generation and session ID are assigned by the server.
Provider service declarations in Hello are candidates; they are not approvals.

Only after authentication do the peers start yamux. The client opens a reserved
control stream; both sides finish its handshake before exposing `Session`.
Business streams use bounded `OpenRequest` and an authorized `OpenClaims` reply,
then plain business bytes. The receiver must supply `AuthorizeOpenFunc`; a missing
callback rejects all streams. No capability signature scheme is implemented:
`Capability` is an opaque field whose verification belongs to that callback.

| Session | Allowed business direction | Purpose |
|---|---|---|
| access | client to Edge | `access`: untrusted candidate TLS destination |
| provider | Edge to agentd | `serve`: approved resource name, no arbitrary target |
| provider | Edge to agentd | `egress`: approved TLS destination and resource |

`Open` returns after logical admission, not after a target socket has connected.
The runtime owns dialing and application-level success/error responses. Its
context only bounds opening, like `net.Dialer`; cancelling it after success does
not close the flow. The explicit request deadline and session expiry bound flow
lifetime. An authorizer may shorten the deadline. `Request()` preserves the
proposal; `Claims()` returns the approved view.

`CloseWrite` sends yamux FIN and preserves response reads. `Close` also sends a
bounded control `CANCEL`, cancels the peer stream's `Context`, and immediately
unblocks local IO. Target handlers must watch that context and close their real
sockets. This avoids confusing normal request half-close with authorization
revocation. Slow control writes or exhausted control queues fail the session
closed. Session expiry actively closes the transport and every stream; changing
IO deadlines cannot extend a lease.

Defaults: 5-minute maximum session lifetime, 10-second handshake/OPEN timeouts,
128 active business streams, 16 KiB metadata, 65,536 distinct flow IDs per session.
Closed flow IDs remain in a bounded replay ledger. Once exhausted, reconnect;
flow IDs are never reused in a session. Expiry/renewal messages are not implemented
in this milestone. Callbacks must honor their context and must not log secrets.

Run `go test -mod=readonly -race ./connection`. Tests use real yamux sessions over
`net.Pipe`, including concurrent large flows, invalid authentication, direction
checks, metadata limits, replay rejection, half-close, cancellation and expiry.
