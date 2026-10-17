# Modified XHTTP packet-up transport

This is an agents-specific packet-up variant inspired by the fixed Xray-core
source identified in [NOTICE](NOTICE). It uses only the Go standard library. It
does **not** implement VLESS, Reverse, Xray Mux, stream-one, or full native XHTTP
wire compatibility. Transport connections carry arbitrary bytes; agents owns
Workspace/role identity, application framing, authorization and business flows.

## API

```go
h, err := xhttp.NewHandler(xhttp.ServerConfig{
    Authorize: func(r *http.Request) (string, error) {
        // Validate the credential on EVERY request. Return a stable opaque
        // authenticated subject/session identifier, never an unchecked header.
        return verifyTransportCredential(r)
    },
})
// Mount h at one exact endpoint on an HTTPS server.
conn, err := h.Accept(ctx)

clientConn, err := xhttp.Dial(ctx, "https://edge.example/agent", xhttp.ClientConfig{
    Headers: http.Header{"Authorization": {"Bearer " + token}},
})
```

`Handler` implements `http.Handler`, `Accept(context.Context) (net.Conn, error)`,
`Close() error`, and `ActiveSessions() int`. `Close` rejects new sessions,
unblocks Accept, closes existing accepted/pending connections, and interrupts
in-flight response writes and POST body reads. The caller owns the surrounding
`http.Server`, its TLS configuration, header limits, and pre-authentication
connection/request limits. A wrapper must preserve `http.ResponseController`
support (`Unwrap` when wrapping ResponseWriter).

`AuthenticatedPrincipal(acceptedConn)` returns the immutable opaque principal
bound by the server authorizer, so a higher-level handshake can enforce identity
consistency. It returns no identity for client-side or unrelated connections;
the returned value is a verified identifier, never the original bearer token.

HTTPS is the default on both ends. `AllowHTTP: true` permits **loopback only** for
tests/local reverse-proxy deployment, not public plaintext endpoints. The
transport rejects redirects even if an injected `HTTPClient` would follow them.
Endpoint allowlisting and safe credential storage remain application duties.

An injected `ClientConfig.HTTPClient` supplies certificate trust, optional proxy
settings and pooling. Its `Timeout` must be zero because the GET is long-lived.
For HTTP/1.1 its transport must permit at least two connections to the origin:
one for GET and another for POST. HTTP/2 is supported and tested. An injected
client/transport is caller-owned; its shared pool is not closed by this package.

## Wire format and authorization

* GET `endpoint?session=<128-bit random hex>` establishes a download/session.
* POST the same endpoint with `session` and canonical decimal `seq` query
  parameters, starting at zero, uploads one nonempty bounded packet.
* Both requests require `X-Agents-XHTTP-Version: 1` and pass `Authorize`.
* GET returns 200, the version header, then the raw download bytes. POST returns
  204 and the version header when its packet has entered the bounded receiver.
* Sessions bind the authorizer's opaque principal and escaped endpoint path.
  A different principal/path cannot upload into an existing session. Another
  GET cannot attach to or replace an existing session.
* A session ID correlates HTTP requests; it is **not** a bearer credential.
  The authorizer must distinguish scopes that must not share a transport
  identity. Empty principals, missing authorizers and failed authorization are
  rejected. Authorization is checked on every request, including every POST.
* Exact duplicate packets within the bounded recent-history window are
  idempotent. Conflicting duplicates and unverifiable older duplicates return
  409. Out-of-order packets are reordered within a configured window; gaps
  outside that window are rejected. Packets never reach the consumer twice.
* Normal sequential upload waits for receiver capacity when buffers fill;
  bounded POST concurrency and timeout still apply. There is no automatic
  retry/resume/replay after a failed POST or disconnected session.

`Authorize` does not continuously revalidate an already-open GET. The agents
session owner must close its accepted connection on lease expiry/revocation;
per-request authorization and transport idle timeout do not replace application
leases. Reconnection starts a new transport session and never replays bytes.

## Limits and lifecycle

Defaults (`0` selects the default; negative/invalid limits are rejected):

| Server option | Default |
|---|---:|
| MaxSessions | 64 |
| MaxSessionsPerPrincipal | min(8, MaxSessions) |
| MaxPacketBytes | 32 KiB |
| MaxQueuedPackets, MaxReorderPackets | 8 each |
| MaxConcurrentPosts, MaxPostsPerSession | 64, 4 |
| SessionIdleTimeout | 2 minutes |
| PostTimeout | 15 seconds |
| WriteTimeout (HTTP response flush) | 30 seconds |

Client defaults are PacketSize 32 KiB, MaxQueuedPackets 8, HandshakeTimeout 10
seconds, and PostTimeout 15 seconds. Client PacketSize must not exceed the
server's MaxPacketBytes; there is no implicit packet-size negotiation. Memory
is bounded by configured session, packet, queue, reorder and POST-concurrency
limits. Configure conservative aggregate limits rather than multiplying every
maximum together. Idle sessions, including unaccepted ones, are removed.

Dial's context owns both setup and connection lifetime. Cancelling it closes
the GET, pending POST and logical connection. `SetReadDeadline` is real, wakes
blocked reads when changed, and can be reset without closing the connection.
Write deadlines also wake blocked writes and cancel in-flight POSTs. A timeout
after an upload/downstream write has begun closes the logical connection because
delivery is uncertain; callers must not retry that write on the same stream.
Successful server Write means its packet was written and flushed to HTTP, not
that the remote application consumed it. Concurrent Read/Write is supported;
concurrent Writes are serialized without interleaving their bytes.

This `net.Conn` has full close, not TCP half-close. Use agents stream FIN/RST for
business half-close. Addresses are diagnostic transport addresses, never
authenticated device identities. Read/Write/deadline behavior does not assume
Xray's no-op deadline implementation.

## CDN deployment and verification

The endpoint sends `Cache-Control: no-store, no-transform`,
`X-Accel-Buffering: no` and flushes response data. These are requests to the
intermediary, not a guarantee of CDN behavior. Configure cache bypass, streaming
GET responses, credential/header/query forwarding, request size/rate limits,
HTTPS origin authentication, and session-affine origin routing. All requests of
one session must reach the same Handler owner. Uploads are bounded POSTs, so
streaming request-body forwarding is not required. `stream-one` is not used as
a CDN default. Client-side HTTP/2 does not guarantee HTTP/2 to the origin.

Local tests cover TLS HTTP/1.1 and HTTP/2, concurrent bidirectional transfer,
bounded slow-consumer backpressure, limits, reordering/duplicates, authorization
isolation, timeout changes, cancellation and handler/session cleanup:

```sh
go test -race ./transport/xhttp
```

No real CDN has been qualified by these tests. Header/request flood limits and
authorization callback cost must also be enforced at the deployment front door.
