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
* Clients send `X-Agents-XHTTP-Version: 2`. Servers also accept version 1,
  whose clients upload one packet at a time, and echo the version they
  accepted; any other version is rejected with 400. Upgrade Edge before
  clients: a version 2 client is rejected by a version 1 server at GET.
* Every request must pass `Authorize`.
* GET returns 200, the version header, then the raw download bytes. POST returns
  204 and the version header when its packet has entered the session's queue.
* Sessions bind the authorizer's opaque principal and escaped endpoint path.
  A different principal/path cannot upload into an existing session. Another
  GET cannot attach to or replace an existing session.
* A session ID correlates HTTP requests; it is **not** a bearer credential.
  The authorizer must distinguish scopes that must not share a transport
  identity. Empty principals, missing authorizers and failed authorization are
  rejected. Authorization is checked on every request, including every POST.
* Uploads follow Xray-core's packet-up design (see [NOTICE](NOTICE)). The
  client buffers writes, sends everything buffered since the previous POST as
  one packet, and starts the next POST once the previous request has been
  written, without waiting for its response. POST starts are spaced by
  `MinPostsInterval`.
* As in Xray's upload queue, the server reorders packets by sequence and drops
  any packet older than the next expected one, so repeated POSTs are
  idempotent and a packet never reaches the consumer twice. Exactly one copy
  of each sequence is delivered and copies are not compared, so only the
  session's own authorized principal and path can affect its bytes.
* A full queue blocks POST handlers until the reader consumes, which is the
  upload backpressure. More than `MaxBufferedPosts` packets waiting behind a
  missing sequence close the session instead of buffering without bound.
* A failed POST closes the logical connection. There is no automatic
  retry/resume/replay after a failed POST or disconnected session.

`Authorize` does not continuously revalidate an already-open GET. The agents
session owner must close its accepted connection on lease expiry/revocation;
per-request authorization and transport idle timeout do not replace application
leases. Reconnection starts a new transport session and never replays bytes.

## Limits and lifecycle

Defaults (`0` selects the default; negative/invalid limits are rejected). The
first three follow Xray-core's `scMaxEachPostBytes`, `scMaxBufferedPosts` and
`scMinPostsIntervalMs` defaults:

| Server option | Default |
|---|---:|
| MaxEachPostBytes | 1,000,000 bytes |
| MaxBufferedPosts | 30 |
| MaxPostsPerSession | MaxBufferedPosts |
| MaxConcurrentPosts | 256 |
| MaxSessions | 64 |
| MaxSessionsPerPrincipal | min(8, MaxSessions) |
| MaxQueuedPackets (download) | 8 |
| SessionIdleTimeout | 2 minutes |
| PostTimeout | 15 seconds |
| WriteTimeout (HTTP response flush) | 30 seconds |

| Client option | Default |
|---|---:|
| MaxEachPostBytes | 1,000,000 bytes |
| MinPostsInterval | 30 ms |
| MaxQueuedPackets (download) | 8 |
| HandshakeTimeout | 10 seconds |
| PostTimeout | 15 seconds |

Client MaxEachPostBytes must not exceed the server's; there is no implicit
size negotiation. POSTs beyond MaxPostsPerSession or MaxConcurrentPosts wait
for a slot, bounded by PostTimeout, instead of being rejected, because a
pipelined client treats a rejected POST as a lost byte range. The global slot
covers reading the body only. Server memory per session is bounded by roughly
(MaxPostsPerSession + 2 × MaxBufferedPosts) × MaxEachPostBytes, about 90 MB
with the defaults; size these limits to the Edge rather than multiplying every
maximum together. Idle sessions, including unaccepted ones, are removed.

Dial's context owns both setup and connection lifetime. Cancelling it, or
Close, ends the GET and every in-flight POST and discards buffered upload
bytes. `SetReadDeadline` is real, wakes blocked reads when changed, and can be
reset without closing the connection. Client Write returns once its bytes are
buffered, like a TCP socket; the write deadline bounds only the wait for buffer
space, which holds one MaxEachPostBytes packet. A POST that does not complete
within PostTimeout closes the connection. Successful server Write means its
packet was written and flushed to HTTP, not that the remote application
consumed it; a server write deadline that expires after a write has begun
closes the connection because delivery is uncertain. Concurrent Read/Write is
supported; concurrent Writes are serialized without interleaving their bytes.

Over HTTP/1.1 the standard library opens one connection per concurrent POST.
HTTP/2 multiplexes them on one connection and its flow control limits how many
POST bodies are in flight.

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
pipelined and coalesced uploads, slow-consumer backpressure, reorder backlog
limits, duplicates, legacy version 1 clients, authorization isolation, timeout
changes, cancellation and handler/session cleanup:

```sh
go test -race ./transport/xhttp
```

No real CDN has been qualified by these tests. Header/request flood limits and
authorization callback cost must also be enforced at the deployment front door.

Server embeddings behind a trusted HTTPS ingress may explicitly set
`ServerConfig.TLSOffload`. This permits plaintext only on that backend listener;
HTTP authorization and all transport checks remain mandatory. It is not inferred
from `Forwarded` or `X-Forwarded-Proto`, and the backend listener must be protected
from untrusted direct access. `AllowHTTP` remains a loopback-only development
exception. The agent's public endpoint continues to require HTTPS.
