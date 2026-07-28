---
title: Global requests
description: Promise-based connection-wide requests and awaited application handlers.
---

# Global requests

RFC 4254 global requests apply to the whole SSH connection rather than one channel. The library
handles forwarding, host-key rotation, keepalives, and session-lockdown requests internally. An
application can use the generic API for additional standardized or private request names.

Both connection roles include the
[`global-requests-ok`](https://datatracker.ietf.org/doc/draft-ssh-global-requests-ok/) RFC 8308
extension in their initial negotiated extension set with its required empty value. It declares that
the sender correctly handles global requests after authentication and while a rekey is in progress.
`Client.serverSupportsGlobalRequests` and `ServerClient.clientSupportsGlobalRequests` report whether
the latest complete peer extension set contains that name. Recognition is intentionally based on
the name alone: the draft requires receivers to tolerate opaque future values. A later server
extension set which omits the name clears the client property.

The extension does not authorize requests and does not permit sending them before authentication.
Public sending APIs remain unavailable until authentication completes, and received private
requests still pass through the deny-by-default policy described below.

`GLOBAL_REQUESTS_OK_EXTENSION` exports the exact name for applications constructing a complete
authentication-time replacement with `ServerClient.sendAuthenticationExtensions()`. Include it
with an empty `Buffer` when the replacement should preserve the advertisement.

Periodic keepalives are reply-requesting `keepalive@openssh.com` messages. Both success and failure
prove liveness. Client options configure the outbound client timer; matching server options create
one timer per authenticated connection. Missing replies are bounded, while an ordinary failure is
never treated as a timeout.
Periodic probes remain governed by `keepaliveInterval` and `keepaliveCountMax`; the general
`replyTimeout` below applies to application and protocol operations that expect one reply.

## Sending from a client

`Client.globalRequest()` sends a reply-requesting `SSH_MSG_GLOBAL_REQUEST` after authentication and
resolves with the opaque bytes from `SSH_MSG_REQUEST_SUCCESS`:

```ts
const response = await client.globalRequest(
    "query@example.com",
    Buffer.from("opaque request bytes"),
)
```

Request names follow the RFC 4251 name grammar: 1–64 printable US-ASCII characters, no comma, and
at most one non-leading `@` followed by a valid DNS domain. Arguments must be a `Buffer`. Invalid
input rejects before allocating a pending request or writing a packet. A failure reply rejects with
`GlobalRequestError`. Concurrent calls are matched to replies in RFC wire order, and pending calls
reject if the connection closes. The connection's `replyTimeout` also bounds each reply; expiry
rejects the call and closes the connection because a late untagged response cannot safely be
matched to later work. A success or failure response without a pending request is a protocol error
and closes the connection. Request and successful-response packet boundaries copy their opaque
bytes, so caller buffers and received transport frames cannot mutate an in-flight exchange.
If a peer instead sends RFC 4253 `SSH_MSG_UNIMPLEMENTED`, its packet sequence number rejects the
exact matching call immediately with `GlobalRequestError`. That request is removed from the FIFO
reply queue, later requests remain correctly matched, and the connection stays open.

Accepted server connections expose the same API on `ServerClient`, for connection-wide requests
directed at an SSH client:

```ts
import { once } from "node:events"

const [connection] = await once(server, "connection")
await once(connection, "connect")

const response = await connection.globalRequest(
    "query-client@example.com",
    Buffer.from("opaque request bytes"),
)
console.log(response)
```

It has the same validation, FIFO matching, rekey queuing, and close-settlement rules. Failure
replies reject with `ServerGlobalRequestError`.

## Receiving application requests

Unknown global requests are denied by default. Both client and server expose an awaited
`globalRequest` hook for application policy. The context contains a copied opaque argument buffer
and whether the sender requested a reply. Set `success` only after completing the requested work;
an optional response must be a `Buffer`.

```ts
server.hooker.hook("globalRequest", async (_hook, context, controller, connection) => {
    if (context.name !== "reload@example.com") return

    await reloadConfiguration(connection)
    controller.success = true
    controller.response = Buffer.from("reloaded")
})
```

The same hook is available on `client.hooker` without the final connection argument. Requests are
dispatched serially so awaited handlers cannot reorder success or failure replies. A one-way
request still invokes the hook, but the library sends no reply regardless of the controller.
In both peer roles, success is honored only when every registered handler completes without
rejection. Hooker reports a contained failure through `uncaughtException`, and any success or
response left by an earlier handler is discarded.
If the connection closes while a hook is pending, its eventual decision is discarded. In
particular, a late forwarding-policy result cannot create a listening socket after connection
cleanup, and a late application result cannot send a reply on the closed transport.

The per-connection action scheduler retains at most 1024 operations waiting behind active global
or channel work. The operation currently executing does not consume that waiting allowance, and
independent channel keys may continue concurrently. Exceeding the bound terminates the connection:
one-way requests have no failure response with which to apply backpressure safely. Transport close
rejects both active and queued operation Promises, and a later reconnect uses a fresh scheduler so
old work cannot run against new connection state. A handler already executing cannot be cancelled,
but its eventual decision is discarded by the connection-generation checks above.

Built-in protocol requests are processed by their dedicated validation and policy paths before the
generic hook. Do not treat an unrecognized request name as trusted merely because the SSH peer was
authenticated; authorize every application operation and validate its opaque payload explicitly.

## Host-key updates

The client and server implement the current
[SSHM host-key update draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-hostkey-update/)
alongside its deployed compatibility names. A server with host keys advertises the exact RFC 8308
extension value `hostkeys=0`. When `sendAllHostKeys` is enabled, it sends one post-authentication
host-key advertisement. The default `hostKeyAdvertisementFormat: "compatibility"` remains usable by
clients that predate extension negotiation. Set it to `"standard"` to send the draft's `hostkeys`
request instead. A client that received `hostkeys=0` requests possession proofs with the standard
`hostkeys-prove` request; both advertisement forms are accepted.

The standard request name and its signed domain separator are intentionally different:
`hostkeys-prove` is the global request, while each proof signs `hostkeys-prove-0`, the initial
session identifier, and the exact public-key blob. Compatibility proofs use
`hostkeys-prove-00@openssh.com` in both places. Keeping the domains separate prevents a signature
from one form being replayed as the other.

Advertisements are one-way, may occur at most once per transport, must contain unique keys, and
are limited to 64 entries. Proof requests use the same entry limit and reject empty, duplicate,
malformed, or uncontrolled keys as one failed request. The client emits `hostKeys` only for keys
whose ordered proof verifies; a failure never turns an advertised key into a trusted key.

RSA proofs follow the signature algorithm selected by the initial key exchange. An initial
`rsa-sha2-256` or `rsa-sha2-512` exchange requires that same algorithm for every RSA proof. With a
non-RSA initial host key, the server uses RSA-SHA2 for any additional RSA key. Proof requests fail
after an explicitly configured RSA-SHA1 initial exchange.
