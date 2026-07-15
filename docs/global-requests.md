# Global requests

RFC 4254 global requests apply to the whole SSH connection rather than one channel. The library
handles forwarding, host-key rotation, keepalives, and session-lockdown requests internally. An
application can use the generic API for additional standardized or private request names.

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

Request names must be non-empty printable ASCII and arguments must be a `Buffer`. A failure reply
rejects with `GlobalRequestError`. Concurrent calls are matched to replies in RFC wire order, and
pending calls reject if the connection closes. The connection's `replyTimeout` also bounds each
reply; expiry rejects the call and closes the connection because a late untagged response cannot
safely be matched to later work. A success or failure response without a pending request is a
protocol error and closes the connection. Request and successful-response packet boundaries copy
their opaque bytes, so caller buffers and received transport frames cannot mutate an in-flight
exchange.

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

Built-in protocol requests are processed by their dedicated validation and policy paths before the
generic hook. Do not treat an unrecognized request name as trusted merely because the SSH peer was
authenticated; authorize every application operation and validate its opaque payload explicitly.
