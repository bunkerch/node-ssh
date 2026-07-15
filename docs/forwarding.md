# TCP/IP forwarding channels

`forwardOut()` opens an RFC 4254 `direct-tcpip` channel. It describes the original connection and
the destination to the SSH server and resolves to a flow-controlled `ClientTCPIPChannel`, which is
a Node.js `Duplex` stream.

```ts
const tunnel = await client.forwardOut(
    "127.0.0.1", // originator address
    51_234, // originator port
    "database.internal", // destination visible to the SSH server
    5432, // destination port
)

localSocket.pipe(tunnel).pipe(localSocket)
```

The addresses are protocol metadata; the library does not create the destination socket itself.
The receiving server decides whether the request is allowed and connects or otherwise services the
stream. Ports are validated as unsigned 16-bit TCP port numbers before a packet is sent. Address
and socket-path text must be valid UTF-8 on the wire; malformed input is rejected before it reaches
an authorization hook, listener lookup, or channel event.

Forwarding channels consume the same connection-wide `maxChannels` allowance as sessions, X11,
agent forwarding, and other channels. This bounds accepted network connections even when an
application or remote forwarding listener can produce them faster than they close.

## HTTP and HTTPS agents

`HTTPAgent` and `HTTPSAgent` integrate direct forwarding with Node's `http` and `https` clients.
The explicit `SSHHTTPAgent` and `SSHHTTPSAgent` names are aliases for the same classes. Each HTTP
socket establishes an authenticated SSH connection and then opens one `direct-tcpip` channel to the
request destination. Standard agent pooling can keep that channel and its SSH connection alive for
later requests.

```ts
import { once } from "node:events"
import https from "node:https"
import { finished } from "node:stream/promises"
import { HTTPSAgent } from "@bunkerch/modernssh"

const agent = new HTTPSAgent(
    {
        hostname: "gateway.example",
        port: 22,
        username: "deploy",
        agent: signingAgent,
        hostVerifier: verifyGatewayHostKey,
    },
    { keepAlive: true, sourceHost: "build-runner.example" },
)

const request = https.get("https://service.internal/health", { agent })
const [response] = await once(request, "response")
response.pipe(process.stdout)
await finished(response)
```

For HTTPS, TLS is negotiated end-to-end over the SSH channel; the SSH server does not terminate or
inspect TLS. `sourceHost` and `sourcePort` set the originator metadata in the forwarding request and
default to `127.0.0.1` and zero. Per-request `localAddress` and `localPort` override that metadata;
they do not bind a local interface on the HTTP caller. Call `agent.destroy()` to close pooled HTTP
channels and every SSH connection owned by the agent. Apply the same host-key verification and
destination allowlisting requirements as any other direct-forwarding client. The agent snapshots
its SSH configuration during construction, including nested algorithm and authentication lists, so
later caller mutations cannot change credentials or negotiation for a new request. Encoded private
keys and certificates are parsed once into the configured signing agent; their source containers
and passphrase are not retained. Do not supply `sock`: one already-connected transport cannot
safely back the agent's independent per-socket SSH connections and is rejected during construction.

## Accepting direct connections

Direct forwarding is denied by the server's default channel-open policy. Inspect both the source
and destination fields before allowing it. Destination allowlisting is strongly recommended to
avoid turning an SSH service into an unrestricted network proxy.

```ts
import net from "node:net"
import { DirectTCPIPChannel } from "@bunkerch/modernssh"

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen =
        channel instanceof DirectTCPIPChannel &&
        channel.details.destinationHost === "database.internal" &&
        channel.details.destinationPort === 5432
})

server.on("connection", (connection) => {
    connection.on("channel", (channel) => {
        if (!(channel instanceof DirectTCPIPChannel)) return

        const destination = net.connect({
            host: channel.details.destinationHost,
            port: channel.details.destinationPort,
        })
        channel.stream.pipe(destination).pipe(channel.stream)
    })
})
```

The server-side `DirectTCPIPChannel.stream` uses the same bounded window, packet splitting,
backpressure, EOF, and CLOSE implementation as other server channels. A server-initiated
`direct-tcpip` open is rejected by clients as recommended by RFC 4254.

## Remote forwarding

`forwardIn()` asks the SSH server to listen on an address and port. Every matching incoming channel
passes through the awaited `tcpConnection` Hooker policy and is denied by default. The hook receives
the proposed `ClientForwardedTCPIPChannel`; its immutable `details` contain the destination and
source endpoints. Set `allowOpen` only after asynchronous authorization and local setup succeed.
After confirmation, the client emits the passive `tcp connection` event with the details and
already-open channel. A rejected Hooker handler discards an earlier approval.

```ts
import net from "node:net"
import { ChannelOpenError, ChannelOpenFailureReasonCodes } from "@bunkerch/modernssh"

client.hooker.hook("tcpConnection", async (_hook, channel, decision) => {
    if (!(await authorizeForwardedSource(channel.details.sourceHost))) {
        decision.rejection = new ChannelOpenError(
            ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
            "forwarded source denied by policy",
            "en-US",
        )
        return
    }

    const localService = net.connect({ host: "127.0.0.1", port: 8080 })
    localService.pipe(channel).pipe(localService)
    decision.allowOpen = true
})

const allocatedPort = await client.forwardIn("127.0.0.1", 0)
// Later, cancel the exact address and allocated port.
await client.unforwardIn("127.0.0.1", allocatedPort)
```

A port of zero requests dynamic allocation; `forwardIn()` resolves to the allocated port reported
by the server. An active or still-pending fixed address/port request is rejected locally before a
duplicate global request reaches the peer. Bind addresses have server-specific exposure rules. In
particular, wildcard binds can expose a listener beyond loopback when the SSH server permits gateway
ports, so validate both the requested bind and every connection's source metadata. Policy can set `decision.rejection` to
a validated `ChannelOpenError` when the server should receive a specific uint32 reason, UTF-8
description, and RFC 3066 language tag. A policy decision that completes after transport teardown
is discarded and its proposed channel is destroyed. Destroying the proposed channel during policy
denies the open even if a later handler sets `allowOpen`.

### Allowing remote forwarding on a server

Server-side remote forwarding is denied by default. The `tcpipForward` policy hook receives the
requested bind before any TCP listener is created. Restrict both address and port; allowing a
wildcard address grants the authenticated client network exposure through the SSH server.
When several policy handlers run, the listener is created only if every handler completes without
rejection and the final decision allows it; a contained later failure discards an earlier allow.

```ts
server.hooker.hook("tcpipForward", (_hook, context, decision, connection) => {
    decision.allow =
        connection.username === "deploy" &&
        context.bindAddress === "127.0.0.1" &&
        (context.bindPort === 0 || context.bindPort >= 40_000)
})
```

After approval, `modernssh` owns the TCP listener and opens a `ForwardedTCPIPChannel` back to the
requesting client for each connection. Requests for port zero receive the allocated port. A matching
`cancel-tcpip-forward` request stops accepting new connections immediately; disconnecting the SSH
connection also closes all of its listeners. Existing tunnel channels retain the normal independent
EOF and CLOSE lifecycle.

An application may also represent an incoming connection explicitly after the client has requested
and the server has accepted the exact bind. `ServerClient.forwardOut()` checks that authorization,
opens the RFC 4254 `forwarded-tcpip` channel, and returns its flow-controlled channel:

```ts
async function forwardIncomingConnection(socket, acceptedBind, connection) {
    const channel = await connection.forwardOut(
        acceptedBind.address,
        acceptedBind.port,
        socket.remoteAddress ?? "",
        socket.remotePort ?? 0,
    )
    socket.pipe(channel.stream).pipe(socket)
}

server.on("connection", (connection) => {
    incomingConnections.on("connection", (socket, acceptedBind) => {
        void forwardIncomingConnection(socket, acceptedBind, connection).catch((error) => {
            socket.destroy(error)
        })
    })
})
```

The bound address and port must identify a currently active forwarding request. This prevents an
application bug from opening an unsolicited server-initiated channel. Channel-open rejection is
reported through the returned Promise. Destroying the returned server-side stream sends channel
CLOSE to its peer; peer CLOSE and transport teardown destroy the stream without trying to close the
channel a second time. The SSH connection remains available for unrelated channels.

## OpenSSH UNIX-domain socket forwarding

[OpenSSH's `streamlocal` extension](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
applies the same direct and remote forwarding model to UNIX-domain sockets. It is not part of RFC
4254, so these APIs use an `openssh_` prefix and require a peer that implements the
OpenSSH extension.

`Client` defaults `strictVendor` to `true`, so these methods reject before sending a request unless
the peer advertises a compatible OpenSSH identification. Explicitly set `strictVendor: false` for a
trusted alternative implementation of the same extension.

`openssh_forwardOutStreamLocal()` opens a `direct-streamlocal@openssh.com` channel to a socket on
the SSH server:

```ts
const socket = await client.openssh_forwardOutStreamLocal("/run/app/control.sock")
localSocket.pipe(socket).pipe(localSocket)
```

For remote UNIX-socket forwarding, every incoming channel is denied unless its path exactly
matches a successful request and the awaited `streamLocalConnection` Hooker policy approves it.
The hook receives the proposed channel, so policy can authorize the immutable socket-path details
and finish asynchronous local setup before setting `allowOpen`. The passive `unix connection`
event runs only after confirmation and receives the already-open channel.

```ts
client.hooker.hook("streamLocalConnection", async (_hook, channel, decision) => {
    if (!(await authorizeSocketPath(channel.details.socketPath))) {
        return
    }

    const localSocket = net.connect("/run/app/control.sock")
    localSocket.pipe(channel).pipe(localSocket)
    decision.allowOpen = true
})

await client.openssh_forwardInStreamLocal("/run/user/1000/modernssh.sock")
await client.openssh_unforwardInStreamLocal("/run/user/1000/modernssh.sock")
```

Socket paths must be non-empty and cannot contain NUL. An active or pending request for the same
path rejects locally before sending a duplicate global request. Filesystem ownership, permissions,
stale socket replacement, and path visibility are controlled by the SSH server and its operating system.
Policy can provide a `ChannelOpenError` in `decision.rejection` for a specific failure reason,
description, and language tag. Decisions completed after transport teardown are discarded and the
proposed channel is destroyed. A channel destroyed during policy cannot be confirmed by a later
approval.

### Allowing UNIX-socket forwarding on a server

Server-side stream-local forwarding is denied by default. Allow only paths owned by the
authenticated principal; broad writable directories can let a client replace or impersonate local
services.

```ts
server.hooker.hook("streamLocalForward", (_hook, context, decision, connection) => {
    decision.allow =
        connection.username === "deploy" && context.socketPath.startsWith("/run/modernssh/deploy/")
})
```

After approval, `modernssh` owns the UNIX listener and opens a `ForwardedStreamLocalChannel` back
to the requesting client for each connection. A matching cancellation stops accepting new
connections, and disconnecting SSH closes every listener owned by that connection. Existing paths
are never unlinked to make room for a listener: a stale or occupied path makes the request fail.
The policy chain must complete without a rejected handler before the listener is created, so an
earlier allow cannot survive a contained backend failure.

For an explicitly represented incoming UNIX connection, call
`connection.openssh_forwardOutStreamLocal(socketPath)`. The path must exactly match a currently
accepted stream-local forwarding request and contain no NUL. It resolves to a
`ForwardedStreamLocalChannel`; pipe the local socket through `channel.stream` as with TCP.

Incoming `direct-streamlocal@openssh.com` channels use the normal `channelOpenRequest` policy and
are also denied by default. Inspect the exact destination before connecting it to a local socket:

```ts
import net from "node:net"
import { DirectStreamLocalChannel } from "@bunkerch/modernssh"

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen =
        channel instanceof DirectStreamLocalChannel &&
        channel.details.socketPath === "/run/app/control.sock"
})

server.on("connection", (connection) => {
    connection.on("channel", (channel) => {
        if (!(channel instanceof DirectStreamLocalChannel)) return
        const destination = net.connect(channel.details.socketPath)
        channel.stream.pipe(destination).pipe(channel.stream)
    })
})
```
