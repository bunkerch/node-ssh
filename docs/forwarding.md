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
stream. Ports are validated as unsigned 16-bit TCP port numbers before a packet is sent.

## Accepting direct connections

Direct forwarding is denied by the server's default channel-open policy. Inspect both the source
and destination fields before allowing it. Destination allowlisting is strongly recommended to
avoid turning an SSH service into an unrestricted network proxy.

```ts
import net from "node:net"
import { DirectTCPIPChannel } from "modernssh"

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

`forwardIn()` asks the SSH server to listen on an address and port. Each accepted connection emits
`tcp connection`; call `accept()` synchronously to obtain its flow-controlled
`ClientForwardedTCPIPChannel`, or call `reject()` to deny it. Incoming forwarding channels are
denied unless they match a successfully requested listener, and are also denied when no handler is
registered.

```ts
import net from "node:net"

client.on("tcp connection", (details, accept, reject) => {
    if (details.sourceHost !== "192.0.2.10") {
        reject()
        return
    }

    const tunnel = accept()
    if (tunnel) {
        const localService = net.connect({ host: "127.0.0.1", port: 8080 })
        localService.pipe(tunnel).pipe(localService)
    }
})

const allocatedPort = await client.forwardIn("127.0.0.1", 0)
// Later, cancel the exact address and allocated port.
await client.unforwardIn("127.0.0.1", allocatedPort)
```

A port of zero requests dynamic allocation; `forwardIn()` resolves to the allocated port reported
by the server. Bind addresses have server-specific exposure rules. In particular, wildcard binds
can expose a listener beyond loopback when the SSH server permits gateway ports, so validate both
the requested bind and every connection's source metadata.

### Allowing remote forwarding on a server

Server-side remote forwarding is denied by default. The `tcpipForward` policy hook receives the
requested bind before any TCP listener is created. Restrict both address and port; allowing a
wildcard address grants the authenticated client network exposure through the SSH server.

```ts
server.hooker.hook("tcpipForward", (_hook, context, decision, connection) => {
    decision.allow =
        connection.credentials?.data.username === "deploy" &&
        context.bindAddress === "127.0.0.1" &&
        (context.bindPort === 0 || context.bindPort >= 40_000)
})
```

After approval, `modernssh` owns the TCP listener and opens a `ForwardedTCPIPChannel` back to the
requesting client for each connection. Requests for port zero receive the allocated port. A matching
`cancel-tcpip-forward` request stops accepting new connections immediately; disconnecting the SSH
connection also closes all of its listeners. Existing tunnel channels retain the normal independent
EOF and CLOSE lifecycle.

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

For remote UNIX-socket forwarding, register a `unix connection` handler before requesting the
listener. As with TCP forwarding, every incoming channel is denied unless its path exactly matches
a successful request and the handler synchronously accepts it.

```ts
client.on("unix connection", (details, accept, reject) => {
    if (details.socketPath !== "/run/user/1000/modernssh.sock") {
        reject()
        return
    }

    const tunnel = accept()
    if (tunnel) {
        const localSocket = net.connect("/run/app/control.sock")
        localSocket.pipe(tunnel).pipe(localSocket)
    }
})

await client.openssh_forwardInStreamLocal("/run/user/1000/modernssh.sock")
await client.openssh_unforwardInStreamLocal("/run/user/1000/modernssh.sock")
```

Socket paths must be non-empty and cannot contain NUL. Filesystem ownership, permissions, stale
socket replacement, and path visibility are controlled by the SSH server and its operating system.

### Allowing UNIX-socket forwarding on a server

Server-side stream-local forwarding is denied by default. Allow only paths owned by the
authenticated principal; broad writable directories can let a client replace or impersonate local
services.

```ts
server.hooker.hook("streamLocalForward", (_hook, context, decision, connection) => {
    decision.allow =
        connection.credentials?.data.username === "deploy" &&
        context.socketPath.startsWith("/run/modernssh/deploy/")
})
```

After approval, `modernssh` owns the UNIX listener and opens a `ForwardedStreamLocalChannel` back
to the requesting client for each connection. A matching cancellation stops accepting new
connections, and disconnecting SSH closes every listener owned by that connection. Existing paths
are never unlinked to make room for a listener: a stale or occupied path makes the request fail.

Incoming `direct-streamlocal@openssh.com` channels use the normal `channelOpenRequest` policy and
are also denied by default. Inspect the exact destination before connecting it to a local socket:

```ts
import net from "node:net"
import { DirectStreamLocalChannel } from "modernssh"

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
