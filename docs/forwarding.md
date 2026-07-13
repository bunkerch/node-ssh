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
