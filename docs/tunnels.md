# Packet tunnels

`modernssh` supports the `tun@openssh.com` channel for carrying complete IP datagrams or Ethernet
frames. This is a packet transport API: it does not create or configure a host TUN/TAP interface,
routes, addresses, or privileges. Applications remain responsible for those operating-system
operations and for deciding which authenticated peers may open a tunnel.

## Client

Open a point-to-point (layer-3) channel and request automatic interface-unit selection:

```ts
import { Client, TunnelMode } from "@bunkerch/modernssh"

const tunnel = await client.openTunnel(TunnelMode.PointToPoint)

tunnel.events.on("packet", ({ family, data }) => {
    // `data` is one complete IPv4 or IPv6 datagram.
})

await tunnel.sendIPv4(ipv4Datagram)
await tunnel.sendIPv6(ipv6Datagram)
```

Pass a non-negative unit number as the second argument to request a particular unit. For a layer-2
channel, use `TunnelMode.Ethernet`, listen for `frame`, and call `sendFrame(frame)`.

`openTunnel()` is vendor-gated when strict vendor checking is enabled, consistently with other
vendor extensions. It returns a Promise. The older `openssh_openTunnel()` spelling remains a thin
alias for existing applications.

## Server policy

Incoming tunnels use `TunnelChannel`. Authorize them with the server's awaited
`channelOpenRequest` hook; they are denied unless the hook explicitly allows them.

```ts
import { TunnelChannel, TunnelMode } from "@bunkerch/modernssh"

server.hooker.hook("channelOpenRequest", async (_hook, channel, controller) => {
    if (channel instanceof TunnelChannel && channel.mode === TunnelMode.PointToPoint) {
        await authorizeTunnel(channel.unit)
        controller.allowOpen = true
    }
})
```

After authorization, use the same `packet`/`frame` events and `sendIPv4`, `sendIPv6`, or
`sendFrame` methods on the server channel.

## Framing and limits

Each send is encoded into exactly one SSH channel-data message. If the peer's channel window is too
small, the returned promise remains pending until a window adjustment permits the entire packet;
the library never splits one datagram or frame across messages. A payload larger than the peer's
negotiated maximum packet size is rejected. Point-to-point payloads are checked for a matching IPv4
or IPv6 version and minimum header size before they are sent or emitted.

Prefer the typed packet methods above. The inherited `sendData()` method and client stream writes
accept only a complete, already encoded tunnel payload, including its packet-length and optional
address-family fields. They validate that framing and still send it atomically; unframed bytes,
truncated payloads, and mode-mismatched payloads reject through the returned Promise or stream write
callback. Validation failures from `sendIPv4()`, `sendIPv6()`, and `sendFrame()` also reject their
Promises rather than throwing synchronously.
