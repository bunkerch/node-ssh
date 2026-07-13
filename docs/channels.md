# Client session channels

After `connect()` authenticates, a client can start a command or an interactive shell. Both APIs
return a `ClientSessionChannel`, which is a Node.js `Duplex` stream. Its readable side is standard
output, its writable side is standard input, and `channel.stderr` is a separate readable stream.

```ts
const channel = await client.exec("node --version")

channel.pipe(process.stdout)
channel.stderr.pipe(process.stderr)

channel.on("exit", (code, signal) => {
    console.log({ code, signal })
})
```

`client.shell()` opens the same kind of stream and requests an interactive shell. `openSession()`
opens a session without choosing a program, so callers can issue lower-level channel requests.
Callback forms are also available:

```ts
client.exec("node --version", (error, channel) => {
    if (error) throw error
    channel!.pipe(process.stdout)
})
```

Calling `channel.end()` finishes standard input by sending channel EOF. Calling `channel.close()`
sends EOF followed by CLOSE. A peer CLOSE is always acknowledged before the stream is destroyed.

## Protocol behavior

The implementation follows RFC 4254 channel rules:

- Local and remote channel numbers are tracked independently.
- Outbound data is split to the peer's maximum packet size and paused when its window is empty.
- Inbound stdout and stderr share the advertised receive window. Window adjustments are sent as
  stream consumers make room.
- Request success and failure replies are matched in request order.
- `exit-status` and `exit-signal` requests are exposed through the `exit` event and channel fields.
- Data after EOF, oversized data, window overruns, duplicate confirmations, and packets for unknown
  channels are treated as protocol errors.

The interoperability suite exercises session opening, `exec`, stdout larger than the initial
window, stderr, exit status, EOF, and CLOSE against the pinned `ssh2` implementation.
