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

`exec()` accepts typed session setup options and applies them before the program request, in SSH
protocol order:

```ts
const channel = await client.exec("stty size; printf '%s' \"$LANG\"", {
    allowHalfOpen: false,
    agentForward: true,
    env: { LANG: "C.UTF-8" },
    pty: { term: "xterm-256color", cols: 120, rows: 40 },
    x11: { single: true, screen: 0 },
})
```

Environment requests from this convenience API do not ask for replies, matching common
OpenSSH behavior; servers may silently ignore variables outside their `AcceptEnv` policy. PTY, X11,
and agent-forwarding requests require success before `exec` starts. `shell()` accepts the same
options and requests a default PTY unless `pty: false` is supplied. `sftp(environment)` sends the
given environment before starting the subsystem. The callback overloads accept these option
objects as the argument before the callback.

For PTY, environment, resize, signal, or subsystem setup, open a session explicitly and make the
requests in protocol order:

```ts
const channel = await client.openSession()
await channel.requestPty({ term: "xterm-256color", columns: 120, rows: 40 })
await channel.setEnv("LANG", "en_US.UTF-8")
await channel.exec("top")

await channel.setWindow({ columns: 160, rows: 50 })
await channel.sendBreak(750)
await channel.signal("SIGTERM")
```

`subsystem(name)` starts a named subsystem instead of `exec()` or `shell()`. Only one program-start
request can succeed on a session. PTY terminal modes can be supplied as numeric RFC 4254 opcode to
uint32-value mappings; the encoder adds the required `TTY_OP_END` terminator.

Applications can also exchange private channel requests without bypassing channel state. Outbound
requests are matched to success or failure replies in wire order; pass `false` as the third argument
for a one-way notification:

```ts
await channel.request("refresh@example.com", Buffer.from("full"))
await channel.request("changed@example.com", Buffer.from("users"), false)

channel.hooker.hook("request", async (_hook, context, decision) => {
    if (context.type !== "refresh@example.com") return
    await refresh(context.args)
    decision.success = true
})
```

Server channels provide the same `request(type, args, wantReply)` operation. Incoming requests
that do not have a channel-specific built-in handler reach the server's awaited `channelRequest`
hook. Its request packet is the fifth argument; set `handled = true` and set `success` only after the
application work has completed. Unknown requests fail by default. One-way requests still invoke the
hook but never receive a protocol reply.

`sendBreak(duration)` implements RFC 4335 and waits for the server to confirm that it performed a
terminal BREAK. The duration is an unsigned millisecond value; zero requests the device default.
`break(duration)` is an equivalent short form. Servers commonly clamp nonzero requests to 500
through 3,000 milliseconds as recommended by the RFC.

Calling `channel.end()` finishes standard input by sending channel EOF. Calling `channel.close()`
sends EOF followed by CLOSE. A peer CLOSE is always acknowledged before the stream is destroyed.

## Disabling additional sessions

After opening every session it needs, a client can ask an OpenSSH-compatible server to reject any
later session channels:

```ts
const session = await client.exec("deploy")
await client.opensshNoMoreSessions()
```

`opensshNoMoreSessions()` is the promise API; `openssh_noMoreSessions()` additionally provides the
callback form. The request is irreversible for the connection. Existing session
channels and non-session channel types are unaffected, while a `modernssh` server rejects later
session opens before invoking application channel policy. OpenSSH may enforce the request by
disconnecting a client that attempts another session, so pending channel operations are rejected
when that disconnect arrives.

OpenSSH-specific client APIs require a compatible OpenSSH server identification by default. Set
`strictVendor: false` on `Client` only when a non-OpenSSH peer is known to implement these vendor
requests correctly. The same gate applies to agent forwarding and stream-local forwarding.

## Agent forwarding

Agent forwarding is disabled by default. Configure a forwardable `SSHAgent` or `OnePasswordAgent`,
open a session, request the OpenSSH-compatible forwarding extension before starting its program,
and then start the command:

```ts
import { Client, SSHAgent } from "modernssh"

const client = new Client({ hostname, username, agent: new SSHAgent() })
await client.connect()

const channel = await client.openSession()
await channel.openssh_forwardAgent()
await channel.exec("ssh-add -L")
```

After the server accepts the request, each `auth-agent@openssh.com` channel is connected directly
to a fresh local agent socket. Incoming agent channels are rejected unless a session request has
succeeded, and agents without a stream capability such as `DiskAgent` cannot be forwarded.

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

The interoperability suite exercises session opening, `exec`, stdin, stdout, stderr, exit status,
EOF, CLOSE, and OpenSSH's `no-more-sessions@openssh.com` extension against OpenSSH. Fixed RFC and
OpenSSH protocol byte vectors cover the exact request encodings.

## Serving exec and shell requests

The server denies channel opens by default. Allow session channels at the server policy layer, then
configure each accepted `SessionChannel`. Request hooks decide whether an individual operation is
accepted; channel events provide its duplex stream after the success reply is sent.

```ts
server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen = channel instanceof SessionChannel
})

server.on("connection", (connection) => {
    connection.on("channel", (channel) => {
        if (!(channel instanceof SessionChannel)) return

        channel.hooker.hook("execRequest", (_hook, context, decision) => {
            decision.success = context.command === "status"
        })

        channel.events.on("exec", (_command, stream) => {
            stream.stdin.pipe(process.stdout)
            stream.stderr.write("diagnostics\n")
            stream.stdout.write("ok\n", () => {
                stream.exit(0)
                stream.stdout.end()
            })
        })
    })
})
```

The `Shell` passed to `exec` and `shell` events is a Node.js `Duplex`. It is also available through
the `stdin` and `stdout` aliases, and has a separate writable `stderr`. Output writes obey the
client's shared channel window and maximum packet size. `exit(number)` sends `exit-status`; passing
a signal name sends `exit-signal`. Ending stdout flushes queued output, sends EOF and CLOSE, and a
remote EOF only ends stdin so the server can still finish its response.

Session hooks also cover `ptyRequest`, `envRequest`, and `subsystemRequest`. Accepted values are
available in `channel.pty` and `channel.env`; the corresponding `pty`, `env`, and `subsystem` events
are emitted after acceptance. Runtime `windowChange` and `signal` notifications first run ordered,
awaited hooks and are then exposed as observation events:

```ts
channel.hooker.hook("windowChange", async (_hook, dimensions) => {
    await pty.resize(dimensions.columns, dimensions.rows)
})

channel.hooker.hook("signal", async (_hook, { signal }) => {
    await processController.signal(signal)
})
```

These runtime controls are one-way notifications: conforming senders never request a reply. PTY
mode payloads are parsed and validated before a policy hook runs, and malformed setup requests that
ask for a reply receive channel failure.

RFC 4335 BREAK is denied unless the session has started a program and an awaited `breakRequest`
policy hook confirms that the operation was performed. The hook receives the requested duration
unchanged so device-specific code can apply its own default and safe limits:

```ts
channel.hooker.hook("breakRequest", async (_hook, context, decision) => {
    const duration = context.duration === 0 ? 500 : Math.min(3_000, Math.max(500, context.duration))
    decision.success = await serialConsole.sendBreak(duration)
})
```

Treat BREAK authorization as security-sensitive: consoles may interpret it as a request to halt a
system or enter privileged configuration. After accepting a PTY, the server may also call
`stream.setXonXoff(clientCanDo)` to send RFC 4254's one-way local-flow-control notification. Clients
emit `xonXoff` with the boolean value and never reply to this notification.

Agent forwarding is separately denied by default even for an allowed session. The server must
approve `agentForwardRequest`; after approval it may open one or more bounded agent channels:

```ts
channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
    decision.success = connection.credentials?.data.username === "deploy"
})

const agentChannel = await connection.openssh_forwardAgent()
agentProtocolStream.pipe(agentChannel.stream).pipe(agentProtocolStream)
```

The request creates a transitive trust relationship: the server can ask the user's agent to sign
arbitrary supported data for the rest of the SSH connection. Only enable it for fully trusted
servers and authenticated principals. The implementation uses RFC 9987's deployed OpenSSH request
and channel names because peers generally do not yet advertise the standardized names via RFC 8308.

## X11 forwarding

RFC 4254 X11 forwarding is also disabled by default. A client requests it on a session before
starting a program and handles each independent connection synchronously:

```ts
client.on("x11", (details, accept, reject) => {
    if (details.originatorAddress !== "127.0.0.1") {
        reject()
        return
    }
    const channel = accept()
    if (!channel) return
    const display = net.connect({ host: "127.0.0.1", port: 6000 })
    channel.pipe(display).pipe(channel)
})

const session = await client.openSession()
const request = await session.requestX11({
    single: false,
    screen: 0,
    protocol: "MIT-MAGIC-COOKIE-1",
    cookie: process.env.X11_COOKIE,
})
await session.exec("xeyes")
```

If no cookie is supplied, the client generates a random 128-bit fake cookie as recommended by RFC 4254. Applications that pipe to a real X server must replace that fake cookie in the initial X11
setup packet with the real cookie; the normalized request returned by `requestX11()` exposes the
generated value for this purpose. Alternatively, explicitly supply the real cookie and accept the
greater exposure. Cookies are validated as non-empty hexadecimal data. `single: true` authorizes
exactly one incoming channel, and all unused authorization is removed when its session closes.

On a server, `x11Request` receives the requested single-connection flag, authentication protocol,
hex cookie, and screen. After explicit approval, `connection.x11()` opens a bounded channel back to
the client:

```ts
channel.hooker.hook("x11Request", (_hook, request, decision) => {
    decision.success =
        request.protocol === "MIT-MAGIC-COOKIE-1" &&
        connection.credentials?.data.username === "deploy"
})

const x11 = await connection.x11("127.0.0.1", 60_000)
xApplicationSocket.pipe(x11.stream).pipe(xApplicationSocket)
```

The server refuses `x11()` unless an active session approved forwarding. Single-connection requests
are consumed by the first open, while already-open X11 channels remain independent when the session
closes, as required by RFC 4254.
