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

For PTY, environment, resize, signal, or subsystem setup, open a session explicitly and make the
requests in protocol order:

```ts
const channel = await client.openSession()
await channel.requestPty({ term: "xterm-256color", columns: 120, rows: 40 })
await channel.setEnv("LANG", "en_US.UTF-8")
await channel.exec("top")

await channel.setWindow({ columns: 160, rows: 50 })
await channel.signal("SIGTERM")
```

`subsystem(name)` starts a named subsystem instead of `exec()` or `shell()`. Only one program-start
request can succeed on a session. PTY terminal modes can be supplied as numeric RFC 4254 opcode to
uint32-value mappings; the encoder adds the required `TTY_OP_END` terminator.

Calling `channel.end()` finishes standard input by sending channel EOF. Calling `channel.close()`
sends EOF followed by CLOSE. A peer CLOSE is always acknowledged before the stream is destroyed.

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
EOF, and CLOSE against OpenSSH. Fixed RFC byte vectors cover the exact channel request encodings.

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
are emitted after acceptance. Runtime `windowChange` and `signal` notifications are exposed as
events. PTY mode payloads are parsed and validated before a policy hook runs, and malformed setup
requests that ask for a reply receive channel failure.

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
