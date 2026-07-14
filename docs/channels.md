# Client session channels

After `connect()` authenticates, a client can start a command or an interactive shell. Both APIs
return a `ClientSessionChannel`, which is a Node.js `Duplex` stream. Its readable side is standard
output, its writable side is standard input, and `channel.stderr` is a separate readable stream.
At the packet boundary, opaque channel data and request-detail buffers are copied; callers may
safely reuse or clear input buffers after constructing a packet, and parsed details do not alias
the transport frame that carried them. Channel open results and scalar control packets likewise
snapshot their metadata before they can be queued or observed asynchronously.

```ts
import { once } from "node:events"

const channel = await client.exec("node --version")

channel.pipe(process.stdout)
channel.stderr.pipe(process.stderr)

await once(channel, "close")
console.log({ code: channel.exitCode, signal: channel.exitSignal })
```

`exitCode` and `exitSignal` retain the terminal result after close. The channel also emits an
observational `exit` event when that result arrives, but durable state is preferable when code
attaches after starting a short-lived command.

`client.shell()` opens the same kind of stream and requests an interactive shell. `openSession()`
opens a session without choosing a program, so callers can issue lower-level channel requests.

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
given environment before starting the subsystem.

For PTY, environment, resize, signal, or subsystem setup, open a session explicitly and make the
requests in protocol order:

```ts
import { TerminalMode } from "modernssh"

const channel = await client.openSession()
await channel.requestPty({
    term: "xterm-256color",
    columns: 120,
    rows: 40,
    modes: {
        [TerminalMode.VINTR]: 3,
        [TerminalMode.ECHO]: 1,
        [TerminalMode.TTY_OP_ISPEED]: 115_200,
        [TerminalMode.TTY_OP_OSPEED]: 115_200,
    },
})
await channel.setEnv("LANG", "en_US.UTF-8")
await channel.exec("top")

await channel.sendData("help\n")
await channel.setWindow({ columns: 160, rows: 50 })
await channel.sendBreak(750)
await channel.signal("SIGTERM")
```

`subsystem(name)` starts a named subsystem instead of `exec()` or `shell()`. Only one program-start
request can succeed on a session. `TerminalMode` contains every RFC 4254 mnemonic and
`TerminalModes` is an equivalent registry alias. PTY modes accept either an opcode-to-uint32 object
or a `ReadonlyMap`; numeric opcodes remain accepted for future assignments in the RFC's 1–159
range. The encoder validates every opcode and value and adds the required `TTY_OP_END` terminator.
The server exposes received values through `SessionPtyInfo.modes` without discarding modes it does
not recognize.

Client channels remain ordinary Node.js duplex streams for piping. Use `await channel.sendData()`
when subsequent protocol actions must follow fully flow-controlled stdin; concurrent calls are
queued in call order, split at the peer's packet limit, and own a copy of Buffer input.

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

Request hooks are awaited before their decisions change channel state or produce application
events. A peer CLOSE remains terminal and is acknowledged immediately even while a hook is pending;
any decision that finishes after the channel closes is discarded. Pending writes and outbound
request Promises reject on close instead of waiting for an application hook that may never settle.

`sendBreak(duration)` implements RFC 4335 and waits for the server to confirm that it performed a
terminal BREAK. The duration is an unsigned millisecond value; zero requests the device default.
`break(duration)` is an equivalent short form. Servers commonly clamp nonzero requests to 500
through 3,000 milliseconds as recommended by the RFC.

Calling `channel.end()` finishes standard input by sending channel EOF. Calling `channel.close()`
sends EOF followed by CLOSE. A peer CLOSE is always acknowledged before the stream is destroyed.

OpenSSH's `eow@openssh.com` request is a different half-close: it asks the peer to stop sending
channel data while leaving the reverse direction and the channel itself open. Call
`channel.sendEndOfWrite()` on a client session or `shell.sendEndOfWrite()` on a server session. The
method returns `false` when the peer is not identified as OpenSSH; pass `true` only when the
application has separately established support. Incoming requests are validated, deduplicated,
and exposed through the awaited `endOfWrite` hook before the writable half is stopped. Client
channels also emit `endOfWrite` as a passive notification.

## Disabling additional sessions

After opening every session it needs, a client can ask an OpenSSH-compatible server to reject any
later session channels:

```ts
const session = await client.exec("deploy")
await client.opensshNoMoreSessions()
```

`opensshNoMoreSessions()` and its compatibility alias `openssh_noMoreSessions()` both return a
Promise. The request is irreversible for the connection. Existing session
channels and non-session channel types are unaffected, while a `modernssh` server rejects later
session opens before invoking application channel policy. OpenSSH may enforce the request by
disconnecting a client that attempts another session, so pending channel operations are rejected
when that disconnect arrives.

OpenSSH-specific client APIs require a compatible OpenSSH server identification by default. Set
`strictVendor: false` on `Client` only when a non-OpenSSH peer is known to implement these vendor
requests correctly. The same gate applies to the explicit compatibility form of agent forwarding
and to stream-local forwarding.

## Agent forwarding

Agent forwarding is disabled by default. Configure a forwardable `SSHAgent` or `OnePasswordAgent`.
For a single manually opened session, request forwarding before starting its program:

```ts
import { Client, SSHAgent } from "modernssh"

const client = new Client({ hostname, username, agent: new SSHAgent() })
await client.connect()

const channel = await client.openSession()
await channel.forwardAgent()
await channel.exec("ssh-add -L")
```

`forwardAgent()` uses RFC 9987's `agent-req` request and accepts `agent-connect` channels when the
server advertises exact version `0` of `agent-forward`. When the advertisement is absent, it safely
falls back to the pre-standardization names for identified OpenSSH servers. Use
`openssh_forwardAgent()` only when intentionally forcing that compatibility form; as with other
vendor requests, `strictVendor: false` is required to force it for an unidentified peer.

Set `agentForward: true` on the client to request forwarding automatically before every `exec()` or
`shell()` program request. A session may override the connection default in either direction.

```ts
const client = new Client({
    hostname,
    username,
    agent: process.env.SSH_AUTH_SOCK,
    agentForward: true,
})
await client.connect()

const forwarded = await client.exec("ssh-add -L")
const isolated = await client.exec("deploy", { agentForward: false })
```

After the server accepts the request, each `agent-connect` channel—or its compatibility form—is
connected directly to a fresh local agent socket. Incoming agent channels are rejected unless a
session request has succeeded, and agents without a stream capability such as `DiskAgent` cannot
be forwarded.

A server can inspect an authorized forwarded agent through the Promise-based protocol client. The
connection carries no request identifiers, so operations are serialized and each response has a
10-second deadline by default:

```ts
import { SSHAgentProtocolClient } from "modernssh"

const channel = await connection.forwardAgent()
const agent = new SSHAgentProtocolClient(channel.stream)
try {
    const identities = await agent.getPublicKeys()
    const [id, publicKey] = identities[0]
    const message = Buffer.from("application challenge")
    const signature = await agent.sign(id, message)
    if (!publicKey.verifySignature(message, signature))
        throw new Error("Agent returned a bad signature")
} finally {
    agent.destroy()
}
```

`SSHAgentProtocolServer` serves an already-connected `Duplex` with awaited, deny-by-default
identity, signing, management, lock, and extension hooks. It is useful for exposing a deliberately
restricted agent rather than forwarding an entire local socket:

```ts
import { SSHAgentProtocolServer } from "modernssh"

const agentServer = new SSHAgentProtocolServer()

agentServer.hooker.hook("identities", async (_hook, decision) => {
    decision.identities = await identitiesAllowedForThisConnection()
})

agentServer.hooker.hook("sign", async (_hook, request, decision) => {
    decision.signature = await signIfAuthorized(request.publicKey, request.data, request.algorithm)
})

await agentServer.serve(connectedAgentStream)
```

Both roles enforce the agent's 256 KiB message ceiling, strict framing, fatal UTF-8 comments, exact
RSA SHA-2 flags, response types, and signature algorithms. Server hooks are awaited in wire order;
missing, rejected, or invalid policy decisions return the protocol failure response. The server
also verifies a supplied signature against the requested key and message before releasing it.
The client exclusively owns reads from its stream and must not share it with another protocol
consumer. Destroy the client when finished; a request deadline also destroys the stream because an
untagged late response cannot safely be matched to a later request. Call `serve()` only once per
stream and await it through peer closure or failure.
Forwarding still gives the remote host an interface capable of requesting signatures as your local
identity, so expose only the identities and destinations that host is trusted to use.
See [SSH agent protocol](agent-protocol.md) for management methods, constraints, extension results,
lock semantics, and the complete server hook surface.

## Protocol behavior

The implementation follows RFC 4254 channel rules:

- Local and remote channel numbers are tracked independently. A peer identifier is reserved as soon
  as its open request arrives, including while asynchronous policy is pending, and remains reserved
  until both CLOSE messages have been exchanged. Reusing an active identifier is a protocol error;
  reuse after the channel is fully closed is valid.
- Outbound data is split to the peer's maximum packet size and paused when its window is empty.
- Inbound stdout and stderr share the advertised receive window. Window adjustments are sent as
  stream consumers make room. A zero adjustment is a valid no-op; an adjustment that would raise
  the current window above `2^32 - 1` causes an RFC protocol-error disconnect.
- Request success and failure replies are matched in request order.
- A peer CLOSE promptly tears down the channel and settles pending operations. Late results from
  request hooks cannot create session resources, emit request events, or send request replies.
- `exit-status` and `exit-signal` requests are exposed through the `exit` event and channel fields.
  Exit signals retain `exitSignal`, `exitCoreDumped`, `exitErrorMessage`, and `exitLanguageTag`.
  These one-way results are accepted only once on a session channel; signal names, UTF-8 messages,
  language tags, reply flags, and trailing data are validated before the event is emitted.
- Data after EOF, oversized data, window overruns, duplicate or contradictory open outcomes,
  duplicate peer identifiers, and packets for unknown channels are treated as protocol errors.
  Protocol-error disconnects are sent consistently whether the triggering packet arrived alone,
  fragmented, or in a coalesced read.

The interoperability suite exercises session opening, `exec`, stdin, stdout, stderr, exit status,
EOF, CLOSE, end-of-write, and OpenSSH's `no-more-sessions@openssh.com` extension against OpenSSH.
Fixed RFC and OpenSSH protocol byte vectors cover the exact request encodings.

## Serving exec and shell requests

The server denies channel opens by default. Allow session channels at the server policy layer, then
configure each accepted `SessionChannel`. Request hooks decide whether an individual operation is
accepted; channel events provide its duplex stream after the success reply is sent.

```ts
async function runStatusCommand(stream) {
    stream.stdin.pipe(process.stdout)
    await stream.writeStderr("diagnostics\n")
    await stream.writeStdout("ok\n")
    stream.exit(0)
    stream.stdout.end()
}

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
            void runStatusCommand(stream).catch((error) => {
                stream.destroy(error)
            })
        })
    })
})
```

The `Shell` passed to `exec` and `shell` events is a Node.js `Duplex`. It is also available through
the `stdin` and `stdout` aliases, and has a separate writable `stderr`. Await `writeStdout()` or
`writeStderr()` when later protocol messages must follow the output; ordinary stream writes remain
available for piping. Output writes obey the client's shared channel window and maximum packet size. `exit(number)` sends `exit-status`; passing
a signal name sends `exit-signal`. Its optional diagnostic message must be valid UTF-8 and is
validated before the one-way result is sent. Ending stdout flushes queued output, sends EOF and CLOSE, and a
remote EOF only ends stdin so the server can still finish its response.

Session hooks also cover `ptyRequest`, `envRequest`, and `subsystemRequest`. Accepted values are
available in `channel.pty` and `channel.env`; the corresponding `pty`, `env`, and `subsystem` events
are emitted after acceptance. Session command, terminal, and environment text must be valid UTF-8;
malformed values are rejected before any policy hook runs. Runtime `windowChange` and `signal`
notifications first run ordered, awaited hooks and are then exposed as observation events:

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

const agentChannel = await connection.forwardAgent()
agentProtocolStream.pipe(agentChannel.stream).pipe(agentProtocolStream)
```

The request creates a transitive trust relationship: the server can ask the user's agent to sign
arbitrary supported data for the rest of the SSH connection. Only enable it for fully trusted
servers and authenticated principals. A `modernssh` server advertises RFC 9987 version `0`, accepts
both request forms, and opens the channel form corresponding to the accepted request. The explicit
`connection.openssh_forwardAgent()` helper remains available when a server must force the
pre-standardization channel name for a known compatibility peer.

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
