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
options and requests a default PTY unless `pty: false` is supplied.
`sftp(environment, { requestTimeout })` sends the given environment before starting the subsystem
and can override the connection reply deadline for SFTP initialization and tagged replies.

`exec()` and `shell()` snapshot their session options when the operation starts, including the
environment, PTY terminal modes, and X11 cookie bytes. Later changes to caller-owned configuration
do not affect requests waiting for the session channel to open. `sftp()` likewise copies its
environment and timeout options at invocation.

Both session helpers validate the options object before allocating a channel. `agentForward` and
`allowHalfOpen` require actual booleans, environment values require strings, and PTY and X11
configuration must use their documented scalar or object shapes. Invalid input rejects the
returned Promise; it never throws synchronously or turns a truthy value such as the string
`"false"` into an enabled forwarding request.

The command text passed to `exec()` must be valid UTF-8, and `subsystem()` requires an RFC 4250 SSH
name. These values are validated before allocating a channel identifier. Invalid values reject the
operation without opening a disposable session first.

For PTY, environment, resize, signal, or subsystem setup, open a session explicitly and make the
requests in protocol order:

```ts
import { TerminalMode } from "@bunkerch/modernssh"

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

Generic request policy fails closed in both directions: every registered handler must complete
without rejection before `success` or the server's `handled` override is honored. A contained later
failure discards decisions made by earlier handlers.

Request hooks are awaited before their decisions change channel state or produce application
events. A peer CLOSE remains terminal and is acknowledged immediately even while a hook is pending;
any decision that finishes after the channel closes is discarded. Pending writes and outbound
request Promises reject on close instead of waiting for an application hook that may never settle.
Channel traffic received before the corresponding open confirmation is a connection-level protocol
error; an unconfirmed channel cannot be used as an early data, request, EOF, or CLOSE path.

`sendBreak(duration)` implements RFC 4335 and waits for the server to confirm that it performed a
terminal BREAK. The duration is an unsigned millisecond value; zero requests the device default.
`break(duration)` is an equivalent short form. Servers commonly clamp nonzero requests to 500
through 3,000 milliseconds as recommended by the RFC.

Calling `channel.end()` finishes standard input by sending channel EOF. Calling `channel.close()`
sends EOF followed by CLOSE. A peer CLOSE is always acknowledged before the stream is destroyed.
EOF waits behind data already accepted by `sendData()` and prevents every later write, so channel
data cannot overtake the RFC 4254 half-close even when the peer's receive window is exhausted.

The server-side `Shell` follows the same directional lifecycle. `shell.end()` finishes stdout by
sending EOF but keeps stdin readable; the client may continue sending data because RFC 4254 leaves
the channel open in the opposite direction. Use `shell.close()` to send EOF followed by CLOSE when
the program and its input are both finished. A typical terminal path is
`shell.exit(0).close()` after the final stdout write completes.

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
when that disconnect arrives. A successful reply has no response data; unexpected data is a
protocol error and closes the connection because the peer has already applied irreversible state.

OpenSSH-specific client APIs require a compatible OpenSSH server identification by default. Set
`strictVendor: false` on `Client` only when a non-OpenSSH peer is known to implement these vendor
requests correctly. The same gate applies to the explicit compatibility form of agent forwarding
and to stream-local forwarding.

## Agent forwarding

Agent forwarding is disabled by default. Configure a forwardable `SSHAgent` or `OnePasswordAgent`.
For a single manually opened session, request forwarding before starting its program:

```ts
import { Client, SSHAgent } from "@bunkerch/modernssh"

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
be forwarded. Establishing that local socket may be asynchronous. If the SSH transport closes
first, a socket that resolves later is destroyed without creating a channel or attempting a reply
on the closed transport. This remains true when the same `Client` reconnects: an agent lookup is
bound to the transport that requested it and cannot attach to a channel identifier reused by the
new connection.

A server can inspect an authorized forwarded agent through the Promise-based protocol client. The
connection carries no request identifiers, so operations are serialized and each response has a
10-second deadline by default:

```ts
import { SSHAgentProtocolClient } from "@bunkerch/modernssh"

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
import { SSHAgentProtocolServer } from "@bunkerch/modernssh"

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
  reuse after the channel is fully closed is valid. If the connection closes while channel-open
  policy is pending, a late approval is discarded without creating or publishing a channel.
- `maxPendingChannelOpens` bounds peer opens whose application decision is still pending and
  defaults to 64 in both roles. Reaching the limit rejects additional opens with RFC 4254 resource
  shortage without closing the connection or invoking their policy/provider. Zero rejects every
  peer-initiated open. Established channels do not consume this pending-decision allowance.
- Independent peer opens run their awaited admission policies concurrently and may be answered out
  of arrival order because every RFC 4254 result identifies its channel. Applications that mutate
  shared authorization state must provide their own synchronization inside the Hooker handler.
- `maxChannels` bounds all active channels and pending peer opens on a connection and defaults to
  1024 in both roles. It applies equally to local opens and peer opens. Reaching the limit reports
  RFC 4254 resource shortage without closing the connection or invoking policy for a rejected peer
  open. Capacity is recovered after both CLOSE messages are exchanged; zero disables all channels.
- Outbound data is split to the peer's maximum packet size and paused when its window is empty.
- Inbound stdout and stderr share the advertised receive window. Window adjustments are sent as
  stream consumers make room. A zero adjustment is a valid no-op; an adjustment that would raise
  the current window above `2^32 - 1` causes an RFC protocol-error disconnect.
- Request success and failure replies are matched in request order.
- Outbound channel opens and reply-requesting channel requests use the connection's `replyTimeout`.
  Expiry rejects the operation and closes the connection so a late ordered reply cannot be
  misattributed.
- Local channel numbers span the complete RFC 4254 `uint32` range, wrap after `0xffffffff`, and
  skip identifiers that are still active. An identifier becomes reusable only after its channel
  has closed.
- Local or peer CLOSE promptly settles pending writes and outbound requests; settlement never waits
  for the peer's CLOSE acknowledgement. Late results from request hooks cannot create session
  resources, emit request events, or send request replies.
- At most 1024 packet operations may wait behind active global or per-channel async work on one
  connection. Overflow closes the connection because one-way channel requests cannot be rejected
  individually. Transport teardown rejects and removes queued operations instead of abandoning
  their Promises.
- Transport termination immediately makes every owned channel report `isOpen === false`, even when
  the connection ended before the channel-level CLOSE exchange completed.
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
Channel admission also requires every registered `channelOpenRequest` handler to complete without
rejection; a contained failure discards an allow decision made by an earlier handler.
Aborting or closing the proposed channel during policy denies it even if a later handler sets
`allowOpen`; the server never confirms or publishes a proposal that is no longer open.
When policy intentionally denies an open, it may assign a validated `ChannelOpenError` to
`decision.rejection`. The peer then receives its exact uint32 reason, UTF-8 description, and RFC
3066 language tag. Named standard reasons are available through `ChannelOpenFailureReasonCodes`;
future assignments and RFC 4254 private-use values remain usable as numbers. If opening is denied,
`openSession()`, `forwardOut()`, and the other channel-opening Promise APIs reject with the same
typed error and expose `reasonCode`, `message`, and `languageTag`.

```ts
import {
    ChannelOpenError,
    ChannelOpenFailureReasonCodes,
    SessionChannel,
} from "@bunkerch/modernssh"

async function runStatusCommand(stream) {
    stream.stdin.pipe(process.stdout)
    await stream.writeStderr("diagnostics\n")
    await stream.writeStdout("ok\n")
    stream.exit(0)
    stream.stdout.end()
}

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    if (channel instanceof SessionChannel) {
        decision.allowOpen = true
        return
    }
    decision.rejection = new ChannelOpenError(
        ChannelOpenFailureReasonCodes.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
        "channel type disabled by policy",
        "en-US",
    )
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

Program requests consume a session only after their policy succeeds. Every `shellRequest`,
`execRequest`, and `subsystemRequest` handler must complete without rejection; a contained later
failure discards an earlier success and does not activate or publish a shell or subsystem stream.

The `Shell` passed to `exec` and `shell` events is a Node.js `Duplex`. It is also available through
the `stdin` and `stdout` aliases, and has a separate writable `stderr`. Await `writeStdout()` or
`writeStderr()` when later protocol messages must follow the output; ordinary stream writes remain
available for piping. Output writes obey the client's shared channel window and maximum packet size. `exit(number)` sends `exit-status`; passing
a signal name sends `exit-signal`. Its optional diagnostic message must be valid UTF-8 and is
validated before the one-way result is sent. Ending stdout flushes queued output, sends EOF and CLOSE, and a
remote EOF only ends stdin so the server can still finish its response.
Destroying the `Shell`, including `destroy(error)` from an application failure, sends channel CLOSE
when the SSH connection is still available. It never leaves a server-owned session channel open,
and teardown caused by an existing peer CLOSE or transport failure remains idempotent.

Session hooks also cover `ptyRequest`, `envRequest`, and `subsystemRequest`. Accepted values are
available in `channel.pty` and `channel.env`; the corresponding `pty`, `env`, and `subsystem` events
are emitted after acceptance. Every decision-bearing handler must complete without rejection before
its success is retained or any accepted state or event is published. Session command, terminal, and
environment text must be valid UTF-8; malformed values are rejected before any policy hook runs.
Runtime `windowChange` and `signal` notifications first run ordered, awaited hooks and are then
exposed as observation events:

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
system or enter privileged configuration. Every `breakRequest` handler must complete successfully;
a later contained failure discards an earlier approval and suppresses the `break` event. After
accepting a PTY, the server may also call
`stream.setXonXoff(clientCanDo)` to send RFC 4254's one-way local-flow-control notification. Clients
emit `xonXoff` with the boolean value and never reply to this notification.

Agent forwarding is separately denied by default even for an allowed session. The server must
approve `agentForwardRequest`; every handler must complete successfully before the authorization is
registered. After approval it may open one or more bounded agent channels:

```ts
channel.hooker.hook("agentForwardRequest", (_hook, decision) => {
    decision.success = connection.username === "deploy"
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
starting a program. Each incoming connection then passes through the awaited `x11Connection`
Hooker policy and is denied by default. The hook receives the proposed channel, whose immutable
details identify the originator. Set `allowOpen` only after authorization and local display setup
complete; the passive `x11` event runs after channel confirmation.

```ts
client.hooker.hook("x11Connection", async (_hook, channel, decision) => {
    if (!(await authorizeX11Origin(channel.details.originatorAddress))) {
        return
    }

    const display = net.connect({ host: "127.0.0.1", port: 6000 })
    channel.pipe(display).pipe(channel)
    decision.allowOpen = true
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
Local argument-validation and channel-capacity failures occur before an outgoing X11 open and do
not consume that single authorization.
Policy may set `decision.rejection` to a `ChannelOpenError` with a specific failure reason,
description, and language tag. A decision completed after transport teardown is discarded and its
proposed channel is destroyed. Destroying a proposal during policy denies it even if a later hook
sets `allowOpen`.

On a server, `x11Request` receives the requested single-connection flag, authentication protocol,
hex cookie, and screen. Every handler must complete successfully before the authorization is
registered. After explicit approval, `connection.x11()` opens a bounded channel back to the client:

```ts
channel.hooker.hook("x11Request", (_hook, request, decision) => {
    decision.success = request.protocol === "MIT-MAGIC-COOKIE-1" && connection.username === "deploy"
})

const x11 = await connection.x11("127.0.0.1", 60_000)
xApplicationSocket.pipe(x11.stream).pipe(xApplicationSocket)
```

The server refuses `x11()` unless an active session approved forwarding. Single-connection requests
are consumed by the first open, while already-open X11 channels remain independent when the session
closes, as required by RFC 4254.
