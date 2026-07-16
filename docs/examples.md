# Examples

These recipes use only the package-root ESM API. Public operations are Promise-based, application
policy uses awaited `Hooker` handlers, and EventEmitter listeners remain synchronous. See
[Getting started](getting-started.md) for every connection option and the
[API reference](api/index.md) for exact declarations.

## Connect with known-hosts verification

```ts
import { homedir } from "node:os"
import { join } from "node:path"
import { Client, KnownHosts } from "@bunkerch/modernssh"

const hostname = "ssh.example.com"
const knownHosts = await KnownHosts.load(join(homedir(), ".ssh", "known_hosts"))
const client = new Client({
    hostname,
    username: "deploy",
    agent: process.env.SSH_AUTH_SOCK,
    hostVerifier: knownHosts.verifier(hostname),
})

client.on("error", (error) => console.error("SSH connection error", error))
await client.connect()
```

The verifier rejects unknown, changed, and revoked keys. See [Known hosts](known-hosts.md) for
first-use enrollment, host certificates, hashed hostnames, and safe key rotation.

## Run a command and capture its result

Read stdout and stderr concurrently so neither channel can block the other. The `close` event means
the complete channel lifecycle has finished; inspect the exit fields afterward.

```ts
import { once } from "node:events"
import type { Readable } from "node:stream"

async function collect(stream: Readable): Promise<Buffer> {
    const chunks: Buffer[] = []
    for await (const chunk of stream) chunks.push(Buffer.from(chunk))
    return Buffer.concat(chunks)
}

const command = await client.exec("git status --short")
const closed = once(command, "close")
const [stdout, stderr] = await Promise.all([collect(command), collect(command.stderr)])
await closed

console.log({
    stdout: stdout.toString("utf8"),
    stderr: stderr.toString("utf8"),
    exitCode: command.exitCode,
    exitSignal: command.exitSignal,
})
```

To provide stdin, write to the returned duplex channel and end its writable side:

```ts
const command = await client.exec("sha256sum -")
command.end(fileContents)
command.pipe(process.stdout)
command.stderr.pipe(process.stderr)
await once(command, "close")
```

## Open an interactive shell

```ts
import { once } from "node:events"

const shell = await client.shell({
    pty: {
        term: process.env.TERM ?? "xterm-256color",
        columns: process.stdout.columns ?? 80,
        rows: process.stdout.rows ?? 24,
    },
})

process.stdin.pipe(shell)
shell.pipe(process.stdout)
shell.stderr.pipe(process.stderr)
await once(shell, "close")
```

Call `shell.setWindow()` when the local terminal is resized. The [channel guide](channels.md)
covers PTY modes, environment variables, signals, exit results, X11, agent forwarding, and
half-close behavior.

## Upload and download with SFTP

Whole-file helpers resolve only after the operation completes:

```ts
const sftp = await client.sftp()

try {
    await sftp.fastPut("./release.tar.gz", "/srv/releases/release.tar.gz", {
        mode: 0o640,
        concurrency: 8,
    })
    await sftp.fastGet("/var/log/service.log", "./service.log", {
        concurrency: 8,
    })
} finally {
    sftp.end()
}
```

Use Node stream pipelines when data should remain streaming and backpressure-aware:

```ts
import { createReadStream, createWriteStream } from "node:fs"
import { pipeline } from "node:stream/promises"

await pipeline(
    createReadStream("./large-image.raw"),
    sftp.createWriteStream("/srv/data/large-image.raw", { mode: 0o640 }),
)

await pipeline(sftp.createReadStream("/srv/data/result.bin"), createWriteStream("./result.bin"))
```

See [SFTP](sftp.md) for atomic rename, directory iteration, exact `bigint` offsets, attributes,
request limits, extensions, and implementing an SFTP server.

## Connect through a jump host

An SSH channel is a Node duplex stream, so it can carry another SSH connection without a local
port or process-wide connection-sharing mechanism:

```ts
const jump = new Client({
    hostname: "jump.example.com",
    username: "deploy",
    hostVerifier: verifyJumpHost,
})
await jump.connect()

const transport = await jump.forwardOut("127.0.0.1", 0, "database.internal", 22)
const target = new Client({
    sock: transport,
    username: "database-admin",
    hostVerifier: verifyDatabaseHost,
})
await target.connect()

try {
    const command = await target.exec("hostname")
    command.pipe(process.stdout)
    command.stderr.pipe(process.stderr)
    await once(command, "close")
} finally {
    target.end()
    jump.end()
}
```

Host verification is independent at each hop. The target verifier must authenticate the target,
not the jump host.

## Forward a local connection

`forwardOut()` creates a direct TCP channel to a destination visible from the SSH server:

```ts
import { once } from "node:events"
import net from "node:net"

async function forward(local: net.Socket): Promise<void> {
    const tunnel = await client.forwardOut(
        local.remoteAddress ?? "127.0.0.1",
        local.remotePort ?? 0,
        "database.internal",
        5432,
    )
    local.pipe(tunnel).pipe(local)
}

const listener = net.createServer((local) => {
    void forward(local).catch((error) => local.destroy(error))
})
const listening = once(listener, "listening")
listener.listen(5432, "127.0.0.1")
await listening
```

For an SSH-backed Node HTTP or HTTPS agent, remote listening, Unix sockets, or packet tunnels, see
[Forwarding](forwarding.md) and [packet tunnels](tunnels.md).

## Serve one allowed command

The server separately authorizes authentication, channel admission, and the requested command.
Every policy decision is made in an awaited Hooker handler.

```ts
import { once } from "node:events"
import { Server, SessionChannel, generateKeyPair } from "@bunkerch/modernssh"

const { privateKey: hostKey } = await generateKeyPair("ed25519")
const server = new Server({ hostKeys: [hostKey] })

server.on("error", (error) => console.error("SSH server error", error))

server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
    decision.allowLogin =
        context.username === "status" && context.password === process.env.STATUS_PASSWORD
})

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen = channel instanceof SessionChannel
})

server.on("connection", (connection) => {
    connection.on("error", (error) => console.error("SSH peer error", error))
    connection.on("channel", (channel) => {
        if (!(channel instanceof SessionChannel)) return

        channel.hooker.hook("execRequest", (_hook, context, decision) => {
            decision.success = context.command === "status"
        })

        channel.events.on("exec", (_command, stream) => {
            void stream
                .writeStdout("ok\n")
                .then(() => stream.exit(0).end())
                .catch((error) => stream.destroy(error))
        })
    })
})

const listening = once(server, "listening")
server.listen(2222, "127.0.0.1")
await listening
```

Use a persistent host key and a password hash or external identity provider in production. The
[authentication guide](authentication.md) covers public keys, keyboard-interactive, certificates,
multi-factor policy, and attempt limits. The [channel guide](channels.md) covers exec, shell,
subsystem, environment, and terminal policy.

## Close resources

Close channels and subsystem sessions before their connection when possible. `Server.close()` is
already a Promise; event-based channel completion uses `once()` from `node:events`.

```ts
try {
    await useClient(client)
} finally {
    const closed = once(client, "close")
    client.end()
    await closed
}

await server.close()
```

An abrupt failure can use `client.destroy()`, `sftp.destroy(error)`, or the corresponding stream
destruction API. Pending Promise operations reject when their transport or channel is torn down.
