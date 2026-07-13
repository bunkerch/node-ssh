# Getting started

`modernssh` is an ESM package for Node.js 22 and newer. It exports its client, server, key,
authentication-agent, and channel types from the package root. Importing the package does not open
connections or install global patches.

## Client connection

```ts
import { Client } from "modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    port: 22,
    username: "deploy",
    password: process.env.SSH_PASSWORD,
    readyTimeout: 20_000,
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
})

client.hooker.hook("hostKey", (_hook, decision, hostKey) => {
    decision.allowHostKey =
        hostKey.hash("sha256") === "SHA256:replace-with-the-trusted-host-key-fingerprint"
})

client.on("error", (error) => {
    console.error("SSH connection error", error)
})

await client.connect()
console.log("Authenticated", client.isConnected)

const command = await client.exec("uname -a")
command.pipe(process.stdout)
command.stderr.pipe(process.stderr)
await new Promise<void>((resolve) => command.once("close", resolve))

client.end()
```

Register a `hostKey` hook in production and compare the received key with a value from a trusted
source. When no hook is registered, the current client accepts the negotiated host key implicitly;
that behavior is convenient for controlled tests but does not authenticate an unknown server.

`readyTimeout` bounds the complete connection setup: opening a TCP connection (unless `sock` is
supplied), exchanging SSH identification strings, negotiating transport keys, and authenticating.
It defaults to 20 seconds. Set it to `0` to disable the deadline. If the deadline expires,
`connect()` rejects with `Timed out while waiting for handshake` and the client destroys the
underlying transport.

`end()` sends `SSH_MSG_DISCONNECT` with the `BY_APPLICATION` reason and gracefully ends the TCP
connection. `destroy()` immediately destroys the underlying connection. Both methods return the
client instance. `setNoDelay()` controls Nagle's algorithm on the underlying TCP socket and also
returns the client.

When `keepaliveInterval` is greater than zero, the client sends
`keepalive@openssh.com` global requests after authentication. Either success or failure is a valid
liveness response. The client emits an `SSH keepalive timeout` error and destroys the connection
after more than `keepaliveCountMax` consecutive probes go unanswered. The timer does not keep the
Node.js process alive; both options default to ssh2-compatible values of `0` (disabled) and `3`.

## Connection hopping

Pass an already-connected Node `Duplex` as `sock` to run SSH over an application-owned transport.
A common use is opening a second SSH connection through a jump host:

```ts
const jump = new Client({ hostname: "jump.example.com", username: "deploy" })
await jump.connect()

const tunnel = await jump.forwardOut("127.0.0.1", 0, "target.internal", 22)
const target = new Client({ sock: tunnel, username: "deploy" })
await target.connect()

const command = await target.exec("hostname")
command.pipe(process.stdout)
```

When `sock` is supplied, `hostname` is optional and no new TCP connection is created. The client
installs the same framing, error, close, keepalive, rekey, and channel cleanup handlers used for a
normal socket. `end()` and `destroy()` own and close the supplied transport; a destroyed transport
cannot be reused for another connection.

## Server connection

```ts
import { readFile } from "node:fs/promises"
import { PrivateKey, Server } from "modernssh"

const hostKey = PrivateKey.fromString(await readFile("./ssh_host_ed25519_key", "utf8"))
const server = new Server({ hostKeys: [hostKey] })

server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
    decision.allowLogin =
        context.username === "deploy" && context.password === process.env.SSH_PASSWORD
})

server.on("connection", (connection) => {
    connection.on("error", (error) => {
        console.error("SSH peer error", error)
    })
})

server.listen(22, "127.0.0.1")
```

Supply persistent host keys in production. If `hostKeys` is empty, the server generates a temporary
Ed25519 key, which changes identity after every restart.

`Server` mirrors the useful Node TCP-server controls: `address()`, `getConnections()`, `close()`,
`ref()`, and `unref()` all operate without reaching into an internal socket and return the server
where Node supports chaining. `ServerClient.setNoDelay()` controls Nagle's algorithm per accepted
connection.

An application that already owns an accepted `net.Socket` can pass it through the same admission
and handshake path with `server.injectSocket(socket)`. Injected sockets still run the `preconnect`
policy hook, appear in `server.clients` and `getConnections()`, and are removed on close. The
injecting application retains responsibility for the outer listener; the SSH server owns the
injected connected socket after acceptance.

## Passphrase-protected private keys

`PrivateKey.fromString()` and `PrivateKey.parse()` accept an optional string or `Buffer`
passphrase. They read the `openssh-key-v1` format produced by `ssh-keygen`, including Ed25519 and
RSA keys encrypted with any cipher accepted by current OpenSSH: 3DES-CBC, AES-CBC, AES-CTR,
AES-GCM, and `chacha20-poly1305@openssh.com`.

```ts
import { readFile } from "node:fs/promises"
import { PrivateKey } from "modernssh"

const privateKey = PrivateKey.fromString(
    await readFile("./id_ed25519", "utf8"),
    process.env.SSH_KEY_PASSPHRASE,
)
```

`DiskAgent` can receive a fixed passphrase or resolve one for each key path. A resolver is useful
when the secret comes from an application credential store and should only be fetched when a
signature is requested:

```ts
import { Client, DiskAgent } from "modernssh"

const agent = new DiskAgent("/home/deploy/.ssh", {
    passphrase: async (privateKeyPath) => secretStore.read(privateKeyPath),
})
const client = new Client({ hostname: "ssh.example.com", agent })
```

Passphrases and derived key material are copied into temporary buffers and cleared after the
decryption attempt. JavaScript strings themselves cannot be cleared; use a `Buffer` when the
caller also needs explicit control over its original secret storage.

## Public exports

The package root currently exports:

- `Client`, `Server`, and `ServerClient` plus their option, event, and hook types.
- `ClientChannel`, `ClientSessionChannel`, `Channel`, `SessionChannel`, and `Shell`.
- `Agent`, `DiskAgent`, `SSHAgent`, `OnePasswordAgent`, and their option, error, and agent-type
  definitions.
- `PublicKey`, `PrivateKey`, `EncodedSignature`, and `ProtocolVersionExchange`.
- Public service, authentication, connection-state, and extended-data enums.

Deep imports into `dist/` are not part of the supported API. New public functionality will be added
to the root exports as its implementation and tests become library-ready.

## OpenSSH agent authentication

`SSHAgent` uses the UNIX socket supplied explicitly or through `SSH_AUTH_SOCK`. The client lists the
agent's public identities and delegates signatures without reading private key material.

```ts
import { Client, SSHAgent } from "modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    agent: new SSHAgent(),
})

await client.connect()
```

The implementation follows [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html), bounds messages
to OpenSSH's 256 KiB limit, handles fragmented socket reads, and treats identity IDs as opaque
values. `OnePasswordAgent` uses the same protocol while discovering 1Password's default socket and
marks signing as interactive. Access to an agent socket normally grants the ability to request
signatures, so do not expose or forward it to untrusted processes or hosts.
