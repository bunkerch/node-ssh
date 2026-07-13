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

client.end()
```

Register a `hostKey` hook in production and compare the received key with a value from a trusted
source. When no hook is registered, the current client accepts the negotiated host key implicitly;
that behavior is convenient for controlled tests but does not authenticate an unknown server.

`end()` sends `SSH_MSG_DISCONNECT` with the `BY_APPLICATION` reason and gracefully ends the TCP
connection. `destroy()` immediately destroys the underlying connection. Both methods return the
client instance.

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

## Public exports

The package root currently exports:

- `Client`, `Server`, and `ServerClient` plus their option, event, and hook types.
- `Channel`, `SessionChannel`, and `Shell`.
- `Agent`, `DiskAgent`, and their error and agent-type definitions.
- `PublicKey`, `PrivateKey`, `EncodedSignature`, and `ProtocolVersionExchange`.
- Public service, authentication, connection-state, and extended-data enums.

Deep imports into `dist/` are not part of the supported API. New public functionality will be added
to the root exports as its implementation and tests become library-ready.
