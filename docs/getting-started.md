# Getting started

`modernssh` is an ESM package for Node.js 22 and newer. It exports its client, server, key,
authentication-agent, and channel types from the package root. Importing the package does not open
connections or install global patches.

## Client connection

```ts
import { once } from "node:events"
import { Client } from "@bunkerch/modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    port: 22,
    username: "deploy",
    password: process.env.SSH_PASSWORD,
    hostHash: "sha256",
    hostVerifier: (hash) => hash === process.env.SSH_HOST_KEY_SHA256_HEX,
    readyTimeout: 20_000,
    replyTimeout: 30_000,
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
await once(command, "close")

client.end()
```

Policy and credential decisions use `Hooker`, whose handlers may be asynchronous and are awaited
in registration order. Observe contained handler failures through the Hooker's
`uncaughtException` event; it always supplies an `Error`, including when JavaScript code rejects
with a primitive value. Ordinary `Client`, `Server`, and channel EventEmitter listeners are
synchronous notifications, so do not put authorization work in an async event listener.

Both `Client` and `Server` accept a `debug(...message)` option for diagnostics that must be
available from the start of their lifecycle. It receives the same arguments as the corresponding
`debug` event; applications may use either or both. Authentication secrets and key material are
redacted before this surface is called. The constructor diagnostic is an allow-listed summary: it
never forwards the configuration object, private keys, agents, sockets, or policy functions.
Configured secret-bearing objects are represented only by `"<configured>"`. Treat all remaining
values as operationally sensitive and ensure the diagnostic handler does not throw. Public-key
authentication diagnostics identify a candidate by its algorithm and SHA-256 fingerprint; they do
not expose the agent's opaque identity ID, key encoding, or key comment. Errors thrown by a signing
agent are reduced to a fixed failure-stage message rather than forwarded to diagnostic handlers.
The same rule applies to errors thrown while creating, advancing, or closing application-provided
GSS-API contexts; peer-supplied GSS-API status remains available through the typed protocol event.

```ts
const client = new Client({
    hostname: "ssh.example.com",
    debug: (...message) => logger.debug({ component: "ssh", message }),
})
```

Configure `hostVerifier` in production and compare the received raw serialized key, or the
lowercase hexadecimal `hostHash` digest shown above, with a value from a trusted source. The
verifier may return a boolean or a promise of one. The existing `hostKey`
hook can perform richer verification with a parsed `PublicKey`; when both mechanisms are present,
both must allow the key. With neither configured, the client accepts the cryptographically valid
host key implicitly, which does not authenticate an unknown server.

After authentication, a server may advertise additional host keys for rotation. The client
automatically requests an ownership proof bound to the current session and emits `hostKeys` only
with keys whose signatures verify. Exact `hostkeys=0` extension negotiation selects the standard
proof request and signed domain; servers without it retain compatibility behavior:

```ts
import { homedir } from "node:os"
import { join } from "node:path"
import { KnownHosts } from "@bunkerch/modernssh"

const knownHosts = await KnownHosts.load(join(homedir(), ".ssh", "known_hosts"))
const hostname = "ssh.example.com"
const port = 22

client.on("hostKeys", (publicKeys) => {
    void knownHosts
        .replaceHostKeys(hostname, publicKeys, { port })
        .catch((error) => logger.error({ error }, "Could not update known hosts"))
})
```

This event does not replace initial host verification. The proof is trustworthy only because the
current connection was first authenticated with an already trusted key. Unsupported, malformed,
unsigned, or incorrectly signed announcements are never emitted.

See [Known hosts](known-hosts.md) for initial verification, hashed hostname storage, certificate
authorities, revocations, and safe file updates.

`readyTimeout` bounds the complete connection setup: opening a TCP connection (unless `sock` is
supplied), exchanging SSH identification strings, negotiating transport keys, and authenticating.
It defaults to 20 seconds. Set it to `0` to disable the deadline. If the deadline expires,
`connect()` rejects with `Timed out while waiting for handshake` and the client destroys the
underlying transport.

`replyTimeout` bounds ordered connection-protocol replies after authentication and defaults to 30
seconds. It applies to rekey, transport ping, global requests, channel opens, and channel requests
in both peer roles. These replies have no independent request identifier and must remain ordered,
so expiry closes the connection: accepting a late reply while continuing would risk matching it to
later work. The value must be a positive number; choose it above the longest application hook that
is expected to answer a reply-requesting operation.
New SFTP and public-key management sessions inherit this value as their `requestTimeout`, which can
be overridden per session without changing the connection-wide deadline.

`maxPendingChannelOpens` defaults to 64 and bounds server-initiated channel opens awaiting an
asynchronous client decision, such as connecting an agent-forwarding channel to a local provider.
The same server option bounds client opens awaiting `channelOpenRequest` policy on each connection.
Additional opens receive RFC 4254 resource shortage while the SSH connection remains usable. Set
the value to zero when that role must reject every peer-initiated channel.

`maxChannels` defaults to 1024 in both roles and bounds all simultaneous channels on one SSH
connection, including locally initiated channels, established peer channels, and peer opens still
awaiting policy. Reaching the limit rejects a local open with `ChannelOpenError` or answers a peer
open with RFC 4254 resource shortage; it does not close the connection or invoke policy for the
rejected peer open. A slot becomes available only after both sides exchange `CHANNEL_CLOSE`. Set
the value to zero to disable every channel while retaining transport and global-request access.

For direct TCP connections, `localAddress` and `localPort` select the source binding. Set exactly
one of `forceIPv4` or `forceIPv6` to restrict hostname resolution to that address family. If both
flags have the same value, normal system resolution is used. These four options are ignored when
an already-connected `sock` is supplied.

`end()` sends `SSH_MSG_DISCONNECT` with the `BY_APPLICATION` reason and gracefully ends the TCP
connection. Use `disconnect(new DisconnectError(reason, description, languageTag))` to send a
specific validated reason and localized description instead. `destroy()` immediately destroys the
underlying connection. All three methods return the client instance. `setNoDelay()` controls
Nagle's algorithm on the underlying TCP socket and also returns the client. See
[SSH transport behavior](transport.md#auxiliary-transport-messages-and-shutdown) for a complete
disconnect example.

The `end` event reports peer transport EOF. Because SSH cannot continue without an inbound packet
stream, the client then destroys even an `allowHalfOpen` injected transport; terminal cleanup and
rejection of pending work complete at the later `close` event. After `close`, `canConnect` becomes
true and the same client may connect again. Each connection starts with fresh protocol parsers,
sequence numbers, negotiated keys, extensions, authentication state, channels, and forwarding
state; configured options, event listeners, and hooks remain installed. A client constructed with
an already-connected `sock` cannot reuse that destroyed transport, so supply a new client for a new
injected socket. Concurrent `connect()` calls are rejected. An asynchronous host-key, key-exchange,
or authentication provider that finishes after its transport closes remains bound to that old
connection; its result cannot install keys, send credentials, or clean up state belonging to a
later connection.

When `keepaliveInterval` is greater than zero, the client sends
`keepalive@openssh.com` global requests after authentication. Either success or failure is a valid
liveness response. The client emits an `SSH keepalive timeout` error and destroys the connection
after more than `keepaliveCountMax` consecutive probes go unanswered. The timer does not keep the
Node.js process alive; the options default to `0` (disabled) and `3`, respectively.

`Server` accepts the same options. Every authenticated `ServerClient` owns an independent,
unreferenced timer. A connection that exceeds its unanswered bound emits `SSH keepalive timeout`
through its `error` event and terminates without affecting other accepted clients.

```ts
const server = new Server({
    hostKeys,
    replyTimeout: 30_000,
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
})
```

Servers that advertise the `ping@openssh.com` transport extension may also be probed directly.
`ping()` echoes opaque bytes. Calls made during rekey are queued until the exchange finishes, and
concurrent replies retain request order.

```ts
const reply = await client.ping(Buffer.from("health-check"))
```

The method rejects without sending a vendor packet when the server did not advertise version `0`
of the extension. This is separate from the periodic `keepaliveInterval` global request above.

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
installs the same framing, error, end, close, keepalive, rekey, and channel cleanup handlers used
for a normal socket. `end()` and `destroy()` own and close the supplied transport; a destroyed
transport cannot be reused for another connection. `connect()` rejects before writing if the
supplied stream has already ended, closed, or stopped being both readable and writable.

`Server.injectSocket()` accepts the same kind of connected `Duplex`, so an application can run a
nested SSH server directly over an accepted channel without creating a loopback TCP listener:

```ts
import { DirectTCPIPChannel, Server } from "@bunkerch/modernssh"

const nested = new Server({ hostKeys: [nestedHostKey] })

gateway.on("connection", (connection) => {
    connection.on("channel", (channel) => {
        if (channel instanceof DirectTCPIPChannel) nested.injectSocket(channel.stream)
    })
})
```

The outer server must still authorize the `direct-tcpip` channel through its awaited
`channelOpenRequest` Hooker policy. The nested server owns the injected stream after acceptance
and applies its ordinary `preconnect`, key-exchange, authentication, channel, and cleanup paths.

## Server connection

```ts
import { readFile } from "node:fs/promises"
import { Server } from "@bunkerch/modernssh"

const server = new Server({
    hostKeys: [
        await readFile("./ssh_host_ed25519_key"),
        {
            key: await readFile("./ssh_host_ecdsa_key"),
            passphrase: process.env.SSH_HOST_KEY_PASSPHRASE,
        },
    ],
})

server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
    decision.allowLogin =
        context.username === "deploy" && context.password === process.env.SSH_PASSWORD
})

server.on("connection", (connection, endpoint) => {
    console.log("SSH peer", endpoint.remoteAddress, endpoint.remotePort)
    connection.on("error", (error) => {
        console.error("SSH peer error", error)
    })
})

server.listen(22, "127.0.0.1")
```

Supply persistent host keys in production. Entries may be loaded `PrivateKey` objects, encoded
strings or buffers, or `{ key, passphrase }` objects for encrypted containers. The constructor
parses every entry eagerly, rejects public keys and incorrect passphrases, and retains only parsed
private-key objects in private server configuration; it does not expose encoded containers,
passphrases, or host private keys through a public options bag. If `hostKeys` is empty, the server
generates a temporary Ed25519 key, which changes identity after every restart.
With the default `sendAllHostKeys: true`, advertised public identities must be unique and no more
than 64 may be configured. Set `sendAllHostKeys: false` when the server should select among a
larger key inventory without announcing it after authentication.

`Server` mirrors useful Node TCP-server controls without exposing callback completion flows.
`getConnections()` and `close()` return Promises, `listen()` reports readiness through the
`listening` event, and `address()`, `ref()`, and `unref()` remain synchronous. The readonly
`server.listening` and `server.connections` properties provide synchronous state snapshots;
`await server[Symbol.asyncDispose]()` closes an active listener and also permits `await using`.
Set `server.maxConnections` before listening to bound the transports owned concurrently by the
server:

```ts
server.maxConnections = 200
server.listen(22, "127.0.0.1")
```

The limit defaults to `Infinity` and accepts `Infinity` or a non-negative integer; zero denies every
new transport. A connection consumes a slot before the awaited `preconnect` policy runs, so slow
admission checks cannot bypass the bound. The server's `handshakeTimeout` starts before that policy,
so a policy that never settles cannot retain the slot indefinitely unless the deadline is explicitly
disabled. `getConnections()` includes these pending transports as well as admitted SSH clients, and
a slot is released when its underlying transport closes. `connections` reports the same owned set
synchronously. A peer rejected because the limit is full is closed before SSH parsing or
application policy begins, then emits `drop` with an immutable endpoint snapshot. The event also
covers injected transports, whose unavailable endpoint fields remain `undefined`.

Call `listen()` only once until the server has closed; a duplicate request made while host-key
preparation or native listener startup is pending throws synchronously instead of creating an
unhandled deferred error. Calling `close()` during that pending phase cancels startup, emits
`close`, and resolves without opening a listener later. Other deferred startup failures are
reported through the server's `error` event.
The `connection` event's immutable endpoint snapshot retains the remote and local address, family,
and port after the socket closes. Fields may be undefined for an injected or non-IP transport that
does not expose them.
`ServerClient.setNoDelay()` controls Nagle's algorithm when the transport exposes that TCP
capability and is a safe no-op for other duplex transports. Call `ServerClient.end()` for a
graceful application shutdown: it sends an RFC 4253 `BY_APPLICATION` disconnect before ending the
transport. `terminate()` destroys the transport immediately, while `disconnect(error)` sends a
caller-selected protocol reason, UTF-8 description, and optional RFC 3066 language tag. The
`DisconnectError` and `DisconnectReason` values are exported from the package root.

An application that already owns an accepted `net.Socket`, SSH channel, or custom connected
`Duplex` can pass it through the same admission and handshake path with
`server.injectSocket(transport)`. The exported `ServerTransport` interface requires duplex stream
behavior and makes TCP endpoint metadata and `setNoDelay()` optional. Injection synchronously
reserves a `maxConnections` slot and transfers ownership to the SSH server. The transport appears
in `getConnections()` immediately, runs the `preconnect` policy hook, and appears in
`server.clients` only after admission; it is removed from both applicable collections on close.
The injecting application retains responsibility for the outer listener. When `preconnect` hooks
are present, they must complete without rejection and explicitly set `allowConnection = true`;
denial happens before the public `connection` event. `injectSocket()` rejects a transport
synchronously if it has already closed or is no longer both readable and writable; attach it before
transferring or closing either side of the stream. The server rechecks the transport after deferred
host-key preparation and discards it without emitting `connection` if it closed during that
interval.

## Passphrase-protected private keys

Generate new Ed25519, RFC 8709 Ed448, RSA, or RFC 5656 ECDSA key pairs with `generateKeyPair()`.
RSA defaults to a 3072-bit modulus; ECDSA defaults to NIST P-256 and accepts 256, 384, or 521 bits. The returned
`PrivateKey` and `PublicKey` objects are immediately usable for signing, server host keys, agents,
or OpenSSH serialization. The API also accepts `"dsa"` solely for explicit RFC 4253 legacy
interoperability; its fixed DSA-1024/SHA-1 method is not a modern choice and is never offered by
default.

```ts
import { writeFile } from "node:fs/promises"
import { generateKeyPair } from "@bunkerch/modernssh"

const { privateKey, publicKey } = await generateKeyPair("ed25519", {
    comment: "deploy@build01",
})
await writeFile("./id_ed25519", `${privateKey.toString()}\n`, { mode: 0o600 })
await writeFile("./id_ed25519.pub", `${publicKey.toString()}\n`)
```

`generateKeyPairSync()` accepts the same key types and options when generation must finish before
ordinary control flow continues:

```ts
import { generateKeyPairSync } from "@bunkerch/modernssh"

const hostIdentity = generateKeyPairSync("ecdsa", {
    bits: 384,
    comment: "host@example.test",
})
```

Synchronous RSA and DSA parameter generation can block the Node.js event loop for a noticeable
amount of time. Prefer `generateKeyPair()` in servers and other latency-sensitive processes; use
the synchronous form for startup tooling or short-lived command-line programs where blocking is
intentional.

RSA accepts `bits` from 1024 through 16384, though new deployments should retain the 3072-bit
default or choose a larger policy-approved size. Ed25519 and Ed448 have fixed sizes and reject `bits`.
Ed448 is available for explicit deployments that need its higher security level; it is not in the
default host-key offer because it is not broadly deployed.
Comments cannot contain NUL or line endings because the public-key format is line-oriented. Key
generation uses the runtime cryptographic random source; write private material with restrictive
permissions and avoid logging it.

Pass encryption options to `PrivateKey.toString()` or `serialize()` when persisting generated or
loaded keys. Encryption uses OpenSSH's `bcrypt` KDF with 16 rounds and `aes256-ctr` by default,
matching the broadly compatible OpenSSH key-file defaults. Increase `rounds` according to the
latency budget of the application that loads the key.

```ts
const encrypted = privateKey.toString({
    passphrase: Buffer.from(process.env.KEY_PASSPHRASE!, "utf8"),
    cipher: "aes256-gcm@openssh.com",
    rounds: 32,
})
await writeFile("./id_ed25519", `${encrypted}\n`, { mode: 0o600 })
```

Supported output ciphers are 3DES-CBC; AES-128/192/256 CBC and CTR; AES-128/256 GCM; and
ChaCha20-Poly1305. Prefer AES-GCM or ChaCha20-Poly1305 when authenticated key-file encryption is
required. Empty passphrases and invalid round counts are rejected. The serializer copies caller
passphrase buffers and clears its derived key, IV, passphrase copy, and temporary plaintext key
buffers after encryption; callers remain responsible for clearing their original buffer.

### Reading protected keys

Use `parseKey()` when input may contain either a private or public key. It routes raw OpenSSH
private containers, armored private keys, PuTTY PPK private keys, SSH public-key blobs,
authorized-key lines, generic SubjectPublicKeyInfo public PEM, PKCS#1 RSA public PEM, and RFC 4716
public-key files by their explicit framing. The return type is `PrivateKey | PublicKey`; a
passphrase is accepted only when the input is private. Authorized-key, RFC 4716, and PPK blobs
require canonical standard base64; malformed characters and noncanonical pad bits are rejected
rather than silently ignored.

```ts
import { readFile } from "node:fs/promises"
import { parseKey, PrivateKey } from "@bunkerch/modernssh"

const key = parseKey(await readFile("./deploy_key"), process.env.SSH_KEY_PASSPHRASE)
if (!(key instanceof PrivateKey)) throw new Error("A private key is required")
```

PPK versions 2 and 3 can also be loaded directly with `PrivateKey.fromPuTTY()`. Import supports
RSA, DSA, Ed25519, Ed448, and the NIST P-256, P-384, and P-521 ECDSA curves. Encrypted version 3
files support Argon2d, Argon2i, and Argon2id with AES-256-CBC; version 2's SHA-1-based derivation is
accepted for existing keys but should not be selected for new storage. The loader authenticates
the complete public and private envelope before constructing a key, rejects incorrect or missing
passphrases, and clears passphrase copies, derived material, and temporary plaintext buffers.

To keep untrusted key files from causing unbounded work, PPK input is limited to 16 MiB, each
decoded key blob to 8 MiB, and Argon2 settings to 256 MiB of memory, 100 passes, and 64 lanes.
Comments must be valid UTF-8 without NUL or line endings. PPK support is import-only; serialize a
loaded key with `PrivateKey.toString()` when an OpenSSH private-key container is required.

RFC 4716 files can be read and written directly. Use `parseRFC4716PublicKey()` when only the key is
needed, or `parseRFC4716PublicKeyFile()` when unknown headers must survive a rewrite:

```ts
import { parseRFC4716PublicKeyFile, serializeRFC4716PublicKey } from "@bunkerch/modernssh"

const keyFile = parseRFC4716PublicKeyFile(await readFile("./deploy_key.pub"))
const rewritten = serializeRFC4716PublicKey(keyFile.publicKey, keyFile.headers)
```

Import accepts CR, LF, and CRLF files, joins backslash-continued headers, and applies a
case-insensitive `Comment` header to the returned `PublicKey`. Serialization folds headers and the
base64 body to the format's 72-byte physical-line limit. It enforces the exact begin/end markers,
64-byte ASCII header tags, 1,024-byte UTF-8 header values, and a body containing one canonical SSH
public-key blob. No blank PEM-style separator or CRC is accepted. `key.hash("md5")` provides the
legacy colon-separated RFC 4716 fingerprint display; prefer `key.hash("sha256")` for trust policy.

The private-key container format can hold more than one key. Use `parseKeys()`,
`PrivateKey.parseAll()`, or `PrivateKey.fromStringAll()` when such a container is allowed; these
return entries in wire order and verify every public envelope against its private entry. Singular
parsers reject a multi-key container rather than choosing one implicitly. Create one with
`PrivateKey.serializeMany(keys)` or `PrivateKey.toStringMany(keys)`, passing the same encryption
options accepted by a single key. Containers are limited to 1,024 keys and 16 MiB of binary data;
armored input is limited to 24 MiB.

Armored private-key parsing requires exact begin and end markers, ASCII content, non-empty body
lines, and canonical padded base64. Both LF and CRLF line endings are accepted, with an optional
final line ending. Whitespace around markers, blank body lines, invalid characters, and
noncanonical pad bits are rejected instead of being silently discarded by the runtime decoder.

`PrivateKey.fromString()` and `PrivateKey.parse()` accept an optional string or `Buffer`
passphrase. They read the `openssh-key-v1` format produced by `ssh-keygen`, including Ed25519, RSA,
and ECDSA keys encrypted with any cipher accepted by current OpenSSH: 3DES-CBC, AES-CBC, AES-CTR,
AES-GCM, and `chacha20-poly1305@openssh.com`.

`PrivateKey.fromString()` also accepts standard unencrypted PKCS#8 PEM for Ed25519, Ed448, RSA,
DSA, and the three supported ECDSA curves; traditional RSA and DSA PEM; and SEC1 EC PEM. Encrypted
PKCS#8 and traditional PEM use the same optional passphrase argument and are decrypted by Node's
native key parser before conversion into the library's validated SSH representation. Unsupported
key families and curves are rejected rather than silently coerced.

Call `PublicKey.fromPEM()` directly when the input is known to be a public PEM. It accepts Ed25519,
Ed448, RSA, legacy DSA, and the three supported ECDSA curves and converts them to the canonical SSH
public-key form.

Key envelopes validate algorithm identifiers with the RFC 4250 SSH-name rules and require the name
to match the contained key implementation. Private envelopes additionally require their public
identity to match the private material. Constructed envelopes copy their metadata object, so later
mutation of the caller's input object cannot silently relabel a retained key.

Comments are strict UTF-8 and may not contain NUL, CR, or LF. These rules apply to generated,
constructed, authorized-key, and private-container values, and are rechecked when mutable key
objects are serialized. Malformed container text is rejected instead of replacement-decoded.

Certificate public-key lines and wire blobs are parsed into `PublicKey` objects whose algorithm is
an exported `SSHCertificatePublicKey`. Its `data` exposes the certified plain key, CA key, serial,
role, identifier, principals, validity interval, critical options, and extensions without losing
64-bit values. Call `verifyCertificateSignature()` before using that metadata for authentication.
The caller must also enforce the expected role, current time, accepted principal, trusted CA, and
every critical option; parsing a valid CA signature alone is not an authorization decision.
Certificate identifiers, principals, and option names use fatal UTF-8 decoding. Critical options
and extensions must be strictly ordered by their exact encoded key bytes; duplicates and malformed
text are rejected while option values remain opaque buffers for policy-specific interpretation.

`DiskAgent` can receive a fixed passphrase or resolve one for each key path. A resolver is useful
when the secret comes from an application credential store and should only be fetched when a
signature is requested:

```ts
import { Client, DiskAgent } from "@bunkerch/modernssh"

const agent = new DiskAgent("/home/deploy/.ssh", {
    passphrase: async (privateKeyPath) => secretStore.read(privateKeyPath),
    onInvalidPublicKey: async (error, publicKeyPath) => {
        await auditLog.write({ error, publicKeyPath })
    },
})
const client = new Client({ hostname: "ssh.example.com", agent })
```

Each decryption attempt copies its passphrase and clears that temporary copy with the derived key
material. A fixed `Buffer` passphrase is additionally snapshotted and retained privately as agent
configuration so later signatures remain possible; use a resolver when the agent should fetch the
secret just in time instead. JavaScript strings themselves cannot be cleared.

The agent also snapshots its handler references during construction. Mutating the caller's options
object or clearing its original fixed passphrase buffer later does not change the configured agent.

The directory is resolved to an absolute normalized path. Discovery skips malformed public-key
companions; `onInvalidPublicKey` is awaited for each skipped identity so applications can report or
audit it. Direct lookup and discovery share the same whitespace-tolerant public-key parser.
Public-key comments may contain spaces and are preserved.

`DiskAgent.sign()` snapshots the message before reading key files or awaiting a passphrase resolver,
so caller mutation during key loading cannot change what is signed.

Socket-backed agents, including the Cygwin transport, likewise snapshot signing messages before
socket discovery, transport handshakes, or identity lookup.

## Public exports

The package root currently exports:

- `Client`, `Server`, and `ServerClient` plus their option, event, and hook types.
- `ClientChannel`, `ClientSessionChannel`, `Channel`, `SessionChannel`, and `Shell`.
- `Agent`, `PrivateKeyAgent`, `DiskAgent`, `SSHAgent`, `CygwinAgent`, `PageantAgent`,
  `createSocketAgent`, `SSHAgentProtocolClient`, `SSHAgentProtocolServer`, `OnePasswordAgent`, and
  their option, hook, constraint, management, extension, error, and agent-type definitions. See
  [SSH agent protocol](agent-protocol.md) for the complete Promise API and awaited hook surface.
- `PublicKey`, `PublicKeyAlgorithm`, `PrivateKey`, `EncodedSignature`,
  `ProtocolVersionExchange`, `generateKeyPair()`, `generateKeyPairSync()`, `parseKey()`, and
  `parseKeys()`.
- Public service, authentication, connection-state, and extended-data enums.

Deep imports into `dist/` are not part of the supported API. New public functionality will be added
to the root exports as its implementation and tests become library-ready.

## Socket agent authentication

`SSHAgent` uses a Unix-domain socket or Windows named pipe supplied explicitly or through
`SSH_AUTH_SOCK`. The client lists the agent's public identities and delegates signatures without
reading private key material. `sign()` snapshots its message before the asynchronous identity
lookup, so later mutation of a caller-owned buffer cannot change what the agent signs.

```ts
import { Client } from "@bunkerch/modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    agent: process.env.SSH_AUTH_SOCK,
})

await client.connect()
```

Passing a socket path calls `createSocketAgent(path)`. On POSIX it constructs `SSHAgent`. On Windows,
named-pipe paths such as `\\.\pipe\agent` also use `SSHAgent`, while other paths use `CygwinAgent`
for Cygwin's legacy socket-file transport. Construct a specific class directly to override that
selection or configure Cygwin handshake limits. Explicit paths must be non-empty strings without NUL
bytes. Path availability is checked when a Promise opens the connection rather than during
construction, so a later-created socket works and connection failures remain asynchronous. Custom
agent objects are validated during client construction and must provide a valid `AgentType` plus
`getPublicKeys()`, `getPublicKey()`, and `sign()` methods; an optional `getStream()` enables agent
forwarding.

On Windows, the special value `"pageant"` constructs `PageantAgent`. Pageant 0.75 and newer speaks
the standard agent protocol over a per-user named pipe whose protected name is derived through the
Windows cryptography API. Discovery happens during construction; importing the package or using a
different agent does not load the Windows FFI binding. Pageant may prompt before allowing a
signature, so the agent is marked interactive.

```ts
const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    agent: "pageant",
})
```

`new PageantAgent(pipePath)` bypasses discovery when an application already has the `IdentityAgent`
path emitted by Pageant's `--openssh-config` option. Automatic discovery is Windows-only and throws
`PageantAgentError` on unsupported platforms or when the native pipe name cannot be derived.

The agent messages follow [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html), are bounded to
256 KiB, handle fragmented socket reads, and treat identity IDs as opaque values. Identity comments
use fatal UTF-8 decoding, so malformed agent text fails the listing. Generic failure replies must
contain only their message byte; trailing fields are rejected.

`CygwinAgent` reads at most 4 KiB from the socket descriptor by default, accepts only the legacy
ASCII stream descriptor, and connects only to IPv4 loopback. It validates the complete 16-byte
secret echo, performs Cygwin's discovery and credentialed exchanges on separate TCP connections,
and applies a 10-second idle deadline to each handshake. `handshakeTimeout: 0` disables that
deadline; `maxSocketFileLength` may tighten the descriptor bound. On Windows only, an unreadable
POSIX-style path is resolved once through `cygpath -w`. The negotiated stream then uses the same
bounded RFC 9987 protocol client and may be forwarded like another stream-capable agent. Descriptor
contents, socket secrets, partial handshake reads, and discovered credential buffers are cleared
after negotiation or failure.

`OnePasswordAgent` uses the same protocol while discovering 1Password's default socket and
marks signing as interactive. It discovers the application group socket on macOS,
`~/.1password/agent.sock` on Linux, and 1Password's
[documented system-wide pipe](https://www.1password.dev/ssh/get-started),
`\\.\pipe\openssh-ssh-agent`, on Windows. Windows discovery does not probe the pipe at construction
time, so a stopped or disabled agent rejects the later Promise-based operation. Passing an explicit
path bypasses platform discovery. Access to an agent socket normally grants the ability to request
signatures, so do not expose or forward it to untrusted processes or hosts.
