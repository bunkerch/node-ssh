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
    hostHash: "sha256",
    hostVerifier: (hash) => hash === process.env.SSH_HOST_KEY_SHA256_HEX,
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

Configure `hostVerifier` in production and compare the received raw serialized key, or the
lowercase hexadecimal `hostHash` digest shown above, with a value from a trusted source. The
verifier may return a boolean or call its second argument asynchronously. The existing `hostKey`
hook can perform richer verification with a parsed `PublicKey`; when both mechanisms are present,
both must allow the key. With neither configured, the client accepts the cryptographically valid
host key implicitly, which does not authenticate an unknown server.

After authentication, a server may advertise additional host keys for rotation. The client
automatically requests an ownership proof bound to the current session and emits `hostKeys` only
with keys whose signatures verify:

```ts
client.on("hostKeys", async (publicKeys) => {
    await knownHosts.replaceHostKeys(
        client.options.hostname,
        publicKeys.map((key) => key.toString()),
    )
})
```

This event does not replace initial host verification. The proof is trustworthy only because the
current connection was first authenticated with an already trusted key. Unsupported, malformed,
unsigned, or incorrectly signed announcements are never emitted.

`readyTimeout` bounds the complete connection setup: opening a TCP connection (unless `sock` is
supplied), exchanging SSH identification strings, negotiating transport keys, and authenticating.
It defaults to 20 seconds. Set it to `0` to disable the deadline. If the deadline expires,
`connect()` rejects with `Timed out while waiting for handshake` and the client destroys the
underlying transport.

For direct TCP connections, `localAddress` and `localPort` select the source binding. Set exactly
one of `forceIPv4` or `forceIPv6` to restrict hostname resolution to that address family. If both
flags have the same value, normal system resolution is used. These four options are ignored when
an already-connected `sock` is supplied.

`end()` sends `SSH_MSG_DISCONNECT` with the `BY_APPLICATION` reason and gracefully ends the TCP
connection. `destroy()` immediately destroys the underlying connection. Both methods return the
client instance. `setNoDelay()` controls Nagle's algorithm on the underlying TCP socket and also
returns the client.

When `keepaliveInterval` is greater than zero, the client sends
`keepalive@openssh.com` global requests after authentication. Either success or failure is a valid
liveness response. The client emits an `SSH keepalive timeout` error and destroys the connection
after more than `keepaliveCountMax` consecutive probes go unanswered. The timer does not keep the
Node.js process alive; the options default to `0` (disabled) and `3`, respectively.

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

Generate new Ed25519, RFC 8709 Ed448, RSA, or RFC 5656 ECDSA key pairs with `generateKeyPair()`.
RSA defaults to a 3072-bit modulus; ECDSA defaults to NIST P-256 and accepts 256, 384, or 521 bits. The returned
`PrivateKey` and `PublicKey` objects are immediately usable for signing, server host keys, agents,
or OpenSSH serialization. The API also accepts `"dsa"` solely for explicit RFC 4253 legacy
interoperability; its fixed DSA-1024/SHA-1 method is not a modern choice and is never offered by
default.

```ts
import { writeFile } from "node:fs/promises"
import { generateKeyPair } from "modernssh"

const { privateKey, publicKey } = await generateKeyPair("ed25519", {
    comment: "deploy@build01",
})
await writeFile("./id_ed25519", `${privateKey.toString()}\n`, { mode: 0o600 })
await writeFile("./id_ed25519.pub", `${publicKey.toString()}\n`)
```

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
private containers, armored private keys, SSH public-key blobs, authorized-key lines, generic
SubjectPublicKeyInfo public PEM, and PKCS#1 RSA public PEM by their explicit framing. The return
type is `PrivateKey | PublicKey`; a passphrase is accepted only when the input is private.

```ts
import { readFile } from "node:fs/promises"
import { parseKey, PrivateKey } from "modernssh"

const key = parseKey(await readFile("./deploy_key"), process.env.SSH_KEY_PASSPHRASE)
if (!(key instanceof PrivateKey)) throw new Error("A private key is required")
```

The private-key container format can hold more than one key. Use `parseKeys()`,
`PrivateKey.parseAll()`, or `PrivateKey.fromStringAll()` when such a container is allowed; these
return entries in wire order and verify every public envelope against its private entry. Singular
parsers reject a multi-key container rather than choosing one implicitly. Create one with
`PrivateKey.serializeMany(keys)` or `PrivateKey.toStringMany(keys)`, passing the same encryption
options accepted by a single key.

`PrivateKey.fromString()` and `PrivateKey.parse()` accept an optional string or `Buffer`
passphrase. They read the `openssh-key-v1` format produced by `ssh-keygen`, including Ed25519, RSA,
and ECDSA keys encrypted with any cipher accepted by current OpenSSH: 3DES-CBC, AES-CBC, AES-CTR,
AES-GCM, and `chacha20-poly1305@openssh.com`.

`PrivateKey.fromString()` also accepts standard unencrypted PKCS#8 PEM for Ed25519, Ed448, RSA, DSA, and
the three supported ECDSA curves; traditional RSA and DSA PEM; and SEC1 EC PEM. Encrypted PKCS#8
and traditional PEM use the same optional passphrase argument and are decrypted by Node's native
key parser before conversion into the library's validated SSH representation. Unsupported key
families and curves are rejected rather than silently coerced.

Call `PublicKey.fromPEM()` directly when the input is known to be a public PEM. It accepts Ed25519,
Ed448, RSA, legacy DSA, and the three supported ECDSA curves and converts them to the canonical SSH
public-key form.

Certificate public-key lines and wire blobs are parsed into `PublicKey` objects whose algorithm is
an exported `SSHCertificatePublicKey`. Its `data` exposes the certified plain key, CA key, serial,
role, identifier, principals, validity interval, critical options, and extensions without losing
64-bit values. Call `verifyCertificateSignature()` before using that metadata for authentication.
The caller must also enforce the expected role, current time, accepted principal, trusted CA, and
every critical option; parsing a valid CA signature alone is not an authorization decision.

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
- `Agent`, `PrivateKeyAgent`, `DiskAgent`, `SSHAgent`, `OnePasswordAgent`, and their option, error,
  and agent-type definitions.
- `PublicKey`, `PrivateKey`, `EncodedSignature`, and `ProtocolVersionExchange`.
- Public service, authentication, connection-state, and extended-data enums.

Deep imports into `dist/` are not part of the supported API. New public functionality will be added
to the root exports as its implementation and tests become library-ready.

## OpenSSH agent authentication

`SSHAgent` uses the UNIX socket supplied explicitly or through `SSH_AUTH_SOCK`. The client lists the
agent's public identities and delegates signatures without reading private key material.

```ts
import { Client } from "modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    agent: process.env.SSH_AUTH_SOCK,
})

await client.connect()
```

Passing a socket path is shorthand for constructing `new SSHAgent(path)`. Construct `SSHAgent`
directly when its methods or socket metadata are also needed. The implementation follows
[RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html), bounds messages
to OpenSSH's 256 KiB limit, handles fragmented socket reads, and treats identity IDs as opaque
values. `OnePasswordAgent` uses the same protocol while discovering 1Password's default socket and
marks signing as interactive. Access to an agent socket normally grants the ability to request
signatures, so do not expose or forward it to untrusted processes or hosts.
