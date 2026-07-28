---
title: SSH agent protocol
description: Identity management, constraints, locking, extensions, and restricted agent endpoints.
---

# SSH agent protocol

`SSHAgentProtocolClient` and `SSHAgentProtocolServer` implement the connection-oriented agent
protocol from RFC 9987 over an already-connected Node.js `Duplex`. The same classes work with a
local agent socket and with an authorized forwarded-agent channel.

An `Agent.getStream()` implementation used for forwarding must resolve to a live, readable and
writable Node.js `Duplex`. A rejected operation, non-stream result, or already-closed stream rejects
only that channel open with `SSH_OPEN_CONNECT_FAILED`; it does not close the SSH connection or
forward the provider's error details to diagnostics.

## Client

All client operations return promises. Agent messages do not carry request identifiers, so one
client serializes requests and requires each reply before sending the next request. The default
reply deadline is 10 seconds. A timeout destroys the stream because a late, untagged reply could
otherwise be mistaken for the reply to a later request.

Invalid framing, oversized messages, non-buffer stream data, and unsolicited response bytes also
destroy the persistent stream and clear buffered input. These violations make it unsafe to match a
later untagged reply to a request. A well-formed one-byte failure response only rejects that request
and leaves the connection available for later operations.

`sign()` snapshots its message when called, before queued identity lookup or earlier agent requests
can delay the signing frame. Later mutation of a caller-owned buffer cannot change what is signed.
The internal message snapshot, request payload, wire frame, and response frame are cleared after the
operation settles; this does not modify the caller's buffer.

```ts
import { createConnection } from "node:net"
import { once } from "node:events"
import { SSHAgentProtocolClient } from "@bunkerch/modernssh"

const socket = createConnection(process.env.SSH_AUTH_SOCK!)
await once(socket, "connect")

const agent = new SSHAgentProtocolClient(socket)
try {
    const identities = await agent.getPublicKeys()
    const [id, publicKey] = identities[0]
    const message = Buffer.from("application challenge")
    const signature = await agent.sign(id, message)
    if (!publicKey.verifySignature(message, signature)) throw new Error("Invalid signature")
} finally {
    await agent.close()
}
```

`close()` stops accepting new operations, drains requests that were already queued, sends EOF, and
settles after the duplex stream closes. Concurrent calls share one Promise, and
`Symbol.asyncDispose` exposes the same lifecycle for `await using`. When `requestTimeout` is
nonzero, it also bounds terminal stream closure and destroys an unresponsive stream. Use
`destroy(error?)` when queued work must be aborted immediately.

The management methods are:

- `addIdentity(privateKey, options?)` adds a DSA, ECDSA, Ed25519, Ed448, RSA, security-key,
  certificate-backed, or registered custom private-key type. `options.comment` overrides the key
  comment. The option bag must be a plain object, the comment must be a string when present, and
  constraints must be an array.
- `addToken(tokenId, pin?, options?)` asks the agent to load keys from a hardware token. The add
  request treats the token identifier and PIN as opaque SSH strings. Its option bag must be a plain
  object and its constraints must be an array.
- `removeIdentity(publicKey)`, `removeAllIdentities()`, and `removeToken(tokenId, pin?)` remove
  loaded identities. RFC 9987 requires the remove-token identifier and PIN to be valid UTF-8.
- `lock(passphrase)` and `unlock(passphrase)` change the agent lock state.
- `extension(type, contents?)` sends a named extension request and returns either
  `{ kind: "success" }` or `{ kind: "response", contents }`.
- `queryExtensions()` uses the standard `query` extension and returns its advertised extension
  names.

The system interoperability suite starts a real `ssh-agent`, initializes an isolated SoftHSM token,
and sends a constrained `addToken()` request through `SSHAgentProtocolClient`. The agent discovers
the token's RSA identity, produces a verified RSA-SHA2-512 signature, removes the provider through
`removeToken()`, and reports an empty identity set afterward. This exercises the standard agent
token operations without physical hardware or an in-process agent implementation.

Create a certificate-backed identity by attaching a parsed certificate to its matching private
key. The certificate, its embedded public key, and the private material are checked for an exact
match before the request is sent.

```ts
import { readFile } from "node:fs/promises"
import { PrivateKey, PublicKey } from "@bunkerch/modernssh"

const subject = PrivateKey.fromString(await readFile("id_ed25519", "utf8"))
const certificate = PublicKey.parseString(await readFile("id_ed25519-cert.pub", "utf8"))
const certifiedSubject = subject.withCertificate(certificate)

await agent.addIdentity(certifiedSubject, { comment: "deployment certificate" })
```

Standard certificate algorithm names use the private-certificate encoding from
`draft-ietf-sshm-cert-01`: the complete certificate followed by only the corresponding private
fields. Deployed certificate aliases use their established complete private-key field layout. The
client selects the layout from the certificate algorithm name, and the server accepts both while
validating the binding before invoking application policy.

An extension-specific failure rejects with `SSHAgentExtensionFailureError`. A normal
`SSHAgentProtocolError` means the extension was unsupported, the request was refused, the reply
was malformed, the stream failed, or the deadline expired.

### OpenSSH session binding

`opensshSessionBind()` binds one agent connection to a host key and the session identifier from an
SSH key exchange. The host-key signature is verified locally before the request is sent. Set
`forwarding` to `true` for a forwarding hop and to `false` for the final user-authentication
session.

```ts
await agent.opensshSessionBind({
    hostKey,
    sessionIdentifier,
    signature: hostKeySignature,
    forwarding: true,
})
```

The identifier and signature must be the values from the same initial key exchange; an arbitrary
application signature is not a session binding. A refused or malformed bind rejects with
`SSHAgentExtensionFailureError`. The extension permits at most 16 accepted bindings on one
connection, rejects duplicate identifiers, and rejects any further binding after a final
authentication binding.

### Key constraints

Pass constraints when adding an identity or token:

```ts
await agent.addIdentity(privateKey, {
    comment: "deployment key",
    constraints: [
        { type: "lifetime", seconds: 15 * 60 },
        { type: "confirm" },
        {
            type: "extension",
            name: "policy@example.com",
            data: Buffer.from([1]),
        },
    ],
})
```

Lifetime values are unsigned 32-bit seconds. A confirmation constraint asks the agent to obtain
explicit approval for each private-key operation. An extension constraint consumes the remaining
bytes of the request because RFC 9987 gives its data no separate length; it must therefore be the
last constraint. Unknown constraints fail closed on the server. Explicit `null` is never treated as
an empty constraint list, because doing so would silently remove restrictions from the added key.

Destination restrictions use a typed constraint so their boundary remains parseable when another
constraint follows:

```ts
await agent.addIdentity(privateKey, {
    constraints: [
        {
            type: "openssh-restrict-destination",
            destinations: [
                {
                    // Omitting `from` means the machine running the agent.
                    to: {
                        username: "alice",
                        hostname: "target.example",
                        hostKeys: [{ publicKey: targetHostKey }],
                    },
                },
            ],
        },
        { type: "confirm" },
    ],
})
```

For forwarded paths, `from` identifies the preceding host and `to` identifies the following host.
Each host key may set `certificateAuthority: true` to match certificates signed by that CA instead
of matching the key directly. A target hostname and at least one target host key are required.

Token requests can associate certificates produced by `ssh-keygen` or another conforming SSH
certificate issuer with token-hosted private keys:

```ts
await agent.addToken(providerPath, pin, {
    constraints: [
        {
            type: "openssh-associated-certificates",
            certificatesOnly: true,
            certificates: [userCertificate],
        },
    ],
})
```

Associated certificates are valid only for constrained token-add requests. Every entry must be an
SSH certificate, and the list cannot be empty. `certificatesOnly` asks the token implementation to
load only the certificate identities rather than also exposing their plain public-key identities.

Security-key private containers retain an authenticator key handle rather than a locally usable
private scalar. Load one with its published provider constraint:

```ts
import { readFile } from "node:fs/promises"
import { PrivateKey } from "@bunkerch/modernssh"

const privateKey = PrivateKey.fromString(await readFile("./id_ed25519_sk", "utf8"))
await agent.addIdentity(privateKey, {
    constraints: [
        {
            type: "openssh-security-key-provider",
            provider: "internal",
        },
    ],
})
```

`OPENSSH_AGENT_SECURITY_KEY_PROVIDER` is the literal `sk-provider@openssh.com` extension name.
Exactly one typed provider constraint is required for a security-key identity, and it is rejected
for ordinary identities and token requests. Unlike a generic extension constraint, its provider is
a length-delimited string, so another constraint may follow it. Empty, NUL-containing, malformed,
duplicate, and untyped provider constraints are rejected before sending or before server policy.

Calling `sign()` directly on `SSHED25519SecurityKeyPrivateKey` or
`SSHECDSASecurityKeyPrivateKey` fails explicitly; signing requires an agent/provider that can use
the retained key handle. A filesystem middleware path causes the receiving agent to load native
code and must be treated as trusted configuration. `internal` selects the receiving agent's built-in
provider when it offers one.

Private-key, PIN, and passphrase request frames are copied for transport and cleared after they
have been written and answered. This does not clear buffers retained by the caller.

## Server

`SSHAgentProtocolServer` exposes application-owned identities through awaited `Hooker` policy.
Every security-sensitive decision is denied unless its hook explicitly supplies a valid result and
every registered handler completes without rejection. In particular, a contained later identity or
signing failure discards a result supplied by an earlier handler. The same rule applies to identity
and token additions and removals: the agent returns success only after the complete handler chain
finishes, so an earlier approval cannot hide a later storage failure.

```ts
import { SSHAgentProtocolServer } from "@bunkerch/modernssh"

const server = new SSHAgentProtocolServer()

server.hooker.hook("identities", async (_hook, decision) => {
    decision.identities = await listAllowedIdentities()
})

server.hooker.hook("sign", async (_hook, request, decision) => {
    decision.signature = await signIfAllowed(request.publicKey, request.data, request.algorithm)
})

server.hooker.hook("removeAllIdentities", async (_hook, decision) => {
    await removeEveryIdentity()
    decision.success = true
})

await server.serve(connectedStream)
```

The available hooks are `identities`, `sign`, `addIdentity`, `addToken`, `removeIdentity`,
`removeAllIdentities`, `removeToken`, `lock`, `unlock`, `extension`, `queryExtensions`, and
`sessionBind`. Hooks run in wire order. Requests across multiple streams served by one server are
also globally ordered so a successful lock cannot race a later sensitive operation on another
stream. Before a globally queued request reaches policy, the server rechecks its originating
stream and discards the request if that stream has already closed.

Every hook receives an `SSHAgentProtocolConnectionContext` as its final argument. Its `stream`
identifies the served connection, `sessionBindAttempted` records even malformed or refused bind
attempts, and `sessionBindings` contains defensive snapshots of accepted bindings in forwarding
order. Its `signal` is aborted when the served stream closes or its server request deadline
expires; pass that signal to cancellable key stores, hardware providers, and authorization
backends.

```ts
server.hooker.hook("sessionBind", async (_hook, binding, decision, connection) => {
    decision.success = await allowAgentPathBinding(binding, connection.sessionBindings)
})

server.hooker.hook("sign", async (_hook, request, decision, connection) => {
    decision.signature = await signIfPathAllowed(
        request,
        connection.sessionBindings,
        connection.signal,
    )
})
```

The server validates the binding signature and ordering before invoking `sessionBind`, but the hook
is deny-by-default and must set `success = true`. Registering this hook automatically advertises
`session-bind@openssh.com` from `queryExtensions`; the server refuses to advertise that name when
no binding policy is installed.

The protocol server does not own the application key store. Applications must retain destination
constraints accepted by `addIdentity` or `addToken` and enforce them during later identity, signing,
and removal hooks using the connection bindings. Merely approving `sessionBind` records the path;
it does not authorize use of a destination-constrained key.

Set `success = true` for add, remove, lock, and unlock hooks. For a generic extension, set one of:

```ts
decision.result = { kind: "success" }
decision.result = { kind: "response", contents: Buffer.from("extension reply") }
decision.result = { kind: "failure" } // extension is known, but this request failed
```

Leaving an extension result undefined reports that the extension is unsupported. The separate
`queryExtensions` hook sets `decision.extensions` to the complete supported-name list.

PIN and lock-passphrase contexts contain ephemeral buffers that are cleared as soon as the hook
returns or its connection signal aborts; copy one only when the backing token operation genuinely
requires longer ownership. A successful lock stores a salted, derived verifier instead of the
passphrase. While locked, the server refuses signing, identity/token addition, and extensions before
invoking their hooks. An unlock hook runs only after the supplied passphrase matches, and the
derived verifier is cleared after approval. The lock state changes only after every corresponding
handler completes without rejection: a failed lock chain leaves the server unlocked, and a failed
unlock chain retains the existing verifier. The `locked` getter reports the current state.

Extension results, the advertised extension list, and session bindings follow the same complete
handler-chain rule. A later contained failure suppresses an earlier extension result or list and
does not retain a proposed session binding.

The server validates private and public key relationships, UTF-8 fields, key constraints,
signature flags and algorithms, response bounds, and exact trailing data. It verifies policy
signatures against the requested public key before returning them. Malformed input and missing,
rejected, invalid, or incompletely handled policy decisions receive the protocol failure response.

RFC 9987 recommends honoring bulk identity and token removal even when restrictive policy would
normally deny other operations, so applications should normally approve those hooks after their
backing removal succeeds. The protocol server cannot delete application-owned keys by itself.

## Limits and interoperability

Both roles default to a 256 KiB agent-message limit. Configure `maxMessageLength` on either role
when a tighter bound is appropriate.

After reading a response length, the client allocates that bounded payload once and copies each
later fragment directly into it. Legal responses fragmented down to individual bytes therefore
require linear copying. Partial response bytes are owned by the client and cleared on protocol
failure or explicit destruction.

Client and server requests default to a 10-second deadline. The client deadline covers its
serialized request and reply. The server deadline separately bounds time in the global
cross-stream queue plus awaited policy, and the resulting response write. If server policy or
stream flow control times out, only that served stream is aborted and the global queue advances so
other agent connections remain usable. Late server-owned lock, unlock, and session-binding state
changes are suppressed. The AbortSignal cannot undo application side effects which already
completed, so policy should pass it through before committing slow external mutations.

A zero client timeout disables its deadline. Server deadlines must be positive. Client and server
option bags must be plain objects. Only omitted values select defaults; explicit `null` limits and
timeouts are rejected.

The fixed-frame tests cover RFC 9987 identity, token, constraint, removal, lock, and extension
layouts plus the published session-binding, destination-constraint, and security-key provider
layouts. Integration tests pass a real SSH certificate through token policy and exercise identity
management, destination constraints, session binding, signing, locking, unlocking, removal, and a
provider-constrained security-key identity against the system OpenSSH agent.
