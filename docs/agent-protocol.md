# SSH agent protocol

`SSHAgentProtocolClient` and `SSHAgentProtocolServer` implement the connection-oriented agent
protocol from RFC 9987 over an already-connected Node.js `Duplex`. The same classes work with a
local agent socket and with an authorized forwarded-agent channel.

## Client

All client operations return promises. Agent messages do not carry request identifiers, so one
client serializes requests and requires each reply before sending the next request. The default
reply deadline is 10 seconds. A timeout destroys the stream because a late, untagged reply could
otherwise be mistaken for the reply to a later request.

```ts
import { createConnection } from "node:net"
import { once } from "node:events"
import { SSHAgentProtocolClient } from "modernssh"

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
    agent.destroy()
}
```

The management methods are:

- `addIdentity(privateKey, options?)` adds a DSA, ECDSA, Ed25519, Ed448, RSA, or registered custom
  private-key type. `options.comment` overrides the key comment.
- `addToken(tokenId, pin?, options?)` asks the agent to load keys from a hardware token. The add
  request treats the token identifier and PIN as opaque SSH strings.
- `removeIdentity(publicKey)`, `removeAllIdentities()`, and `removeToken(tokenId, pin?)` remove
  loaded identities. RFC 9987 requires the remove-token identifier and PIN to be valid UTF-8.
- `lock(passphrase)` and `unlock(passphrase)` change the agent lock state.
- `extension(type, contents?)` sends a named extension request and returns either
  `{ kind: "success" }` or `{ kind: "response", contents }`.
- `queryExtensions()` uses the standard `query` extension and returns its advertised extension
  names.

An extension-specific failure rejects with `SSHAgentExtensionFailureError`. A normal
`SSHAgentProtocolError` means the extension was unsupported, the request was refused, the reply
was malformed, the stream failed, or the deadline expired.

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
last constraint. Unknown constraints fail closed on the server.

Private-key, PIN, and passphrase request frames are copied for transport and cleared after they
have been written and answered. This does not clear buffers retained by the caller.

## Server

`SSHAgentProtocolServer` exposes application-owned identities through awaited `Hooker` policy.
Every security-sensitive decision is denied unless its hook explicitly supplies a valid result.

```ts
import { SSHAgentProtocolServer } from "modernssh"

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
`removeAllIdentities`, `removeToken`, `lock`, `unlock`, `extension`, and `queryExtensions`. Hooks
run in wire order. Requests across multiple streams served by one server are also globally ordered
so a successful lock cannot race a later sensitive operation on another stream.

Set `success = true` for add, remove, lock, and unlock hooks. For a generic extension, set one of:

```ts
decision.result = { kind: "success" }
decision.result = { kind: "response", contents: Buffer.from("extension reply") }
decision.result = { kind: "failure" } // extension is known, but this request failed
```

Leaving an extension result undefined reports that the extension is unsupported. The separate
`queryExtensions` hook sets `decision.extensions` to the complete supported-name list.

PIN and lock-passphrase contexts contain ephemeral buffers that are cleared as soon as the hook
returns; copy one only when the backing token operation genuinely requires longer ownership. A
successful lock stores a salted, derived verifier instead of the passphrase. While locked, the
server refuses signing, identity/token addition, and extensions before invoking their hooks. An
unlock hook runs only after the supplied passphrase matches, and the derived verifier is cleared
after approval. The `locked` getter reports the current state.

The server validates private and public key relationships, UTF-8 fields, key constraints,
signature flags and algorithms, response bounds, and exact trailing data. It verifies policy
signatures against the requested public key before returning them. Malformed input and missing,
rejected, or invalid policy decisions receive the protocol failure response.

RFC 9987 recommends honoring bulk identity and token removal even when restrictive policy would
normally deny other operations, so applications should normally approve those hooks after their
backing removal succeeds. The protocol server cannot delete application-owned keys by itself.

## Limits and interoperability

Both roles default to a 256 KiB agent-message limit. Configure `maxMessageLength` on either role
when a tighter bound is appropriate, and configure `requestTimeout` on the client. A zero client
timeout disables the deadline.

The fixed-frame tests cover RFC 9987 identity, token, constraint, removal, lock, and extension
layouts. Integration tests also add an identity to the system OpenSSH agent, list it, sign with it,
lock and unlock the agent, and remove the identity again.
