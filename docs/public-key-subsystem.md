# Public-key management subsystem

RFC 4819 defines the `publickey` SSH subsystem for managing the authenticated user's authorized
public keys. It is separate from public-key authentication and from SSH agent forwarding: the
subsystem changes server-side authorization data after the SSH connection has already
authenticated.

Support must be enabled by the server. A standards-compliant client API does not imply that a
particular SSH daemon provides this subsystem.

## Client

Open the subsystem after connecting, then use its Promise-only operations:

```ts
import { readFile } from "node:fs/promises"
import { Client, PublicKey } from "@bunkerch/modernssh"

const client = new Client({ hostname: "keys.example.com", username: "alice" })
// Configure host-key verification and authentication before connecting.
await client.connect()

const publicKeys = await client.publicKeySubsystem({ requestTimeout: 30_000 })
const key = PublicKey.parseString(await readFile("./id_ed25519.pub", "utf8"))

const capabilities = await publicKeys.listAttributes()
console.log(capabilities)

await publicKeys.add(key, {
    overwrite: false,
    attributes: [{ name: "comment", value: "alice's workstation" }],
})

for (const entry of await publicKeys.list()) {
    console.log(entry.key.toString(), entry.attributes)
}

await publicKeys.remove(key)
publicKeys.end()
```

`add()` copies key attributes before it queues the request. String values are encoded as strict
UTF-8; pass a `Buffer` for an opaque extension attribute. `overwrite: false` is the default. A
server should report `KeyAlreadyPresent` when that key already exists and overwrite was not
requested. The add option bag and each attribute must be plain objects; `attributes` must be an
array, and explicit `null` is rejected for the overwrite and critical boolean flags.

Every unsuccessful status rejects with `PublicKeySubsystemStatusError`. Its `code` can be compared
with `PublicKeySubsystemStatusCode`, while `message` and `languageTag` preserve the server's status
text:

```ts
import { PublicKeySubsystemStatusCode, PublicKeySubsystemStatusError } from "@bunkerch/modernssh"

try {
    await publicKeys.remove(key)
} catch (error) {
    if (
        error instanceof PublicKeySubsystemStatusError &&
        error.code === PublicKeySubsystemStatusCode.KeyNotFound
    ) {
        console.log("The key was already absent")
    } else {
        throw error
    }
}
```

RFC 4819 permits only one unacknowledged client request. Concurrent API calls are therefore queued
and retain call order. `end()` gracefully ends the subsystem channel. `destroy(error?)` aborts it;
pending and queued operations reject when the channel or SSH connection closes.
`requestTimeout` bounds version negotiation and each serialized request reply. It defaults to the
connection's `replyTimeout`; direct `PublicKeySubsystemClient.connect()` calls default to 30
seconds. Expiry rejects the operation and closes only the subsystem channel, preventing a late
untagged reply from being mistaken for a later operation while leaving the SSH connection usable.
The value must be a positive finite number.
The client option bag must be a plain object. Only an omitted `requestTimeout` selects the
connection-level or 30-second direct-call default; explicit `null` is rejected before a subsystem
channel is allocated or version negotiation begins.

## Server

Access is denied until the ordinary session-channel and subsystem Hooker policies approve it. The
library does not select a database, mutate `authorized_keys`, or infer authorization rules. The
application must scope storage to the connection's authenticated user and make each change durable
before setting `controller.success`.

The `publicKey` EventEmitter notification is observational and its listener stays synchronous. It
installs awaited Hooker handlers for operations that may perform asynchronous storage or policy
work:

```ts
import { PublicKeySubsystemStatusCode, SessionChannel } from "@bunkerch/modernssh"

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen = channel instanceof SessionChannel
})

server.on("connection", (connection) => {
    const keys = new Map()

    connection.on("channel", (channel) => {
        if (!(channel instanceof SessionChannel)) return

        channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
            if (context.subsystem !== "publickey") return
            decision.success = true
            decision.publicKey = {
                attributes: [{ name: "comment", compulsory: false }],
            }
        })

        channel.events.on("publicKey", (publicKeys) => {
            publicKeys.hooker.hook("add", async (_hook, context, controller) => {
                const id = context.key.hash("sha256")
                if (keys.has(id) && !context.overwrite) {
                    controller.failureCode = PublicKeySubsystemStatusCode.KeyAlreadyPresent
                    controller.description = "Key already present"
                    return
                }

                await storeAuthorizedKey(connection, context)
                keys.set(id, context)
                controller.success = true
            })

            publicKeys.hooker.hook("remove", async (_hook, context, controller) => {
                const id = context.key.hash("sha256")
                if (!keys.has(id)) {
                    controller.failureCode = PublicKeySubsystemStatusCode.KeyNotFound
                    controller.description = "Key not found"
                    return
                }

                await removeAuthorizedKey(connection, context.key)
                keys.delete(id)
                controller.success = true
            })

            publicKeys.hooker.hook("list", async (_hook, controller) => {
                controller.keys = await listAuthorizedKeys(connection)
                controller.success = true
            })
        })
    })
})
```

The example's map only illustrates overwrite decisions; production storage must be associated with
the authenticated account and survive connection closure. If no `add` or `remove` hook is present,
the server denies that operation. If no `list` hook is present, listing is reported as unsupported.
An async hook rejection is contained by `Hooker` and becomes a general-failure status instead of an
unhandled EventEmitter rejection.

The server option bag and every advertised capability must be plain objects, `attributes` must be
an array, and `compulsory` must be a boolean when present. Configuration is validated before the
server installs stream listeners or begins version exchange, and explicit `null` never selects a
default.

## Attributes and authorization

`decision.publicKey.attributes` is the capability list returned by `listAttributes()`. A critical
attribute that is absent from that list is rejected before application policy runs. Advertising an
attribute means the application understands and implements its intent; merely retaining its bytes
is not enough for a critical attribute.

The standard `comment` value is strict UTF-8. `comment-language` must immediately follow its
corresponding comment and contain a valid language tag. Other standard attributes can restrict
commands, shells, subsystems, X11, agents, environment requests, source hosts, and forwarding.
Those restrictions are application policy: this subsystem does not automatically connect stored
attributes to later authentication or channel authorization.

Marking a capability `compulsory: true` promises that server administration applies that attribute
to every added key whether or not the client supplied it. The application must actually add and
enforce that restriction. A user-controlled overwrite must never remove compulsory or
administrator-owned restrictions.

## Protocol behavior and limits

Both sides exchange RFC 4819 version 2 before requests begin. A lower unsupported version receives
`VersionNotSupported` before the channel closes. Unknown requests receive `RequestNotSupported`
without closing the subsystem. Duplicate version packets and pipelined requests are fatal protocol
errors.

Frames are bounded to 256 KiB before allocation. `list()` and `listAttributes()` collect at most
1024 response packets and 4 MiB of encoded response data. Key blobs are parsed and their embedded
algorithm must match the outer algorithm name. Malformed framing, invalid text, contradictory key
metadata, unexpected response types, and responses without a pending request close the subsystem
and reject pending work.

EOF in the middle of a frame is also fatal. Both client and server close the public-key subsystem
channel, reject pending client operations, and leave the authenticated SSH connection available for
other channels.

Transport rekeying preserves an active public-key subsystem. Packet codecs are also exported for
applications that need RFC 4819 framing over another already-authenticated SSH session stream, but
the high-level client and server APIs should normally be preferred.
