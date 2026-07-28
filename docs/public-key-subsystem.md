---
title: Public-key management subsystem
description: Manage namespaced authorized keys and certificates over RFC 4819 and RFC 7076.
---

# Public-key management subsystem

RFC 4819 defines the `publickey` SSH subsystem for managing an authenticated user's authorized
keys. RFC 7076 extends it with namespaces and certificates. This is separate from public-key
authentication and agent forwarding: it changes server-side authorization data after the SSH
connection has authenticated.

Support must be enabled by the server. A client API does not imply that a particular SSH daemon
provides this subsystem.

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

console.log(await publicKeys.listAttributes())
console.log(await publicKeys.listNamespaces())

await publicKeys.add(key, {
    namespace: "users",
    overwrite: false,
    attributes: [{ name: "comment", value: "alice's workstation" }],
})

for (const entry of await publicKeys.list({ namespace: "users" })) {
    console.log(entry.key.toString(), entry.attributes)
}

await publicKeys.remove(key, { namespace: "users" })
publicKeys.end()
```

`add()`, `remove()`, and `list()` use the optional `namespace` and `attributes` request options.
The client copies keys, certificates, and attributes before queueing them. String values are strict
UTF-8; use a `Buffer` for an opaque extension value. `overwrite` defaults to `false`.
When version 3 is negotiated and no namespace is supplied, RFC 7076 defines `"ssh"` as the default;
listed key entries expose that effective namespace through `entry.namespace`.

RFC 7076 certificate blobs are intentionally opaque. The format name identifies how the
application should parse and validate the bytes:

```ts
const certificate = await readFile("./alice-certificate.bin")

await publicKeys.addCertificate("x509v3-ssh-rsa", certificate, {
    namespace: "users",
    overwrite: false,
})

for (const entry of await publicKeys.listCertificates()) {
    console.log(entry.format, entry.namespace, entry.certificate)
}

await publicKeys.removeCertificate("x509v3-ssh-rsa", certificate, {
    namespace: "users",
})
```

Certificate operations and `listNamespaces()` require negotiated version 3. The client reports a
clear error after a version-2 downgrade instead of sending an unsupported request. Namespace is
required for certificate add/remove, must be valid UTF-8, and is limited to 300 Unicode
characters.

Every unsuccessful status rejects with `PublicKeySubsystemStatusError`. Its `code` can be compared
with `PublicKeySubsystemStatusCode`; `message` and `languageTag` preserve the server response:

```ts
import { PublicKeySubsystemStatusCode, PublicKeySubsystemStatusError } from "@bunkerch/modernssh"

try {
    await publicKeys.remove(key, { namespace: "users" })
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

Unknown and private status values are preserved as unsigned 32-bit codes. The RFC 7076-specific
codes are `CertificateNotFound` (192), `CertificateNotSupported` (193),
`CertificateAlreadyPresent` (194), `ActionNotAuthorized` (195), and
`CannotCreateNamespace` (196).

Only one request may be unacknowledged, so concurrent calls are queued in call order. `end()`
gracefully ends the subsystem channel. `destroy(error?)` aborts it. Pending and queued operations
reject on a timeout, channel close, SSH disconnect, or transport failure.

`requestTimeout` bounds negotiation and every serialized request. It defaults to the connection's
`replyTimeout`, or 30 seconds when using `PublicKeySubsystemClient.connect()` directly. A timeout
closes only the subsystem channel so an untagged late response cannot satisfy a later operation.

## Server

The library does not choose a database, edit `authorized_keys`, parse certificate formats, or infer
authorization rules. The application must scope storage and policy to the authenticated user and
namespace, validate certificate contents, and make each mutation durable before approving it.

Access remains denied until ordinary session-channel and subsystem Hooker policies approve it.
The `publicKey` event is observational and its listener remains synchronous; policy and storage
work belongs in awaited Hooker handlers:

```ts
import { PublicKeySubsystemStatusCode, SessionChannel } from "@bunkerch/modernssh"

server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen = channel instanceof SessionChannel
})

server.on("connection", (connection) => {
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
                await storeAuthorizedKey(connection.username, context.namespace, context)
                controller.success = true
            })

            publicKeys.hooker.hook("remove", async (_hook, context, controller) => {
                const removed = await removeAuthorizedKey(
                    connection.username,
                    context.namespace,
                    context.key,
                )
                controller.success = removed
                controller.failureCode = PublicKeySubsystemStatusCode.KeyNotFound
            })

            publicKeys.hooker.hook("list", async (_hook, controller, context) => {
                controller.keys = await listAuthorizedKeys(connection.username, context.namespace)
                controller.success = true
            })

            publicKeys.hooker.hook("addCertificate", async (_hook, context, controller) => {
                await validateAndStoreCertificate(connection.username, context)
                controller.success = true
            })

            publicKeys.hooker.hook("removeCertificate", async (_hook, context, controller) => {
                controller.success = await removeCertificate(connection.username, context)
                controller.failureCode = PublicKeySubsystemStatusCode.CertificateNotFound
            })

            publicKeys.hooker.hook("listCertificates", async (_hook, controller) => {
                controller.certificates = await listCertificates(connection.username)
                controller.success = true
            })

            publicKeys.hooker.hook("listNamespaces", async (_hook, controller) => {
                controller.namespaces = await listNamespaces(connection.username)
                controller.success = true
            })
        })
    })
})
```

If a mutation Hooker has no handler, the server returns `ActionNotAuthorized` for version 3 and an
appropriate version-2 failure for a downgraded peer. Missing list handlers report the request as
unsupported. Hook rejections are contained by `Hooker` and become `GeneralFailure`, never an
unhandled EventEmitter rejection.

The server automatically advertises the standard `namespace` capability. Additional advertised
attributes are configured through `decision.publicKey.attributes`. A critical attribute absent
from that list is rejected before application policy runs. Advertising an attribute means the
application understands and enforces its meaning; retaining unknown bytes is not sufficient.

The standard `comment` value is strict UTF-8. `comment-language` must immediately follow its
comment and contain a valid language tag. Other attributes may restrict commands, shells,
subsystems, X11, agents, environment requests, source hosts, and forwarding. Those restrictions
remain application policy. A compulsory capability promises that administration applies it to
every key, and an overwrite must not remove administrator-owned restrictions.

## Negotiation, limits, and interoperability

Both sides advertise version 3 and negotiate the lower version. Version 2 retains the exact RFC
4819 key request layouts; version 3 uses RFC 7076 layouts and enables namespaces and certificates.
A peer below version 2 receives `VersionNotSupported` before the channel closes. Unknown requests
receive `RequestNotSupported`; duplicate versions, contradictory layouts, and pipelined requests
are fatal protocol errors.

Frames are bounded to 256 KiB before allocation. List operations collect at most 1024 packets and
4 MiB of encoded responses. Key blobs must parse and match their outer algorithm name. Malformed
framing, invalid text, repeated namespace attributes, unexpected responses, and replies without a
pending request close the subsystem and reject pending work. EOF in a partial frame is also fatal.

Transport rekeying preserves an active subsystem. The root package exports the packet codec for
applications that already have an authenticated SSH subsystem stream, though the high-level client
and server APIs are normally preferable.

Literal byte vectors independently cover all version-2 and version-3 packet layouts. The encrypted
integration suite covers awaited policy, namespaced keys, certificates, namespace listing,
downgrade behavior, bounds, failures, and rekey. A pinned independent Python peer exercises both
roles at version 3, including fragmented version exchange, coalesced multi-packet responses, key
and certificate state transitions, and namespace listing.
