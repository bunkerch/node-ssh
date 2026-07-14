# Key revocation lists

`KeyRevocationList` loads the binary KRL format produced by `ssh-keygen`. It can reject plain
public keys, certificates, a certificate's embedded key, or every certificate signed by a revoked
authority.

```ts
import { KeyRevocationList, PublicKey } from "@bunkerch/modernssh"

const revocations = await KeyRevocationList.load("/etc/ssh/revoked_keys")
const key = PublicKey.parse(serializedKey)

if (revocations.isRevoked(key)) {
    throw new Error("SSH key is revoked")
}
```

`isRevoked()` accepts either a `PublicKey` or its complete SSH wire serialization. Parsing and
checks are synchronous after `load()` resolves, so the same instance can be used from client host
verification and awaited server authentication hooks.

## Host verification

A KRL answers only whether a key is revoked; it does not establish which key belongs to a host.
Combine it with `KnownHosts` so both policies must pass:

```ts
import { Client, KeyRevocationList, KnownHosts } from "@bunkerch/modernssh"

const hostname = "ssh.example.com"
const knownHosts = await KnownHosts.load("/etc/ssh/ssh_known_hosts")
const revocations = await KeyRevocationList.load("/etc/ssh/revoked_keys")
const verifyKnownHost = knownHosts.verifier(hostname)

const client = new Client({
    hostname,
    hostVerifier(serializedKey) {
        if (!Buffer.isBuffer(serializedKey)) {
            throw new TypeError("Raw host-key verification is required")
        }
        if (revocations.isRevoked(serializedKey)) throw new Error("SSH host key is revoked")
        return verifyKnownHost(serializedKey)
    },
})

await client.connect()
```

Load both files before constructing the client. An `async` EventEmitter listener is not a safe
place to perform host trust decisions because EventEmitter does not await returned promises.

## Supported records

The parser supports explicit keys, SHA-1 and SHA-256 fingerprints, certificate serial lists,
serial ranges, compact serial bitmaps, certificate key identifiers, authority-specific and
all-authority certificate sections, optional extensions, and consecutive signature sections at
the end of a KRL. Certificate checks also cover the plain embedded key and signing authority,
matching `ssh-keygen -Q` behavior.

Unknown critical extensions, unknown sections, nonzero format flags, serial zero, wrapped serial
bitmaps, malformed keys, invalid lengths, non-canonical integers, NUL text, and trailing data fail
during parsing. Optional unknown extensions are ignored. Input is copied before it is retained,
and files larger than 16 MiB are rejected.

Every embedded KRL signature is verified over its exact required prefix while parsing. Invalid
signatures, a non-signature section after the first signature, or a malformed signing key fail the
complete KRL. Cryptographic validity does not establish trust: an attacker can create a different
KRL and sign it with their own key. When loading from an untrusted location, require an exact
trusted signer explicitly:

```ts
import { KeyRevocationList, PublicKey } from "@bunkerch/modernssh"

const revocations = await KeyRevocationList.load(downloadedPath)
const trustedSigner = PublicKey.parseString(configuredSigningKey)

if (!revocations.isSignedBy(trustedSigner)) {
    throw new Error("KRL is not signed by the configured authority")
}
```

`isSignedBy()` returns true only for a key whose embedded signature was already verified. Requiring
it also detects an attacker who strips every signature. The published format notes that current
OpenSSH versions refuse signature sections and recommends separately authenticated SSHSIG files,
so signed KRLs may not be consumable by system tools. Unsigned KRLs distributed through an already
authenticated and integrity-protected channel remain supported.

## Rollback policy

The header metadata is available as `version`, `generatedAt`, and `comment`. `version` and
`generatedAt` are `bigint` Unix values, preserving the complete unsigned 64-bit fields.

The format does not itself prevent an attacker from replacing a KRL with an older valid file.
Applications that update revocation policy should persist the highest accepted `version` and
reject a lower value before replacing the active instance. The library does not invent a rollback
policy because storage and deployment authority belong to the application.
