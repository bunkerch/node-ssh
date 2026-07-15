# Detached SSH signatures

`SSHSignature` signs, parses, serializes, and verifies the detached armored signature format used
by `ssh-keygen -Y`. The format reuses SSH public keys and signature encodings without requiring an
SSH connection.

## Sign and verify

Every signature belongs to a non-empty namespace. The namespace is part of the signed preimage and
prevents a signature created for one application protocol from being accepted by another. Choose a
stable application-specific value rather than a value derived from untrusted input.

```ts
import { readFile, writeFile } from "node:fs/promises"
import { PrivateKey, SSHSignature } from "@bunkerch/modernssh"

const message = await readFile("release.tar.gz")
const privateKey = PrivateKey.fromString(await readFile("release_signer", "utf8"))
const signature = SSHSignature.sign(message, privateKey, {
    namespace: "com.example.release",
})

await writeFile("release.tar.gz.sig", signature.toString())
```

Parsing accepts either armored text or the raw binary blob returned by `serialize()`. Verification
requires the expected namespace instead of trusting the namespace stored inside an untrusted
signature.

```ts
const signature = SSHSignature.parse(await readFile("release.tar.gz.sig"))
const message = await readFile("release.tar.gz")

if (!signature.verify(message, "com.example.release")) {
    throw new Error("Invalid release signature")
}
```

`verify()` proves only that the embedded public key signed the message for that namespace. It does
not decide whether that key is trusted. Compare `signature.publicKey` with a configured key or use
`AllowedSigners` to apply principal, certificate-authority, namespace, time, and optional revocation
policy before accepting the result.

## Allowed signers

`AllowedSigners` parses the same policy-file shape used by `ssh-keygen -Y verify`. Load the policy
once and supply the expected identity and namespace for each verification:

```ts
import { AllowedSigners, KeyRevocationList, SSHSignature } from "@bunkerch/modernssh"

const allowed = await AllowedSigners.load("allowed_signers")
const revocations = await KeyRevocationList.load("revoked_signers.krl")
const signature = SSHSignature.parse(await readFile("release.tar.gz.sig"))

if (
    !allowed.verify(await readFile("release.tar.gz"), signature, {
        principal: "release@example.com",
        namespace: "com.example.release",
        revocations,
    })
) {
    throw new Error("Untrusted release signature")
}
```

Principal and namespace fields use case-sensitive `*` and `?` patterns, with `!` negation taking
precedence over a positive match. Wildcards operate on UTF-8 bytes, so `?` matches one encoded byte
rather than one Unicode code point. Supported options are `cert-authority`, `namespaces`,
`valid-after`, and `valid-before`; keywords are case-insensitive and option values are quoted.
Quoted namespace lists may contain spaces. Timestamps use `YYYYMMDD[Z]` or
`YYYYMMDDHHMM[SS][Z]`. A `UTC` suffix is also accepted. Values without a suffix use the process's
local time zone, matching the command-line format.

For a `cert-authority` entry, the signature must embed a valid user certificate signed by that
entry's key. Its certificate signature, validity interval, and exact requested principal are
checked in addition to the allowed-signers patterns. An exact certificate entry without
`cert-authority` is treated as an exact key, matching command-line behavior. Allowed-signers
`valid-before` is inclusive, while a certificate's own `validBefore` instant is exclusive.

## Agent-backed signing

Use `signWithAgent()` when private material belongs to a local, forwarded, hardware-backed, or
application-defined `Agent`. The method resolves the selected public key, requests the signature,
and cryptographically checks the agent response before returning it. The message is copied before
the first awaited agent operation.

```ts
const [[id]] = await agent.getPublicKeys()
const signature = await SSHSignature.signWithAgent(message, agent, id, {
    namespace: "com.example.release",
    hashAlgorithm: "sha512",
})
```

Both `sha256` and `sha512` message hashing are supported; `sha512` is the default. RSA signing uses
the corresponding RSA-SHA2 signature and rejects legacy RSA-SHA1 signatures. The complete signed
preimage, including its namespace and message digest, is sent to an agent—not the original message.

## Encoding and limits

`toString()` emits the standard header and footer with 70-character base64 lines, matching
`ssh-keygen`. `serialize()` returns the unarmored versioned blob. Parsed namespace and reserved
buffers are exposed through defensive copies. Unsupported future versions, unsupported hashes,
RSA-SHA1, non-canonical base64, trailing fields, NUL namespaces, binary blobs above 1 MiB, and
armored input above 2 MiB are rejected.

Allowed-signers files are strict UTF-8 and bounded to 16 MiB with 64 KiB lines. Unknown or duplicate
options, malformed patterns, invalid keys, impossible timestamps, reversed validity windows, NUL,
and malformed quoting reject the complete file instead of silently weakening policy.

The parser preserves non-empty reserved bytes for forward-compatible inspection and serialization,
but version 1 signing always emits the required empty reserved field. Namespace values may be
strings or opaque buffers; string inputs are encoded as UTF-8.

## Command-line interoperability

A signature written by the library can be verified using an allowed-signers file:

```sh
ssh-keygen -Y verify \
    -f allowed_signers \
    -I signer@example.com \
    -n com.example.release \
    -s release.tar.gz.sig < release.tar.gz
```

Signatures produced by `ssh-keygen -Y sign` can be parsed and verified through the same
`SSHSignature` interface. Interoperability tests exercise both directions with Ed25519 and RSA
keys.
