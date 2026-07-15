# Known hosts

`KnownHosts` reads and updates the host-key database format used by OpenSSH. Use its verifier with
the client to reject unknown, changed, revoked, expired, or incorrectly scoped server identities
before authentication begins.

```ts
import { homedir } from "node:os"
import { join } from "node:path"
import { Client, KnownHosts } from "@bunkerch/modernssh"

const hostname = "ssh.example.com"
const port = 22
const knownHosts = await KnownHosts.load(join(homedir(), ".ssh", "known_hosts"))
const client = new Client({
    hostname,
    port,
    username: "deploy",
    hostVerifier: knownHosts.verifier(hostname, port),
})

await client.connect()
```

Do not set `hostHash` when using this verifier. `KnownHosts` needs the raw serialized key to compare
the complete SSH identity, determine its algorithm, and validate host certificates.

For revocation policy that applies across hosts and users, combine this database with a binary
`KeyRevocationList` as shown in [key revocation lists](key-revocation-lists.md).

## Matching and failures

The parser supports comma-separated hostname patterns, `*` and `?` wildcards, negated patterns,
non-default `[hostname]:port` entries, HMAC-SHA1 `|1|...` hashed hostnames, and the
`@cert-authority` and `@revoked` markers. Hostname matching is case-insensitive. Hashed entries are
compared in constant time after computing their HMAC.

Wildcard matching follows the deployed byte-oriented rules: `?` consumes one UTF-8 byte, `*`
consumes any number of bytes, and case folding applies only to ASCII. Matching uses bounded NFA
state instead of dynamically constructed regular expressions. Files are limited to 16 MiB, lines
to 64 KiB, and individual unhashed patterns to 1023 bytes; oversized policy is rejected during
parsing.

The verifier throws `KnownHostsError` on failure. Its `status` is one of:

- `unknown`: no entry applies to the requested host.
- `changed`: an entry applies, but none trusts the presented key or certificate authority.
- `revoked`: a matching `@revoked` entry contains the presented key or its certificate authority.

`check()` provides the same result without throwing:

```ts
const result = knownHosts.check(hostname, serializedHostKey, port)
if (result.status !== "trusted") {
    console.error(result.status, result.line)
}
```

Malformed files fail closed during `parse()` or `load()`. Unknown but syntactically valid key
algorithms are preserved, so a file can be shared with tools that support a broader algorithm set.

## Host certificates

An `@cert-authority` entry trusts only host-role certificates signed by that exact authority. The
certificate signature, validity interval, hostname principals, and critical options are checked.
An empty principal list means all hostnames, as it does for an unrestricted OpenSSH certificate.
No standard critical options exist for host certificates, so a certificate containing any is
rejected. A matching revocation of either the certificate itself or its authority takes precedence
over every trust entry.

These certificate checks also run in the client before a custom `hostVerifier` or `hostKey` hook,
so custom policy cannot accidentally accept a certificate for another hostname.

When several `hostKey` hooks are registered, trust is granted only if every handler completes
without rejection and the final decision allows the key. Hooker still reports a contained async
failure through `uncaughtException`, but an allow decision made by an earlier handler is discarded.

## Updating a file

`replaceHostKeys()` replaces literal or hashed entries for one host and leaves comments, wildcard
policy, revocations, certificate authorities, and other hostnames intact. It accepts `PublicKey`
objects or their encoded text forms.

```ts
await knownHosts.replaceHostKeys(hostname, replacementKeys, {
    port,
    hashHostname: true,
})
```

Each key receives an independently salted hashed hostname. Writes use a new file in the same
directory, flush its contents, preserve the existing file mode, and atomically rename it over the
target. Calls on the same `KnownHosts` instance are serialized, and each update rereads a
file-backed database first so unrelated changes made since `load()` are retained.

Updating known hosts after the `hostKeys` rotation event is safe only when the current connection
was authenticated from an already trusted entry. The rotation proof establishes that the current
server owns the advertised keys; it does not establish the identity of an initially unknown host.
The client verifies every proof against the initial transport session identifier before emitting
the event. Standard version-0 negotiation and the deployed compatibility flow use distinct signed
domains, so proofs cannot be substituted between them. A failed, malformed, repeated, or
RSA-SHA1-based proof flow emits no replacement keys.
