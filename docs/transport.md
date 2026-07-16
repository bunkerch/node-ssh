---
title: SSH transport behavior
description: Identification, key exchange, encryption, rekeying, and transport lifecycle.
---

# SSH transport behavior

The transport implementation follows the SSH-2 transport protocol in RFC 4253. This document
describes behavior that applications can observe or configure.

## Identification exchange

Clients and servers send an identification in this form before binary SSH packets:

```text
SSH-2.0-software_version optional comments\r\n
```

`ProtocolVersionExchange` validates identifiers when they are constructed or parsed. The library
accepts SSH 2.0 and the RFC 4253 compatibility identifier `1.99`. It normally writes CRLF and also
accepts an LF-only peer identifier for compatibility with older implementations. Identifiers are
limited to 255 encoded bytes, may not contain NUL, and software versions must use the printable
US-ASCII characters permitted by RFC 4253 section 4.2. Optional comments are strict UTF-8 whether
they come from the wire, a constructor, or the `ident` shorthand; invalid JavaScript surrogate text
is rejected rather than replacement-encoded. Runtime callers must supply strings for constructor
fields and either a string or `Buffer` to `parse()` and `fromIdent()`; other values are rejected
without JavaScript string coercion.

Set the client `ident` option to a software identifier and optional comment,
without the `SSH-2.0-` prefix. A `Buffer` is accepted for byte-exact configuration, but it is still
validated as an RFC 4253 identifier. `ident` and the lower-level `protocolVersionExchange` option
are mutually exclusive.

`ProtocolVersionExchange` fields are runtime-immutable as well as readonly in TypeScript. Client
and server construction copy a supplied instance into the validated base representation before
retaining it, so later caller mutation, subclass overrides, or an observational event listener
cannot change the identification used on the wire or in the exchange hash.

Servers accept the same `ident` shorthand. The `greeting` server option sends informational lines
before that identifier; line endings are normalized to CRLF and the same line-length and line-count
bounds enforced by the client parser are applied before listening. Greeting text must be valid
UTF-8 without NUL; invalid JavaScript surrogate text is rejected during server construction.

Network reads do not correspond to SSH messages. The incremental identification parser therefore
handles an identifier split across any number of TCP chunks and preserves binary packet bytes that
arrive in the same chunk as the identifier.

An SSH server may send informational lines before its identifier. `Client` emits their complete
concatenation, including line endings, once through `greeting`; it also emits each line through
`tcpWrapperLog` without the line ending. Wire text is decoded as strict UTF-8 and NUL is rejected;
applications that display a greeting remain responsible for filtering other control characters as
recommended by RFC 4253. To place finite bounds on unauthenticated input, a preamble line is limited
to 8192
bytes and a preamble is limited to 1024 lines. RFC 4253 prohibits clients from sending equivalent
preamble lines, so `ServerClient` rejects them.

Malformed identification input terminates processing through the connection's normal error path.

## Human-readable protocol fields

RFC 4253 debug and disconnect text is decoded as strict UTF-8. Malformed byte sequences are
protocol errors rather than being replaced with the Unicode replacement character. Language tags
are empty or valid RFC 3066 ASCII tags. The same codec is used for channel-open failure text and
other protocol messages that carry these field types.

### Auxiliary transport messages and shutdown

Both peer roles expose RFC 4253 diagnostic messages through `protocolDebug`. Its immutable value
retains the peer's `alwaysDisplay`, `message`, and `languageTag` fields; applications decide how and
where to display it. `sendDebug(message, alwaysDisplay?, languageTag?)` sends the corresponding
diagnostic, while `sendIgnore(data)` sends opaque traffic that the peer must ignore. Ignore data is
copied when the call is made. Both auxiliary message types wait behind an active key exchange so
strict key-exchange peers never receive them between `KEXINIT` and `NEWKEYS`.
Inbound auxiliary traffic remains transparent to service negotiation and every authentication
round. Completion events observe the exchange as complete, so packets sent from `handshake` or
`rekey` handlers use the new outbound protection immediately rather than entering the old queue.

```ts
client.on("protocolDebug", ({ alwaysDisplay, message, languageTag }) => {
    logPeerDiagnostic({ alwaysDisplay, message, languageTag })
})

client.sendDebug("connection is entering maintenance", true, "en")
client.sendIgnore(Buffer.from("opaque padding"))
```

Disconnect reason codes are retained as their exact uint32 value. Named RFC 4253 values use the
`DisconnectReason` enum, while future assignments and the private-use range remain parseable so an
otherwise valid disconnect can always terminate the connection cleanly.
Transport and service packet constructors snapshot scalar metadata before queuing. Protocol marker
packets with no fields reject stray metadata instead of silently accepting an invalid shape.

Both `Client` and `ServerClient` emit `disconnect` with an immutable `PeerDisconnectInfo` before
their subsequent `close` event. It contains `reasonCode`, `description`, and `languageTag` exactly
as validated from the peer. `peerDisconnect` retains that snapshot after closure.

`end()` sends the ordinary `BY_APPLICATION` reason with empty description and language tag. Use
`disconnect()` when the peer should receive a more specific RFC 4253 reason or localized
description. `DisconnectError` validates the uint32 reason, UTF-8 description, and RFC 3066
language tag when it is constructed. Both client and server connections support the same API:

```ts
import { once } from "node:events"
import { DisconnectError, DisconnectReason } from "@bunkerch/modernssh"

const closed = once(client, "close")
client.disconnect(
    new DisconnectError(
        DisconnectReason.SSH_DISCONNECT_BY_APPLICATION,
        "maintenance in progress",
        "en-US",
    ),
)
await closed
```

Both roles also emit `end` when the readable side of the underlying transport reaches EOF. SSH has
no transport half-close state in which a connection can continue without receiving packets, so the
library then destroys the transport and emits `close`. This applies to injected transports even
when their Node.js stream uses `allowHalfOpen`. The later `close` event observes final channel and
pending-operation cleanup, and connection setup rejects immediately instead of waiting for its
readiness or handshake deadline. A graceful SSH shutdown normally produces `disconnect`, then
`end`, then `close`; an abruptly destroyed transport can omit `disconnect` and `end`. EventEmitter
listeners remain synchronous. Register one-shot waits before initiating shutdown so no event can
be missed:

```ts
import { once } from "node:events"

const ended = once(client, "end")
const closed = once(client, "close")
await ended
await closed
```

An inbound disconnect immediately rejects connection setup, packet waits, pending global requests,
transport pings, and channel operations with `PeerDisconnectError`. The error exposes the same
metadata through `disconnect`, `reasonCode`, and `languageTag`; its message is the peer description
or a numeric fallback when that description is empty. Local socket closure without an SSH
disconnect continues to use an ordinary contextual `Error`.

```ts
import { PeerDisconnectError } from "@bunkerch/modernssh"

client.on("disconnect", ({ reasonCode, description, languageTag }) => {
    auditPeerShutdown({ reasonCode, description, languageTag })
})

try {
    await client.connect()
} catch (error) {
    if (error instanceof PeerDisconnectError) reportPeerReason(error.disconnect)
    else throw error
}
```

Protocol names follow RFC 4250: they contain 1 through 64 printable US-ASCII characters, never a
comma, and locally defined names contain one at-sign followed by a valid domain name. This is
enforced for algorithm name-lists, services, authentication methods, extension names, channel
types, global and channel requests, and subsystem names. Name-lists reject empty entries while
preserving repeated names permitted by RFC 4251.

## Service negotiation

After initial key exchange, the client requests `ssh-userauth` and waits for the exact matching
acceptance before sending authentication data. The server accepts only that supported service. An
unknown service is rejected with `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`; a mismatched acceptance,
a message sent by the wrong peer role, application data before the request, or another service
message after negotiation is an RFC protocol error. Transport diagnostics and key-exchange traffic
remain independent of this wait as RFC 4253 requires.

## Binary packet framing

After identification, both sides use the binary packet format from RFC 4253 section 6. The shared
transport codec handles arbitrary TCP fragmentation and multiple packets in one read. It generates
at least four random padding bytes, enforces cipher-block alignment, maintains the 32-bit packet
sequence number, and applies the negotiated packet protection. Conventional ciphers encrypt the
complete packet and authenticate its plaintext with the negotiated MAC. Encrypt-then-MAC and AEAD
ciphers use their separately documented layouts.

SSH boolean fields follow the RFC wire definition: zero is false and every nonzero byte is true.
Serializing a local boolean uses the canonical zero or one representation.

Name-lists preserve their wire order, including repeated names permitted by RFC 4251. Empty entries,
commas inside names, non-ASCII bytes, and malformed names remain protocol errors.

Inbound framing is validated before the decoder waits for the claimed packet body. Packets with
invalid padding, empty payloads, incorrect block alignment, invalid MACs, or total sizes above
35,000 bytes are rejected. The 35,000-byte bound includes framing, padding, and MAC and satisfies
the mandatory receive size in RFC 4253 section 6.1; an internal codec consumer may configure a
larger bound but not a smaller one.

After key exchange, an otherwise well-formed packet with an unknown message number does not close
the transport. Both peer roles send RFC 4253 `SSH_MSG_UNIMPLEMENTED` with the exact rejected packet
sequence number and continue processing subsequent buffered packets. Malformed known packets still
fail explicitly. During negotiated strict initial key exchange, an unknown non-KEX message remains
a key-exchange violation and terminates the connection instead of receiving this recovery response.
The `unimplemented` event reports only the rejected outbound sequence number.

The connection-level `packet` event exposes immutable inbound metadata: packet type, registered
name when known, and sequence number. It never exposes decrypted payload bytes or parsed packet
objects. Authentication values, channel contents, agent traffic, environment values, and opaque
application requests therefore cannot leak through generic transport observation. Use the narrow
typed events and Hooker policies for protocol data an application is meant to consume. Parsed-packet
wait helpers are transport internals and are not part of the public connection API.

`SSH_MSG_NEWKEYS` changes protection independently in each direction, as required by RFC 4253
section 7.3. A sender protects packets immediately after sending its unprotected `NEWKEYS`; a
receiver protects packets immediately after receiving its peer's `NEWKEYS`. Packet processing
yields between coalesced messages so the key-exchange state machine can derive and install keys
before decoding the next protected packet from the same TCP read. `NEWKEYS` and method-specific
key-exchange messages are protocol errors when no exchange is active; they can never reinstall
stale protection or pause ordinary connection traffic. During an exchange, each role accepts the
peer's `NEWKEYS` only after fresh inbound keys and protection objects have been derived and the
compression selection is ready to instantiate, then consumes that readiness exactly once. A
premature or duplicate message receives a protocol-error disconnect before packet protection
changes. The negotiated method also determines the exact next inbound KEX opcode: ordinary
exchanges accept one init or reply, group exchange advances through request, group, init, and reply,
and RSA exchange advances through transient key, encrypted secret, and completion. Each stage is
single-use, so a duplicate or method-incompatible packet is rejected before its payload is parsed.
RFC 4253 optimistic guesses remain compatible with that validation: when
`first_kex_packet_follows` is true and either the peer's first KEX or host-key name differs from the
negotiated pair, exactly one following packet is silently discarded. A correct guess is processed
normally, and an incorrect guess does not consume the real method-stage expectation.

Algorithm negotiation follows the client's name-list preference order independently for key
exchange, host keys, and both transport directions. Non-AEAD ciphers also negotiate each MAC
direction independently; AES-GCM supplies integrity itself and therefore reports an empty MAC name.
The complete selection is validated before it is installed, so a failure cannot leave a partially
selected set. Compression is negotiated independently in both directions from `none`, delayed
`zlib@openssh.com`, and immediate RFC 4253 `zlib`; `none` remains the first default preference.

`SSH_MSG_KEXINIT` parsing consumes its complete fixed layout: the cookie is exactly 16 bytes, all
eight mandatory algorithm lists are non-empty, the reserved uint32 is zero, and trailing bytes are
rejected before negotiation begins. Constructed and parsed offers own their cookie and every
name-list array, so mutation of configuration arrays or a received frame cannot rewrite a queued
offer.

Each peer snapshots its exact serialized local KEXINIT at the transport write boundary. Exchange
hashes use that immutable wire payload, so later mutation of an inspected packet object cannot
change the session transcript. The active offers and exact transcript bytes remain internal. The
role-specific `clientKexInit` and `serverKexInit` observation events receive a parsed packet and a
copied wire payload; unrelated low-level KEXINIT objects cannot replace the active exchange.

Inbound KEXINIT bytes are likewise copied before the role-specific KEXINIT event is published.
Negotiation reparses the private snapshot, so observers may inspect or mutate that event's packet
object without changing the algorithm offer or exchange hash used by the connection.

Method-specific key-exchange packets also own their ephemeral public values, host-key blobs, and
signature envelopes. Constructor inputs and parsed transport frames cannot be mutated later to
change values used for shared-secret computation or exchange-hash verification.
RFC 4419 group exchange additionally copies the host key and peer public value retained across its
multi-message state machine before constructing the final exchange hash.
DH and ECDH public-key getters and shared-secret return values are defensive copies. Mutating a
returned buffer cannot alter the internal values later used for hashing or transport-key derivation.

The two optional language preference name-lists use RFC 3066 syntax rather than algorithm-name
rules. Their order and repeated tags are preserved; malformed tags are rejected in both directions.

The default key-exchange preference starts with the three registered ML-KEM hybrids from the
[IETF SSHM specification](https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/):
`mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, and
`mlkem1024nistp384-sha384`. Each uses a fresh FIPS 203 ML-KEM key pair and encapsulation together
with fresh X25519 or NIST ECDH keys. The client sends the ML-KEM public key followed by its
classical public key; the server sends the ML-KEM ciphertext followed by its classical public key.
The implementation emits uncompressed NIST points and accepts both compressed and uncompressed
SEC1 points as required by the method definitions.

The established secret is `HASH(K_PQ || K_CL)`, with both inputs kept at their fixed 32- or 48-byte
length. That hash output is encoded as an SSH string in the exchange hash and transport-key
derivation. Exact role-specific lengths are checked before ML-KEM processing, non-canonical
ML-KEM encapsulation keys are rejected, NIST points are validated, and an all-zero X25519 result
terminates key exchange. FIPS 203 implicit rejection supplies a pseudorandom secret for a modified
same-length ciphertext, which makes the server host-key signature fail instead of exposing a
decapsulation oracle. Ephemeral ML-KEM, ECDH, and X25519 secret material is erased after use.

The IANA-registered standalone methods `mlkem512-sha256`, `mlkem768-sha256`, and
`mlkem1024-sha384` are also available through explicit algorithm configuration. They implement the
current [pure ML-KEM SSH specification](https://datatracker.ietf.org/doc/draft-harrison-sshm-mlkem/):
the client sends a fresh FIPS 203 encapsulation key and the server returns only the matching
ciphertext. The 32-byte ML-KEM secret is encoded directly as an SSH string in the exchange hash and
as an RFC 4251 `mpint` for transport-key derivation. Public keys and ciphertexts must have the exact
size for their parameter set, non-canonical encapsulation keys fail key exchange, and modified
same-length ciphertexts use FIPS 203 implicit rejection.

These methods are not in the default offer. Unlike the hybrid defaults, they have no classical
ECDH component, and IANA marks them `MAY` rather than `SHOULD`. Opt in only when both peers
deliberately require a pure post-quantum exchange, for example:

```ts
const client = new Client({
    algorithms: { kex: ["mlkem768-sha256"] },
})
```

RFC 9941 `sntrup761x25519-sha512` and its wire-equivalent
`sntrup761x25519-sha512@openssh.com` alias follow the ML-KEM methods. This hybrid combines a
Streamlined NTRU Prime sntrup761 KEM secret with an X25519 secret through SHA-512. The client sends
a 1158-byte KEM public key followed by its 32-byte X25519 public key; the server replies with a
1039-byte KEM ciphertext followed by its 32-byte X25519 public key. Incorrect role-specific lengths
and an all-zero X25519 output terminate key exchange. The resulting 64-byte secret is encoded as an
SSH string for both the exchange hash and transport-key derivation, avoiding secret-dependent mpint
lengths. Decapsulation uses the KEM's implicit-rejection secret when a ciphertext is invalid.

RFC 8731 `curve25519-sha256`, its wire-equivalent deployed alias
`curve25519-sha256@libssh.org`, and `curve448-sha512` follow the hybrid methods, then the RFC 5656
`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, and `ecdh-sha2-nistp521` methods and supported
fixed-group Diffie-Hellman methods. Curve25519 and Curve448 ephemeral public keys remain exact 32-
and 56-byte SSH strings. Their X25519 or X448 output is reinterpreted as a big-endian integer and
encoded as an RFC 4251 `mpint` only for the exchange hash and transport-key derivation; Curve448
uses SHA-512. Both methods accept the non-canonical field encodings required by RFC 7748, while
incorrect point lengths and all-zero secrets terminate key exchange. RFC 5656 ECDH accepts
validated SEC1 curve points and encodes the shared point's x-coordinate as the secret mpint.

RFC 4419 `diffie-hellman-group-exchange-sha256` lets the server select a safe-prime group after the
client requests an acceptable size range. The client requests the RFC 8270 range of 2048 through
8192 bits and prefers 3072 bits; the server chooses the smallest known safe group at least as large
as that preference, or the largest known group within the range. Received groups, canonical mpints,
public values, and shared secrets are validated before the exchange hash is accepted. The SHA-1
variant and RFC 4419's single-size legacy request are supported only as explicit compatibility
paths; prefer SHA-256 and the bounded three-size request for configured use.

RFC 8268 fixed-group key exchange is available as `diffie-hellman-group14-sha256` and the
SHA-512-backed `diffie-hellman-group15-sha512` through `diffie-hellman-group18-sha512` methods.
They use the exact RFC 3526 safe-prime groups at 2048, 3072, 4096, 6144, and 8192 bits. Both peers
reject non-canonical or non-positive public-value mpints and enforce RFC 8268's corrected open
interval `1 < e,f < p-1`; shared secrets at either endpoint are rejected as well. Group 16 is the
preferred fixed finite-field method under RFC 9142, while groups 15, 17, and 18 remain available
after it for peers with different policy.

RFC 8732 GSS-API key exchange is enabled when a configured mechanism adapter supplies
`createKeyExchangeContext`. The library derives each method's suffix from the complete DER-encoded
mechanism OID and offers the Curve25519, Curve448, NIST P-256/P-384/P-521, and fixed groups 14
through 18 families with their specified SHA-2 hash. Context establishment may use any number of
tokens. It must finish with mutual authentication and integrity, after which the server's GSS-API
MIC authenticates the exchange hash before either peer installs keys. Mechanism contexts perform
only token and MIC operations; the transport owns packet ordering, shared-secret calculation,
exchange-hash construction, and cleanup.

The server normally sends its host key during GSS-API key exchange. RFC 4462's `null` host-key
algorithm may instead be configured explicitly for deployments whose GSS mechanism authenticates
the server without an SSH host key. `null` must be the server's only configured host-key algorithm;
it is never mixed into a normal host-key offer, and at least one configured key-exchange method must
come from a GSS-API mechanism adapter. In that mode there is no host-key value for
`hostVerifier` to approve, so applications must treat the configured GSS mechanism and its target
name as the server-authentication trust boundary.

The RFC 6668 `hmac-sha2-256` and `hmac-sha2-512` integrity methods are available for both
directions. Their full 32- and 64-byte outputs authenticate the RFC 4253 sequence number followed
by the plaintext packet. Transport setup validates every negotiated MAC key against the exact size
declared by its SSH method before constructing packet protection. The OpenSSH
`hmac-sha2-256-etm@openssh.com`,
`hmac-sha2-512-etm@openssh.com`, and `hmac-sha1-etm@openssh.com` methods instead leave the
four-byte packet length unencrypted, encrypt the remaining packet body, and authenticate the
sequence number followed by that header and ciphertext. Inbound ETM verifies the tag before any
ciphertext is decrypted.

The historical
[`draft-dbider-sha2-mac-for-ssh-05`](https://datatracker.ietf.org/doc/draft-dbider-sha2-mac-for-ssh/05/)
also defined `hmac-sha2-256-96` and `hmac-sha2-512-96`, using the same 32- and 64-byte keys but only
the first 12 output bytes. The final RFC 6668 and the IANA SSH registry omit these names. They are
available only through explicit algorithm configuration for compatibility and are never offered by
default; prefer the full-length RFC names.

RFC 4418 UMAC is available as `umac-64@openssh.com`, `umac-128@openssh.com`, and their
encrypt-then-MAC variants. SSH encodes the uint32 packet sequence as a big-endian uint64 nonce and
authenticates the packet itself rather than prepending the sequence number. The 128- and 64-bit ETM
variants are in the default offer; ordinary variants remain explicit compatibility choices. A UMAC
instance rejects a repeated or decreasing sequence number, requiring fresh keys before nonce wrap.

RFC 4253's `hmac-sha1-96` uses a 20-byte key and the first 12 bytes of the HMAC-SHA1 result.
`hmac-sha1-96-etm@openssh.com` applies the same truncation to the encrypt-then-MAC packet layout.
Both are excluded from the default offer and should be enabled only for legacy compatibility.

RFC 4253's optional `hmac-md5` and `hmac-md5-96` methods use a 16-byte key and produce either the
full 16-byte HMAC-MD5 result or its first 12 bytes. The deployed
`hmac-md5-etm@openssh.com` and `hmac-md5-96-etm@openssh.com` variants apply those tags to the
encrypt-then-MAC layout. All four exist only for explicitly configured interoperability with legacy
peers; new deployments should not select them.

The legacy `hmac-ripemd160` compatibility method uses a 20-byte key and the complete 20-byte
HMAC-RIPEMD160 result over the RFC 4253 sequence number and plaintext packet. It is available only
through explicit algorithm configuration and remains outside the default offer. Prefer a default
SHA-2 or UMAC method unless a peer specifically requires RIPEMD-160.

RFC 5647 AES-GCM is available under its registered `AEAD_AES_128_GCM` and
`AEAD_AES_256_GCM` names. The RFC requires the selected name to appear in both the encryption and
MAC lists for each direction. Configure both lists when opting in:

```ts
const client = new Client({
    hostname: "ssh.example.com",
    algorithms: {
        cipher: ["AEAD_AES_256_GCM"],
        hmac: ["AEAD_AES_256_GCM"],
    },
})
```

Negotiation rejects the combination unless ordinary SSH preference rules select the identical name
from both lists in that direction. Applications should therefore keep each registered AES-GCM name
in the same relative position in their cipher and MAC configurations. The registered methods are
explicit opt-ins because deployed peers rarely advertise them. The `aes128-gcm@openssh.com` and
`aes256-gcm@openssh.com` variants use the same packet construction but retain their deployed
implicit-MAC negotiation behavior.

For all four names, the four-byte packet length is clear authenticated data; the padding length,
payload, and random padding are encrypted; and the complete 16-byte authentication tag terminates
the packet. Each direction derives a 12-byte IV consisting of a four-byte fixed field and an
eight-byte invocation counter that advances once per packet and must never wrap. No integrity key
is used, and inbound plaintext is not accepted until its tag verifies.

The standardized `chacha20-poly1305` cipher and its wire-identical
`chacha20-poly1305@openssh.com` predecessor use two independent 256-bit ChaCha20 keys. The default
offer places the standardized name first and retains the deployed name for interoperability. One
key encrypts the four-byte packet length so framing can proceed without exposing the payload cipher;
the other encrypts the body and derives a one-time Poly1305 key for the full encrypted packet. The
64-bit nonce is the SSH packet sequence number, the body starts at ChaCha20 block counter one, and
the full 16-byte tag is verified before the body is decrypted. A separate MAC is not negotiated.
Sequence-number reuse or wrap under one transport key is rejected and requires rekeying. Both names
use strict key exchange whenever the peer advertises the matching standard or deployed marker.

RFC 4344 `aes128-ctr`, `aes192-ctr`, and `aes256-ctr` use AES with 128-, 192-, and 256-bit keys and
a 128-bit initial counter. Each direction keeps one continuous counter stream across packet
boundaries until `NEWKEYS` installs fresh key and IV material. All three are available in the
default offer. Transport construction validates the exact key and IV sizes and does not retain or
expose the caller-owned buffers.

The RFC 4253 `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `blowfish-cbc`, `cast128-cbc`, and
three-key `3des-cbc` ciphers are supported as explicit compatibility choices but excluded from
defaults. `blowfish-cbc` and `cast128-cbc` use the RFC-required 128-bit keys and have 64-bit block
sizes. CBC chaining state continues across packet boundaries; SSH packet padding supplies the
required block alignment, so the cipher applies no additional padding. Each direction starts with
newly derived key and IV material after `NEWKEYS` and always uses a separately negotiated MAC.

Prefer the default AEAD and CTR choices for new deployments. The 64-bit block sizes of Blowfish and
CAST-128 are too small for modern high-volume use. Configure any CBC cipher explicitly only when
interoperability with an older peer requires it, and retain the default automatic rekey limits.

## Compression

RFC 4253 `zlib` compresses only the packet payload before padding, encryption, and authentication.
Each direction owns a persistent RFC 1950 stream, performs the required partial flush at every
packet boundary, and resets its stream when that direction activates new keys. Decompression uses a
synchronous flush so each binary packet yields exactly one complete SSH payload; malformed streams
and payloads that expand beyond the receive bound are rejected.

`zlib@openssh.com` uses the same wire format but delays both directions until user authentication
succeeds. The success packet itself remains uncompressed. On a later authenticated rekey, new
delayed-compression streams start immediately after the corresponding `NEWKEYS`, just like ordinary
`zlib`. This avoids compressing attacker-controlled pre-authentication exchanges while retaining
compression for authenticated channel traffic.

RFC 8308 `delay-compression` is a separate standardized negotiation mechanism. It is disabled by
default. Enable it on both peers with `delayCompression: true`; this advertises `zlib,none`
independently in both directions while allowing the initial key exchange to select `none`:

```ts
const server = new Server({
    hostKeys,
    algorithms: { compress: ["none"] },
    delayCompression: true,
})

const client = new Client({
    hostname,
    username,
    algorithms: { compress: ["none"] },
    delayCompression: true,
})
```

Direction-specific policy accepts explicit lists containing `"zlib"` and `"none"`:

```ts
const delayCompression = {
    clientToServer: ["zlib", "none"],
    serverToClient: ["none"],
} as const
```

The extension takes effect only when both peers advertise it. Each direction follows the client's
preference order; bilateral offers without a mutual algorithm in either direction receive a
key-exchange-failure disconnect. `zlib@openssh.com` is rejected inside these lists because it
defines its own delayed activation semantics.

The server activates its selected output stream immediately after sending
`SSH_MSG_USERAUTH_SUCCESS`. The client activates matching input before decoding the next packet,
sends the uncompressed `SSH_MSG_NEWCOMPRESS` trigger, and then activates its selected output
stream. The server accepts up to 32 intervening client messages before requiring that trigger.
Unexpected, duplicate, or server-originated `NEWCOMPRESS` messages are protocol errors. Activation
always creates a fresh compression stream, including when the selected algorithm was already
active. A subsequent rekey replaces both extension selections with its newly negotiated algorithms.

A server may delay its offer until account policy is known. Include the exported builder in the
single authentication-time replacement extension set:

```ts
import { delayCompressionExtension } from "@bunkerch/modernssh"

server.hooker.hook("passwordAuthentication", async (_hook, context, decision, connection) => {
    const account = await accounts.verifyPassword(context.username, context.password)
    if (account.accepted && connection.clientSupportsAuthenticationExtensionInfo) {
        connection.sendAuthenticationExtensions([
            delayCompressionExtension({
                clientToServer: account.uploadCompression,
                serverToClient: account.downloadCompression,
            }),
        ])
    }
    decision.allowLogin = account.accepted
})
```

A role that advertised support cannot initiate rekey until authentication resolves the extension
and it has sent its own compression trigger. `rekey()` rejects during that interval instead of
creating the ambiguous ordering prohibited by RFC 8308.

RSA host keys support the RFC 8332 `rsa-sha2-512` and `rsa-sha2-256` algorithms. The negotiated
algorithm selects the SHA-2 signature while the serialized public key remains `ssh-rsa`, preserving
the key blob and fingerprint. The legacy `ssh-rsa` SHA-1 signature remains available when selected
explicitly. Initial key exchange also advertises RFC 8308 extension negotiation; servers send
`server-sig-algs` immediately after `NEWKEYS` so clients can select an accepted user-authentication
signature without guessing.

RSA key import requires canonical positive SSH mpints and validates the public exponent and odd
modulus. Private import additionally applies native probable-prime tests, checks both factors against
the modulus, and verifies the CRT inverse and private exponent congruence before copying every
retained component. Later mutation of input buffers cannot change the serialized identity or signing
key.

`EncodedSignature` uses the same strict RFC 4250 algorithm-name codec on construction, parsing, and
serialization. It rejects trailing fields, copies caller-owned signature bytes, and revalidates its
intentionally mutable algorithm metadata before writing a wire envelope.

RFC 8709 public keys have fixed widths: `ssh-ed25519` contains exactly 32 key octets and `ssh-ed448`
contains exactly 57. Their signatures contain 64 and 114 octets respectively. Parsing rejects
trailing fields and incorrect lengths, while verification rejects incorrect signature names or
sizes before curve verification. Ed448 is registered for host-key and authentication use and can
be selected explicitly, but is not part of the default offer.

The standard certificate key types from the SSH certificate draft are available through explicit
algorithm configuration, including `ssh-ed448-cert` and the RSA SHA-2 certificate negotiation
names. Their older deployed counterparts remain the interoperable defaults. Standard Ed448
certificates use the underlying 57-byte key and 114-byte signature rules and are covered by a
CA-signed client/server handshake.

Ed25519 and Ed448 private containers hold the RFC 8032 seed followed by their public key. Import
verifies both the repeated public bytes and the public key derived from the seed, then takes private
copies of the key material. A malformed container therefore cannot publish one identity while
signing with unrelated or subsequently mutated bytes.

ECDSA private import likewise derives the RFC 5656 public point from its scalar and compares the
normalized point before accepting it. Public points and private scalars are copied at construction,
so later caller mutation cannot make serialization, signing, and verification observe different
keys.

RFC 4253 `ssh-dss` host and user keys are supported only when explicitly configured. Their public
blob contains the canonical positive `p`, `q`, `g`, and `y` mpints; private containers add `x`.
The implementation enforces the historical 1024-bit `p` and 160-bit `q`, validates primes,
subgroup membership, and the private/public relationship, and encodes signatures as the required
fixed 20-byte `r` followed by 20-byte `s`. DSS always uses SHA-1 and is excluded from defaults; use
Ed25519, ECDSA, or RSA SHA-2 for every new deployment. DSS signing derives its nonce
deterministically according to RFC 6979 instead of depending on fresh random input for every
signature.

RFC 8308 extension messages are position-checked. A client message is accepted only immediately
after its first `NEWKEYS`. When the server offered `ext-info-s`, the client sends that message with
the `ext-info-in-auth@openssh.com` capability. A server message is accepted immediately after its
first `NEWKEYS`; a server with host keys includes exact `hostkeys=0` support for standardized
post-authentication key updates. Without the negotiated authentication capability, the only later
RFC 8308 opportunity is immediately before `USERAUTH_SUCCESS`.

The advertised authentication capability lets a server send one replacement extension set after
receiving the first `USERAUTH_REQUEST` and before authentication completes. This is useful when
extension values depend on the requested account, and the update may precede either an
authentication failure or success. Send it from an awaited authentication hook:

```ts
server.hooker.hook("passwordAuthentication", async (_hook, context, decision, connection) => {
    const account = await accounts.verifyPassword(context.username, context.password)

    if (connection.clientSupportsAuthenticationExtensionInfo) {
        connection.sendAuthenticationExtensions([
            {
                name: "account-policy@example.com",
                value: Buffer.from(account.policy, "utf8"),
            },
        ])
    }
    decision.allowLogin = account.accepted
})
```

`sendAuthenticationExtensions()` throws if the client did not advertise support, no authentication
request is active, authentication already completed, or an update was already sent. Every valid
later message replaces the complete first set, so capabilities omitted from it stop being active.
In particular, a replacement `server-sig-algs` value supersedes the initial value. Messages outside
these opportunities terminate the connection. A replacement set that omits `hostkeys=0` also
clears standard host-key-update negotiation, so a later compatibility advertisement uses its
compatibility proof domain.

`client.serverExtensions` and `serverConnection.clientExtensions` expose deep-copied snapshots that
preserve unknown binary values. Their corresponding `serverExtensions` and `clientExtensions`
events fire whenever a valid complete set arrives. Mutating a returned value cannot change internal
negotiation state. Unknown names remain observable but have no effect unless the application
implements their specification.

### Operating-system elevation

RFC 8308 elevation negotiation is opt-in on the client. Set `elevation` to `"elevated"`,
`"unelevated"`, or `"default"`; these serialize as the exact registered values `y`, `n`, and `d`.
The default `false` does not advertise the extension.

The server exposes elevation as an awaited policy hook after authentication has been approved but
before `USERAUTH_SUCCESS` is sent. This is the point where an application can switch the operating
system security context without allowing sessions to race ahead of that change:

```ts
server.hooker.hook("elevation", async (_hook, context, decision) => {
    decision.elevated = await accounts.applyElevation(context.username, context.preference)
})
```

`context.preference` is `"elevated"`, `"unelevated"`, or `"default"`. RFC 8308 requires a client
that omitted the extension to be treated as `"default"`, so the hook still runs in that case. The
server reports `decision.elevated` only to a client that advertised the extension; leaving it
undefined means no result is available. Every elevation handler must complete without rejection
before a result is retained. If a later handler fails after an earlier handler assigned a result,
authentication still succeeds but the server suppresses the unproven elevation result.

Register the client's synchronous observation handler before connecting. A supporting server sends
the result as a one-way global request immediately after authentication:

```ts
const client = new Client({
    hostname,
    username,
    elevation: "unelevated",
})

client.on("elevation", (elevated) => {
    auditElevationResult(elevated)
})

await client.connect()
```

`client.elevated` retains the reported boolean and remains `undefined` if no result arrived. The
server-side connection exposes the explicitly advertised preference through
`clientElevationPreference`; it remains `undefined` when the client omitted the extension. A
recognized result with a reply request, missing or trailing bytes, or a duplicate result is a
protocol error.

### No channel flow control

RFC 8308 `no-flow-control` can be enabled independently on the client and server with
`noFlowControl: "supported"` or `noFlowControl: "preferred"`. Both peers must advertise the
extension, and at least one must prefer it, before it takes effect:

```ts
const server = new Server({
    hostKeys,
    noFlowControl: "supported",
})

const client = new Client({
    hostname,
    username,
    noFlowControl: "preferred",
})
```

`client.noFlowControl` and `serverConnection.noFlowControl` report the negotiated state. The wire
values are exactly `p` for preferred and `s` for supported; any other value from a participating
peer is a protocol error. A later server extension set replaces the first one, so omitting
`no-flow-control` disables it before authentication completes.

When active, channel-open window fields and window-adjust messages are ignored in both directions.
Packet-size limits, channel close ordering, and SSH packet bounds still apply. The connection
refuses a second simultaneous channel, including while another channel open is pending, but another
channel may be opened after both sides completely close the first. This mode is therefore suitable
only for deliberately single-channel applications; leave it disabled for multiplexed sessions and
forwarding workloads.

Initial key exchange also offers strict key-exchange markers under both the standardized names and
the widely deployed vendor-qualified names. Strict mode is enabled only when client and server
offer a matching pair. It requires each peer's KEXINIT to be binary packet zero, rejects non-KEX
and duplicate KEX messages during the initial exchange, rejects a 32-bit sequence counter that
wrapped before the exchange completed, and resets each direction's implicit packet sequence
immediately after every NEWKEYS. These checks prevent unauthenticated transport messages from
changing sequence state that survives into the protected connection.

The server advertises version `0` of `agent-forward` in its initial RFC 8308 extension message.
Clients use the standardized RFC 9987 `agent-req` and `agent-connect` names only after receiving
that exact value; a replacement extension message that omits it disables the capability. Without
the advertisement, the public agent-forwarding API uses the pre-standardization compatibility
names only for an identified supporting vendor.

The server also advertises version `0` of `ping@openssh.com` in its initial extension message.
Transport PING and PONG use opcodes 192 and 193 and carry one opaque SSH string; the response must
copy that string exactly. Client `ping()` calls are matched in FIFO order, reject mismatched data,
and are available only after the advertisement is received. Pings and replies created during a
rekey are queued until NEWKEYS completes, while server replies otherwise require no application
event handler. Client pings and rekeys use the connection's `replyTimeout`; expiry closes the
transport because subsequent ordered traffic cannot safely overtake the missing reply.

ECDSA host keys support all three curves required by RFC 5656: `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp521`. Received SEC1 points are validated before use,
their original encoding remains part of the serialized key and fingerprint, and ECDSA `r` and `s`
values use canonical positive SSH mpints. Signatures select SHA-256, SHA-384, or SHA-512 according
to the curve size. Signing uses RFC 6979 deterministic nonces, so the same key, message, and
algorithm produce the same standard ECDSA signature.

### Certificate host keys

Pair issued host certificates with their matching private keys through `hostCertificates`. The
server retains the plain host key too, so peers that do not offer certificate algorithms can still
negotiate it:

```ts
const server = new Server({
    hostKeys: [PrivateKey.fromString(await readFile("./ssh_host_ed25519_key", "utf8"))],
    hostCertificates: [await readFile("./ssh_host_ed25519_key-cert.pub")],
})
```

Modern certificate algorithms are preferred when a matching certificate is configured. During
key exchange, the client verifies the possession signature using the certified key and validates
the CA signature, host role, and validity interval before host policy runs. The awaited `hostKey`
hook receives the certificate as its `PublicKey`; inspect its `SSHCertificatePublicKey` algorithm
to trust the CA and match the connection hostname or address against `data.principals`. Host
certificates define no critical options, so a hook should reject any that appear. Exact certificate
pinning through `hostVerifier` remains supported because it receives the complete serialized
certificate blob.

Both `ClientOptions` and `ServerOptions` accept an `algorithms` object with `kex`, `serverHostKey`,
`cipher`, `hmac`, and `compress` categories. Server values are exact ordered arrays. Client values
may be exact arrays or `{ remove, prepend, append }` changes whose entries are names or regular
expressions. Unknown names and empty resolved lists are rejected during construction, defaults are
copied rather than mutated, and the same configured offer is used for every rekey. Modifier values
must be non-empty strings or regular expressions; malformed objects are rejected rather than
silently ignored. `algorithmOffer` exposes the resulting frozen name lists for inspection; the
factory registry behind those names remains internal so runtime map mutation cannot bypass
construction-time validation. Exact arrays can select supported legacy methods. Client `{ append }`
changes can add them after modern defaults.
The RFC 9142 legacy methods `diffie-hellman-group14-sha1`,
`diffie-hellman-group1-sha1`, and `diffie-hellman-group-exchange-sha1` remain available for explicit
interoperability but are never offered by default. SHA-1 host signatures, DSS, CBC/3DES, and
MD5/SHA-1 MACs likewise require explicit configuration.
The group1 implementation embeds its published RFC prime instead of depending on a
runtime-specific alias for the 1024-bit group. Both fixed groups validate peer values in the open
interval `(1, p-1)`. Fixed exchange-hash vectors, encrypted traffic across rekey, and explicitly
enabled OpenSSH negotiation in both peer roles cover both SHA-1 methods.

```ts
const client = new Client({
    hostname,
    algorithms: {
        kex: ["curve25519-sha256"],
        cipher: { remove: [/^aes(?:192|256)-ctr$/] },
        hmac: ["hmac-sha2-256"],
    },
})
```

RFC 4432 `rsa2048-sha256` key exchange is available through explicit algorithm configuration. The
server creates a fresh 2048-bit transient RSA key for every exchange, the client encrypts a random
shared-secret mpint with RSAES-OAEP using SHA-256, and both sides include the host key, transient
key, ciphertext, and secret in the exchange hash. Decryption failures terminate key exchange. This
method is `MAY` in RFC 9142 and does not provide forward secrecy, so it is excluded from defaults:

```ts
const client = new Client({
    hostname,
    algorithms: { kex: ["rsa2048-sha256"] },
})
```

`Client` and each accepted `ServerClient` emit `handshake` after both directions have activated the
negotiated keys. The event fires for the initial exchange and every rekey, before the corresponding
`rekey` event, and reports the `{ kex, srvHostKey, cs, sc }` structure with each
direction's cipher, MAC, compression, and language.

After an exchange, `keyExchangeAlgorithm` contains the negotiated key-exchange name and
`exchangeHash` contains a defensive copy of that exchange's transcript hash. The latter changes on
each rekey; `sessionID` remains the first exchange hash. `negotiatedAlgorithms` returns a deeply
frozen `{ kex, srvHostKey, cs, sc }` value containing the currently active algorithm names. It
reflects direction-specific delayed-compression activation without exposing cipher constructors or
mutable negotiation descriptors.

Derived IVs, encryption keys, integrity keys, shared secrets, and live cipher, MAC, and key-exchange
objects are internal transport state and are not exposed through either connection role. Raw
KEXINIT transcripts and method-specific key-exchange packets are likewise internal; use the
`handshake` event for exchange-completion observations. Completed and failed exchanges explicitly
zero retained shared-secret and software private-scalar buffers, release native ephemeral key
objects, erase temporary RSA key-exchange plaintexts and secret encodings, and discard derived key
buffers after constructing packet protection. Directional `NEWKEYS` replacement deterministically
disposes the superseded packet protection. Connection failure and close dispose both active and
not-yet-activated protection, erase JavaScript-managed cipher keys, MAC keys, expanded subkeys, and
IV state, and make those algorithm objects unusable. Native cipher contexts are finalized before
their JavaScript wrappers are released.

## Key re-exchange

Clients and accepted server connections support RFC 4253 section 9 key re-exchange. Either peer may
initiate it, or an application may request it explicitly:

```ts
await client.rekey()
await serverConnection.rekey()
```

Both roles also rekey automatically using RFC 4253's recommended limits. By default, either one
gigabyte of authenticated wire data in either direction or one hour under the current keys starts
a new exchange, whichever occurs first. Configure the client directly and accepted server
connections through their parent server:

```ts
const client = new Client({
    hostname: "ssh.example.com",
    rekeyBytes: 512 * 1024 * 1024,
    rekeyInterval: 30 * 60 * 1000,
})

const server = new Server({
    rekeyBytes: 512 * 1024 * 1024,
    rekeyInterval: 30 * 60 * 1000,
})
```

Each limit can be set to `0` independently to disable it. The byte limit counts complete protected
packets, including framing, padding, and authentication data, and resets separately when each
direction installs replacement keys. The time limit is measured from completion of the exchange.
Automatic and explicit exchanges share the same state machine, queueing, events, and failure
handling; a peer-initiated exchange suppresses a simultaneously due local automatic exchange.
Detached handling of a peer-initiated exchange remains bound to that transport generation. If the
same `Client` reconnects while an old host-key decision is pending, the old exchange cannot report
its eventual failure by closing the replacement transport.

RFC 4253 permits either peer to initiate rekeying as soon as the initial key exchange has
completed, including during service negotiation or user authentication. `rekey()` follows that
rule and resolves after the replacement keys are active; a concurrent exchange is rejected rather
than starting a second state machine.

Packets already in flight before the peer's `KEXINIT` remain processable as RFC 4253 requires.
After that `KEXINIT` arrives, service, authentication, connection, and vendor transport messages
are rejected until the peer's `NEWKEYS`; generic diagnostics and key-exchange packets remain valid.

Both methods emit `rekey` after the new inbound and outbound protection is active. A re-exchange
generates a fresh ephemeral key pair,
exchange hash, IVs, encryption keys, and any separately required MAC keys. The session identifier
remains the exchange hash from the first key exchange, as required for authentication identity
continuity. Stateful compression streams also reset independently when the new protection for their
direction becomes active.

Reading `sessionID` or `exchangeHash` returns a defensive copy. Mutating application-visible bytes
cannot change the identifier reused by public-key signatures, host-key proofs, or later transport
key derivation, nor the retained transcript hash.

Once either side sends `SSH_MSG_KEXINIT`, outbound service and application packets are queued until
that side has sent `SSH_MSG_NEWKEYS`; transport and KEX packets remain permitted. Packets already in
flight from the peer continue to be processed. Sending `NEWKEYS` changes outbound protection
immediately, receiving it changes inbound protection immediately, and packet sequence numbers are
reset immediately after NEWKEYS when strict key exchange was negotiated. Existing channels remain
open across the exchange.

Channel data stays in its channel write queue during this interval, so `sendData()`, server shell
writes, and Node stream write callbacks retain backpressure until outbound `NEWKEYS` installs the new
keys. Previously queued control packets are written first, preserving call order. Other application
packets retained by the transport are serialized when queued so later object mutation cannot alter
their wire bytes, and the queue is bounded to 1,024 packets and 4 MiB. A synchronous one-way API such
as `sendIgnore()` or `sendDebug()` throws if concurrent use fills that bound; Promise operations
reject through their normal call path. Disconnect and failed key exchange discard the queue and
settle channel work through the ordinary transport-close lifecycle.

OpenSSH interoperability covers both directions: the modern client explicitly rekeys an OpenSSH
server, and an OpenSSH client with a low `RekeyLimit` initiates multiple exchanges while streaming
data through a modern server.
