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
US-ASCII characters permitted by RFC 4253 section 4.2.

Set the client `ident` option to a software identifier and optional comment,
without the `SSH-2.0-` prefix. A `Buffer` is accepted for byte-exact configuration, but it is still
validated as an RFC 4253 identifier. `ident` and the lower-level `protocolVersionExchange` option
are mutually exclusive.

Servers accept the same `ident` shorthand. The `greeting` server option sends informational lines
before that identifier; line endings are normalized to CRLF and the same line-length and line-count
bounds enforced by the client parser are applied before listening.

Network reads do not correspond to SSH messages. The incremental identification parser therefore
handles an identifier split across any number of TCP chunks and preserves binary packet bytes that
arrive in the same chunk as the identifier.

An SSH server may send informational lines before its identifier. `Client` emits their complete
concatenation, including line endings, once through `greeting`; it also emits each line through
`message`, and its decoded contents without the line ending through `tcpWrapperLog`. To place finite
bounds on unauthenticated input, a preamble line is limited to 8192
bytes and a preamble is limited to 1024 lines. RFC 4253 prohibits clients from sending equivalent
preamble lines, so `ServerClient` rejects them.

Malformed identification input terminates processing through the connection's normal error path.

## Binary packet framing

After identification, both sides use the binary packet format from RFC 4253 section 6. The shared
transport codec handles arbitrary TCP fragmentation and multiple packets in one read. It generates
at least four random padding bytes, enforces cipher-block alignment, maintains the 32-bit packet
sequence number, and applies the negotiated packet protection. Conventional ciphers encrypt the
complete packet and authenticate its plaintext with the negotiated MAC. Encrypt-then-MAC and AEAD
ciphers use their separately documented layouts.

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

`SSH_MSG_NEWKEYS` changes protection independently in each direction, as required by RFC 4253
section 7.3. A sender protects packets immediately after sending its unprotected `NEWKEYS`; a
receiver protects packets immediately after receiving its peer's `NEWKEYS`. Packet processing
yields between coalesced messages so the key-exchange state machine can derive and install keys
before decoding the next protected packet from the same TCP read.

Algorithm negotiation follows the client's name-list preference order independently for key
exchange, host keys, and both transport directions. Non-AEAD ciphers also negotiate each MAC
direction independently; AES-GCM supplies integrity itself and therefore reports an empty MAC name.
Every exchange clears prior selections before matching, so a rekey with no mutual algorithm fails
rather than retaining stale transport state. Compression is negotiated independently in both
directions from `none`, delayed `zlib@openssh.com`, and immediate RFC 4253 `zlib`; `none` remains the
first default preference.

The default key-exchange preference starts with the RFC 8731 `curve25519-sha256` method and its
wire-equivalent deployed alias `curve25519-sha256@libssh.org`, the RFC 5656
`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, and `ecdh-sha2-nistp521` methods, then the supported
fixed-group Diffie-Hellman methods. Curve25519 ephemeral public keys remain exact 32-byte SSH
strings, while the X25519 output is reinterpreted and encoded as an RFC 4251 `mpint` only for the
exchange hash and transport-key derivation. RFC 5656 ECDH accepts validated SEC1 curve points and
encodes the shared point's x-coordinate as the secret mpint. Invalid points, incorrect Curve25519
point lengths, and all-zero Curve25519 secrets terminate key exchange.

RFC 4419 `diffie-hellman-group-exchange-sha256` lets the server select a safe-prime group after the
client requests an acceptable size range. The client requests the RFC 8270 range of 2048 through
8192 bits and prefers 3072 bits; the server chooses the smallest known safe group at least as large
as that preference, or the largest known group within the range. Received groups, canonical mpints,
public values, and shared secrets are validated before the exchange hash is accepted. The SHA-1
variant and RFC 4419's single-size legacy request are supported only as explicit compatibility
paths; prefer SHA-256 and the bounded three-size request for configured use.

The RFC 6668 `hmac-sha2-256` and `hmac-sha2-512` integrity methods are available for both
directions. Their full 32- and 64-byte outputs authenticate the RFC 4253 sequence number followed
by the plaintext packet. The OpenSSH `hmac-sha2-256-etm@openssh.com`,
`hmac-sha2-512-etm@openssh.com`, and `hmac-sha1-etm@openssh.com` methods instead leave the
four-byte packet length unencrypted, encrypt the remaining packet body, and authenticate the
sequence number followed by that header and ciphertext. Inbound ETM verifies the tag before any
ciphertext is decrypted.

RFC 4253's `hmac-sha1-96` uses a 20-byte key and the first 12 bytes of the HMAC-SHA1 result.
`hmac-sha1-96-etm@openssh.com` applies the same truncation to the encrypt-then-MAC packet layout.
Both are excluded from the default offer and should be enabled only for legacy compatibility.

RFC 4253's optional `hmac-md5` and `hmac-md5-96` methods use a 16-byte key and produce either the
full 16-byte HMAC-MD5 result or its first 12 bytes. The deployed
`hmac-md5-etm@openssh.com` and `hmac-md5-96-etm@openssh.com` variants apply those tags to the
encrypt-then-MAC layout. All four exist only for explicitly configured interoperability with legacy
peers; new deployments should not select them.

The `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com` AEAD ciphers use the RFC 5647 AES-GCM
packet construction. The four-byte packet length is clear authenticated data; the padding length,
payload, and random padding are encrypted; and the complete 16-byte authentication tag terminates
the packet. Each direction derives a 12-byte IV consisting of a four-byte fixed field and an
eight-byte invocation counter that advances once per packet and must never wrap. No separate MAC
algorithm or integrity key is used, and inbound plaintext is not accepted until its tag verifies.

The `chacha20-poly1305@openssh.com` AEAD cipher uses two independent 256-bit ChaCha20 keys. One
encrypts the four-byte packet length so framing can proceed without exposing the payload cipher; the
other encrypts the body and derives a one-time Poly1305 key for the full encrypted packet. The
64-bit nonce is the SSH packet sequence number, the body starts at ChaCha20 block counter one, and
the full 16-byte tag is verified before the body is decrypted. A separate MAC is not negotiated.
Sequence-number reuse or wrap under one transport key is rejected and requires rekeying.

The RFC 4253 `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, and three-key `3des-cbc` ciphers are
supported as explicit compatibility choices but excluded from defaults. CBC chaining state
continues across packet boundaries; SSH packet padding supplies the required block alignment, so
the cipher applies no additional padding. Each direction starts with newly derived key and IV
material after `NEWKEYS` and always uses a separately negotiated MAC. Prefer the default AEAD and
CTR choices for new deployments; configure CBC explicitly only when interoperability with an older
peer requires it.

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

RSA host keys support the RFC 8332 `rsa-sha2-512` and `rsa-sha2-256` algorithms. The negotiated
algorithm selects the SHA-2 signature while the serialized public key remains `ssh-rsa`, preserving
the key blob and fingerprint. The legacy `ssh-rsa` SHA-1 signature remains available when selected
explicitly. Initial key exchange also advertises RFC 8308 extension negotiation; servers send
`server-sig-algs` immediately after `NEWKEYS` so clients can select an accepted user-authentication
signature without guessing.

RFC 4253 `ssh-dss` host and user keys are supported only when explicitly configured. Their public
blob contains the canonical positive `p`, `q`, `g`, and `y` mpints; private containers add `x`.
The implementation enforces the historical 1024-bit `p` and 160-bit `q`, validates primes,
subgroup membership, and the private/public relationship, and encodes signatures as the required
fixed 20-byte `r` followed by 20-byte `s`. DSS always uses SHA-1 and is excluded from defaults; use
Ed25519, ECDSA, or RSA SHA-2 for every new deployment.

RFC 8308 extension messages are position-checked. A client message is accepted only immediately
after its first `NEWKEYS`; the client sends an empty message at that point when the server offered
`ext-info-s`. A server message is accepted immediately after its first `NEWKEYS` and/or immediately
before `USERAUTH_SUCCESS`. A second server message replaces the complete first set, so capabilities
omitted from it stop being active. Messages outside these opportunities terminate the connection.

`client.serverExtensions` and `serverConnection.clientExtensions` expose deep-copied snapshots that
preserve unknown binary values. Their corresponding `serverExtensions` and `clientExtensions`
events fire whenever a valid complete set arrives. Mutating a returned value cannot change internal
negotiation state. Unknown names remain observable but have no effect unless the application
implements their specification.

Initial key exchange also offers strict key-exchange markers under both the standardized names and
the widely deployed vendor-qualified names. Strict mode is enabled only when client and server
offer a matching pair. It requires each peer's KEXINIT to be binary packet zero, rejects non-KEX
and duplicate KEX messages during the initial exchange, and resets each direction's implicit
packet sequence immediately after every NEWKEYS. These checks prevent unauthenticated transport
messages from changing sequence state that survives into the protected connection.

The server advertises version `0` of `ping@openssh.com` in its initial RFC 8308 extension message.
Transport PING and PONG use opcodes 192 and 193 and carry one opaque SSH string; the response must
copy that string exactly. Client `ping()` calls are matched in FIFO order, reject mismatched data,
and are available only after the advertisement is received. Pings and replies created during a
rekey are queued until NEWKEYS completes, while server replies otherwise require no application
event handler.

ECDSA host keys support all three curves required by RFC 5656: `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp521`. Received SEC1 points are validated before use,
their original encoding remains part of the serialized key and fingerprint, and ECDSA `r` and `s`
values use canonical positive SSH mpints. Signatures select SHA-256, SHA-384, or SHA-512 according
to the curve size.

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
copied rather than mutated, and the same configured offer is used for every rekey. Exact arrays can
select supported legacy methods. Client `{ append }` changes can add them after modern defaults;
SHA-1 key exchange and host signatures, DSS, CBC/3DES, and MD5/SHA-1 MACs are not offered unless
configured.

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

`Client` and each accepted `ServerClient` emit `handshake` after both directions have activated the
negotiated keys. The event fires for the initial exchange and every rekey, before the corresponding
`rekey` event, and reports the `{ kex, srvHostKey, cs, sc }` structure with each
direction's cipher, MAC, compression, and language.

## Key re-exchange

Clients and accepted server connections support RFC 4253 section 9 key re-exchange. Either peer may
initiate it, or an application may request it explicitly:

```ts
await client.rekey()
await serverConnection.rekey()
```

Both methods also have callback overloads and emit `rekey` after the new inbound
and outbound protection is active. A re-exchange generates a fresh ephemeral key pair,
exchange hash, IVs, encryption keys, and any separately required MAC keys. The session identifier
remains the exchange hash from the first key exchange, as required for authentication identity
continuity. Stateful compression streams also reset independently when the new protection for their
direction becomes active.

Once either side sends `SSH_MSG_KEXINIT`, outbound service and application packets are queued until
that side has sent `SSH_MSG_NEWKEYS`; transport and KEX packets remain permitted. Packets already in
flight from the peer continue to be processed. Sending `NEWKEYS` changes outbound protection
immediately, receiving it changes inbound protection immediately, and packet sequence numbers are
reset immediately after NEWKEYS when strict key exchange was negotiated. Existing channels remain
open across the exchange.

OpenSSH interoperability covers both directions: the modern client explicitly rekeys an OpenSSH
server, and an OpenSSH client with a low `RekeyLimit` initiates multiple exchanges while streaming
data through a modern server.
