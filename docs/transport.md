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
sequence number, encrypts the complete packet, and authenticates the plaintext packet with the
negotiated MAC.

Inbound framing is validated before the decoder waits for the claimed packet body. Packets with
invalid padding, empty payloads, incorrect block alignment, invalid MACs, or total sizes above
35,000 bytes are rejected. The 35,000-byte bound includes framing, padding, and MAC and satisfies
the mandatory receive size in RFC 4253 section 6.1; an internal codec consumer may configure a
larger bound but not a smaller one.

`SSH_MSG_NEWKEYS` changes protection independently in each direction, as required by RFC 4253
section 7.3. A sender protects packets immediately after sending its unprotected `NEWKEYS`; a
receiver protects packets immediately after receiving its peer's `NEWKEYS`. Packet processing
yields between coalesced messages so the key-exchange state machine can derive and install keys
before decoding the next protected packet from the same TCP read.

Algorithm negotiation follows the client's name-list preference order independently for key
exchange, host keys, both cipher directions, and both MAC directions. Every exchange clears prior
selections before matching, so a rekey with no mutual algorithm fails rather than retaining stale
transport state. The currently supported compression method is `none`, and both directions must
negotiate it explicitly.

The default key-exchange preference starts with the RFC 8731 `curve25519-sha256` method and its
wire-equivalent deployed alias `curve25519-sha256@libssh.org`, the RFC 5656
`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, and `ecdh-sha2-nistp521` methods, then the supported
fixed-group Diffie-Hellman methods. Curve25519 ephemeral public keys remain exact 32-byte SSH
strings, while the X25519 output is reinterpreted and encoded as an RFC 4251 `mpint` only for the
exchange hash and transport-key derivation. RFC 5656 ECDH accepts validated SEC1 curve points and
encodes the shared point's x-coordinate as the secret mpint. Invalid points, incorrect Curve25519
point lengths, and all-zero Curve25519 secrets terminate key exchange.

The RFC 6668 `hmac-sha2-256` and `hmac-sha2-512` integrity methods are available for both
directions. Their full 32- and 64-byte outputs authenticate the RFC 4253 sequence number followed
by the plaintext packet. The OpenSSH `hmac-sha2-256-etm@openssh.com`,
`hmac-sha2-512-etm@openssh.com`, and `hmac-sha1-etm@openssh.com` methods instead leave the
four-byte packet length unencrypted, encrypt the remaining packet body, and authenticate the
sequence number followed by that header and ciphertext. Inbound ETM verifies the tag before any
ciphertext is decrypted.

RSA host keys support the RFC 8332 `rsa-sha2-512` and `rsa-sha2-256` algorithms. The negotiated
algorithm selects the SHA-2 signature while the serialized public key remains `ssh-rsa`, preserving
the key blob and fingerprint. The legacy `ssh-rsa` SHA-1 signature remains available when selected
explicitly. Initial key exchange also advertises RFC 8308 extension negotiation; servers send
`server-sig-algs` immediately after `NEWKEYS` so clients can select an accepted user-authentication
signature without guessing.

ECDSA host keys support all three curves required by RFC 5656: `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp521`. Received SEC1 points are validated before use,
their original encoding remains part of the serialized key and fingerprint, and ECDSA `r` and `s`
values use canonical positive SSH mpints. Signatures select SHA-256, SHA-384, or SHA-512 according
to the curve size.

Both `ClientOptions` and `ServerOptions` accept an `algorithms` object with `kex`, `serverHostKey`,
`cipher`, `hmac`, and `compress` categories. Server values are exact ordered arrays. Client values
may be exact arrays or `{ remove, prepend, append }` changes whose entries are names or regular
expressions. Unknown names and empty resolved lists are rejected during construction, defaults are
copied rather than mutated, and the same configured offer is used for every rekey.

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
exchange hash, IVs, encryption keys, and MAC keys. The session identifier remains the exchange hash
from the first key exchange, as required for authentication identity continuity.

Once either side sends `SSH_MSG_KEXINIT`, outbound service and application packets are queued until
that side has sent `SSH_MSG_NEWKEYS`; transport and KEX packets remain permitted. Packets already in
flight from the peer continue to be processed. Sending `NEWKEYS` changes outbound protection
immediately, receiving it changes inbound protection immediately, and packet sequence numbers are
not reset. Existing channels remain open across the exchange.

OpenSSH interoperability covers both directions: the modern client explicitly rekeys an OpenSSH
server, and an OpenSSH client with a low `RekeyLimit` initiates multiple exchanges while streaming
data through a modern server.
