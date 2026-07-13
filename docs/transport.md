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

Network reads do not correspond to SSH messages. The incremental identification parser therefore
handles an identifier split across any number of TCP chunks and preserves binary packet bytes that
arrive in the same chunk as the identifier.

An SSH server may send informational lines before its identifier. `Client` emits each such complete
line through `message`, and emits its decoded contents without the line ending through
`tcpWrapperLog`. To place finite bounds on unauthenticated input, a preamble line is limited to 8192
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
