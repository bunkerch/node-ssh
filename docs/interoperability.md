# Interoperability testing

The test suite uses `ssh2` 1.17 as an independent protocol implementation. It establishes real TCP
connections in both directions:

- A `modernssh` client connects to an `ssh2` server, verifies its host key through the client hook,
  negotiates transport protection, and completes `none` authentication.
- An `ssh2` client connects to a `modernssh` server, verifies the server host key, negotiates
  transport protection, and completes `none` authentication.

After authentication, both directions open multiple RFC 4254 session channels. The coverage
includes exec, interactive shell, named subsystem, PTY allocation and terminal modes, environment
variables, resize notifications, signals, stdin, multi-window stdout, stderr, exit status, EOF, and
CLOSE acknowledgement.

The deterministic baseline currently forces algorithms implemented by both libraries:

| Purpose                | Algorithm                       |
| ---------------------- | ------------------------------- |
| Key exchange           | `diffie-hellman-group14-sha256` |
| Server host key        | `ssh-ed25519`                   |
| Encryption             | `aes128-ctr`                    |
| Message authentication | `hmac-sha2-256`                 |
| Compression            | `none`                          |

These tests exercise identification exchange, KEXINIT negotiation, exchange-hash and signature
verification, `NEWKEYS`, encrypted and authenticated packet framing, service negotiation,
authentication, session request ordering, channel flow control, and graceful disconnect behavior
across independent implementations.

The test also covers peers that coalesce key-exchange and protected packets into the same TCP read.
Packet decoding pauses explicitly while key material is derived and resumes after the inbound
cipher and MAC are installed; correctness does not depend on socket chunk boundaries or event-loop
timing.

Additional algorithm and feature combinations will be added as their RFC implementations land.
Passing this baseline demonstrates interoperability for the listed combination, not support for
every algorithm offered by `ssh2`.
