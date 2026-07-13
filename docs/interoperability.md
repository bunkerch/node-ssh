# OpenSSH interoperability testing

The end-to-end interoperability suite uses OpenSSH rather than another JavaScript SSH library. It
establishes real TCP connections in both directions:

- The system `/usr/bin/ssh` client connects to a `modernssh` server, verifies transport and user
  authentication behavior, opens a session, transfers stdin/stdout/stderr, receives an exit status,
  and completes EOF/CLOSE handling.
- A `modernssh` client connects to an OpenSSH server built from the digest-pinned Debian fixture in
  `__tests__/openssh/Dockerfile`, authenticates with a password, executes a command, separates
  stdout/stderr, receives its exit status, and disconnects gracefully.

The OpenSSH server test requires Docker. The image is tagged locally as
`modernssh-openssh-test:bookworm`; Docker reuses its build cache after the first run. The pinned base
image makes the operating-system fixture reproducible, while installing the distribution's
`openssh-server` package exercises the normal packaged daemon configuration.

## Deterministic protocol vectors

Wire codecs are tested independently of OpenSSH with fixed byte strings derived from the RFC
formats. The channel vector suite covers `direct-tcpip`, PTY and terminal modes, environment,
window changes, signals, subsystems, window adjustment, standard data, stderr extended data, EOF,
and CLOSE. Every vector is parsed into asserted fields and serialized back to the exact original
bytes.

Transport tests likewise use deterministic identification, binary framing, encryption-boundary,
MAC, fragmentation, and maximum-size vectors. This keeps exact packet parsing failures local and
diagnosable instead of relying on an external implementation to reject malformed bytes.

Together, the OpenSSH tests and known vectors exercise identification exchange, KEXINIT
negotiation, exchange-hash and signature verification, `NEWKEYS`, encrypted and authenticated
packet framing, service negotiation, authentication, session streams, and graceful disconnect
behavior. Passing these tests proves the covered algorithms and features; it does not imply that
every OpenSSH algorithm or extension has been implemented.
