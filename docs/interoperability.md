# OpenSSH interoperability testing

The end-to-end interoperability suite uses OpenSSH rather than another JavaScript SSH library. It
establishes real TCP connections in both directions:

- The system `/usr/bin/ssh` client connects to a `modernssh` server, verifies transport and user
  authentication behavior, opens a session, transfers stdin/stdout/stderr, receives an exit status,
  completes EOF/CLOSE handling, and separately establishes an `ssh -R` listener whose data crosses
  a server-initiated `forwarded-tcpip` channel. It also exchanges data through both `ssh -L` direct
  and `ssh -R` remote UNIX-socket forwarding against the `modernssh` server.
  It also forwards a real OpenSSH agent, which the server queries over a server-initiated agent
  channel and validates against the fixture key. Its X11 test replaces the SSH fake cookie with a
  real `Xauthority` cookie before delivering the setup packet to a local test display.
- A `modernssh` client connects to an OpenSSH server built from the digest-pinned Debian fixture in
  `__tests__/openssh/Dockerfile`, authenticates with a password, executes a command, separates
  stdout/stderr, receives its exit status, establishes and cancels a remote TCP listener, exchanges
  data over the resulting `forwarded-tcpip` channel, opens direct and remote OpenSSH stream-local
  forwarding channels, disables additional sessions with `no-more-sessions@openssh.com`, verifies
  OpenSSH's enforcement, exchanges SSH-level keepalives, explicitly rekeys the transport, and
  uses high-level environment and PTY session options, and handles the resulting disconnect without
  leaving a channel pending. It also opens a second authenticated SSH connection through an
  OpenSSH `direct-tcpip` channel to validate supplied-duplex connection hopping. The OpenSSH client
  initiates key re-exchange against the modern server under a deliberately low byte limit.
  The same test requests agent forwarding and runs `ssh-add -L` on OpenSSH to prove that the remote
  process sees the modern client's local OpenSSH agent. It also requests X11 forwarding, connects
  to the display allocated by sshd, and exchanges data through the resulting `x11` channel.

The OpenSSH server test requires Docker. The image is tagged locally as
`modernssh-openssh-test:bookworm`; Docker reuses its build cache after the first run. The pinned base
image makes the operating-system fixture reproducible, while installing the distribution's
`openssh-server` package exercises the normal packaged daemon configuration.

## Deterministic protocol vectors

Wire codecs are tested independently of OpenSSH with fixed byte strings derived from the protocol
formats. The channel vector suites cover `direct-tcpip`, `forwarded-tcpip`, TCP forwarding global
requests, all four OpenSSH stream-local forwarding messages, allocated-port responses, PTY and
terminal modes, environment, window changes, signals, RFC 4254 `xon-xoff`, RFC 4335 BREAK,
subsystems, agent forwarding requests and
channel opens, X11 requests and channel opens, `no-more-sessions@openssh.com`, window adjustment,
`keepalive@openssh.com`, standard data, stderr extended data, EOF, and CLOSE. Every vector is parsed
into asserted fields and serialized back to the exact original bytes.

Session interoperability sends a BREAK from the modern client to a real OpenSSH PTY and delivers
an `xon-xoff` notification from the modern server to the system OpenSSH client. In-process peers
also prove that BREAK policy hooks are awaited, success and failure replies match the completed
operation, requested durations are preserved, and client notifications carry the exact boolean.

In-process forwarding tests additionally open server-initiated TCP and UNIX channels through the
public connection APIs only after matching requests have been accepted. They assert every source
and destination field, exchange data in both directions through the bounded channel streams, cover
the callback and promise forms, and reject attempts after cancellation.

Transport tests likewise use deterministic identification, binary framing, encryption-boundary,
MAC, AEAD, fragmentation, and maximum-size vectors. AES-GCM is checked against a published NIST
primitive vector. ChaCha20 and Poly1305 are checked against RFC 8439 vectors. Both AEAD packet
layouts have fixed SSH packets generated independently of the TypeScript codec. This keeps exact
packet parsing failures local and diagnosable instead of relying on an external implementation to
reject malformed bytes.

RFC 4419 group-exchange request, group, init, and reply messages use independently written fixed
frames, including the context-specific opcode 31. Primitive tests select RFC 8270-sized safe groups,
prove both sides derive the same secret, and reject invalid ranges, composite groups, non-canonical
mpints, and out-of-range public values.

Compression tests use independently generated RFC 1950 streams with the RFC 4253 partial flush at
each packet boundary. They prove dictionary continuity across packets, exact payload-only framing,
malformed-stream rejection, and bounded expansion. In-process peers exercise both immediate `zlib`
and delayed `zlib@openssh.com` through multi-packet bidirectional transfers and rekeying.

The agent suite sends fixed RFC 9987 identity-list and signing frames through fragmented UNIX-socket
reads. A separate integration test starts the system OpenSSH `ssh-agent`, loads an independently
generated Ed25519 key with `ssh-add`, lists it through `modernssh`, and verifies a delegated
signature cryptographically.

Private-key interoperability tests generate passphrase-protected Ed25519 keys with `ssh-keygen`
using every cipher accepted by OpenSSH 9.6 (3DES-CBC, AES-CBC, AES-CTR, AES-GCM, and OpenSSH
ChaCha20-Poly1305), then decrypt, sign, and verify each key. They also cover encrypted RSA keys,
missing and incorrect passphrases, authenticated-data tampering, and `DiskAgent` passphrase
resolution. No JavaScript SSH implementation supplies expected key data.

OpenSSH private-key tests also generate every required ECDSA curve and prove parsing, public-key
matching, signing, and verification. An RFC 6979 P-256/SHA-256 signature is independently encoded as
the RFC 5656 pair of SSH mpints and verified as a fixed cryptographic vector.

Authentication interoperability covers RFC 4252 banners and password changes plus RFC 4256
keyboard-interactive exchanges. OpenSSH's client completes a two-prompt keyboard-interactive round
and a forced password change against the modern server. The modern client authenticates through
PAM-backed OpenSSH keyboard-interactive and records OpenSSH's banner. Fixed, independently written
wire vectors cover every new message layout, including the context-dependent reuse of opcode 60.
An in-process integration test proves that a partial password success can change the advertised
method set and cause an earlier failed keyboard-interactive method to be retried as the second
factor. It also verifies the RFC authentication-limit disconnect packet, proves that `none` and
partial success do not consume the failure ceiling, and holds an async policy hook past the server
deadline to ensure its late approval cannot authenticate the connection.

Host-based authentication is exercised in both peer roles with real OpenSSH machine keys. OpenSSH
signs a request with the isolated container's Ed25519 host key and the modern server authorizes its
claimed hostname, local user, target user, public key, and observed address through an awaited hook.
The modern client then uses an OpenSSH host private key to authenticate to the containerized server,
explicitly rekeys, and executes a command. A fixed RFC 4252 request and signature preimage cover the
wire format, while an invalid signature is rejected before application policy runs.

RSA SHA-2 interoperability covers RFC 8332 host and user signatures in both peer roles. The system
OpenSSH client forces `rsa-sha2-512`, authenticates with an RSA key, and initiates rekeying against
the modern server. The modern client uses a real OpenSSH RSA agent and an explicitly forced RSA
SHA-512 host key against the containerized server; an invalid password prevents fallback. Fixed
vectors independently cover the RFC 8308 `server-sig-algs` message and the distinct RSA signature
algorithm and `ssh-rsa` key-format fields.

Host-key rotation interoperability verifies the server's `hostkeys-00@openssh.com` announcement by
requesting `hostkeys-prove-00@openssh.com`, checking each signature against the session-bound proof
message, and matching the resulting RSA key to the real containerized server key. Independent fixed
bytes cover the proof preimage, while focused cryptographic tests reject modified, truncated, and
extra signatures.

ECDSA host-key interoperability forces each RFC-required NIST curve in both peer roles. OpenSSH
initiates low-limit rekeys against the modern server for P-256, P-384, and P-521; separate modern
clients force each corresponding OpenSSH host key, explicitly rekey, authenticate, and execute a
command.

Diffie-Hellman group-exchange interoperability forces both RFC 4419 SHA-256 and SHA-1 method names
in both peer roles. OpenSSH initiates low-limit rekeys against the modern server; separate modern
clients validate OpenSSH-selected safe groups, explicitly rekey, authenticate, and execute a
command. SHA-1 coverage exists for legacy compatibility, while SHA-256 precedes fixed MODP methods
in the default preference.

AEAD interoperability forces ChaCha20-Poly1305 and both 128- and 256-bit AES-GCM variants in both
peer roles. OpenSSH streams enough data to initiate low-limit rekeys against the modern server;
separate modern clients force each cipher against the containerized server, explicitly rekey, and
execute a command. Negotiated handshake details prove that both directions use implicit integrity
rather than a separate MAC.

CBC interoperability forces AES-128, AES-192, AES-256, and three-key 3DES in both peer roles.
OpenSSH initiates low-limit rekeys against the modern server; separate modern clients explicitly
rekey and execute a command against the containerized server. Negotiated handshake details prove
that every CBC direction uses a separate MAC. NIST SP 800-38A AES vectors and an independently
generated OpenSSL 3DES vector verify the block primitives, while fragmented fixed packets verify
that cipher chaining continues when the decoder receives the first block separately.

Delayed-compression interoperability runs in both peer roles. OpenSSH and the modern client each
force `zlib@openssh.com`, transfer repeated multi-packet data in both directions, and rekey while the
compression streams are active. Handshake details confirm the selected method before traffic is
accepted.

SFTP interoperability runs in both directions. The modern client uses OpenSSH's revision 3
subsystem for multi-packet upload and download, concurrent reads with request-id matching, file and
directory handles, attributes and timestamps, rename, canonicalization, directory scanning, and
OpenSSH's documented reversed `SSH_FXP_SYMLINK` arguments. It also negotiates OpenSSH limits and
executes advertised fsync, statvfs, POSIX rename, hard-link, path expansion, server-side copy, home
directory, and identity lookup extensions. Whole-file helpers are exercised for encoded reads,
write, append, size limits, and existence checks; parallel upload and download use deliberately
uneven chunks against the real server. Writable and inclusive-range readable Node streams are also
round-tripped through OpenSSH, and returned mode bits are checked through `SFTPStats` file-type
predicates. The system OpenSSH `sftp` client uploads, lists, renames, symlinks, downloads, and removes
files through a policy-controlled modern server. Independent literal vectors cover every baseline
request and response layout and every extension payload; malformed framing, counts, flags, handles,
response types, request identifiers, and extension replies are rejected without relying on another
JavaScript SSH implementation.

Together, the OpenSSH tests and known vectors exercise identification exchange, KEXINIT
negotiation, exchange-hash and signature verification, `NEWKEYS`, encrypted and authenticated
packet framing, OpenSSH encrypt-then-MAC ordering, RFC 8731 Curve25519 and RFC 5656 ECDH in both
peer roles, RFC 5647 AES-GCM and OpenSSH ChaCha20-Poly1305 packet protection, bidirectional key
re-exchange, immediate and delayed zlib compression, service negotiation, authentication, session
streams, client- and server-side
remote forwarding, and graceful disconnect behavior. Passing these tests proves the covered
algorithms and features; it does not imply that every OpenSSH algorithm or extension has been
implemented.
