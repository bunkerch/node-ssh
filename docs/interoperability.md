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
  forwarding channels, and disconnects gracefully.
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
terminal modes, environment, window changes, signals, subsystems, agent forwarding requests and
channel opens, X11 requests and channel opens, window adjustment, standard data, stderr extended
data, EOF, and CLOSE. Every vector is parsed into asserted fields and serialized back to the exact
original bytes.

Transport tests likewise use deterministic identification, binary framing, encryption-boundary,
MAC, fragmentation, and maximum-size vectors. This keeps exact packet parsing failures local and
diagnosable instead of relying on an external implementation to reject malformed bytes.

The agent suite sends fixed RFC 9987 identity-list and signing frames through fragmented UNIX-socket
reads. A separate integration test starts the system OpenSSH `ssh-agent`, loads an independently
generated Ed25519 key with `ssh-add`, lists it through `modernssh`, and verifies a delegated
signature cryptographically.

Private-key interoperability tests generate passphrase-protected Ed25519 keys with `ssh-keygen`
using every cipher accepted by OpenSSH 9.6 (3DES-CBC, AES-CBC, AES-CTR, AES-GCM, and OpenSSH
ChaCha20-Poly1305), then decrypt, sign, and verify each key. They also cover encrypted RSA keys,
missing and incorrect passphrases, authenticated-data tampering, and `DiskAgent` passphrase
resolution. No JavaScript SSH implementation supplies expected key data.

Authentication interoperability covers RFC 4252 banners and password changes plus RFC 4256
keyboard-interactive exchanges. OpenSSH's client completes a two-prompt keyboard-interactive round
and a forced password change against the modern server. The modern client authenticates through
PAM-backed OpenSSH keyboard-interactive and records OpenSSH's banner. Fixed, independently written
wire vectors cover every new message layout, including the context-dependent reuse of opcode 60.
An in-process integration test proves that a partial password success can change the advertised
method set and cause an earlier failed keyboard-interactive method to be retried as the second
factor.

SFTP interoperability runs in both directions. The modern client uses OpenSSH's revision 3
subsystem for multi-packet upload and download, concurrent reads with request-id matching, file and
directory handles, attributes and timestamps, rename, canonicalization, directory scanning, and
OpenSSH's documented reversed `SSH_FXP_SYMLINK` arguments. It also negotiates OpenSSH limits and
executes advertised fsync, statvfs, POSIX rename, hard-link, path expansion, server-side copy, home
directory, and identity lookup extensions. The system OpenSSH `sftp` client uploads, lists, renames,
symlinks, downloads, and removes files through a policy-controlled modern server. Independent
literal vectors cover every baseline request and response layout and every extension payload;
malformed framing, counts, flags, handles, response types, request identifiers, and extension
replies are rejected without relying on another JavaScript SSH implementation.

Together, the OpenSSH tests and known vectors exercise identification exchange, KEXINIT
negotiation, exchange-hash and signature verification, `NEWKEYS`, encrypted and authenticated
packet framing, service negotiation, authentication, session streams, client- and server-side
remote forwarding, and graceful disconnect behavior. Passing these tests proves the covered
algorithms and features; it does not imply that every OpenSSH algorithm or extension has been
implemented.
