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
  The same test uses the public agent-forwarding API without an RFC 9987 advertisement, then runs
  `ssh-add -L` on OpenSSH to prove both safe compatibility-name fallback and that the remote process
  sees the modern client's local OpenSSH agent. It also requests X11 forwarding, connects
  to the display allocated by sshd, and exchanges data through the resulting `x11` channel.
  A Node subprocess also uses the packaged `HTTPAgent` with `http.get()` to reach an HTTP endpoint
  through a forced `direct-tcpip` channel on the OpenSSH server.

The OpenSSH server test requires Docker. The image is tagged locally as
`modernssh-openssh-test:bookworm`; Docker reuses its build cache after the first run. The pinned base
image makes the operating-system fixture reproducible, while installing the distribution's
`openssh-server` package exercises the normal packaged daemon configuration.

## Deterministic protocol vectors

RFC 4462 GSS-API authentication is covered by literal packet bytes for mechanism negotiation, every
context-exchange message, canonical DER OID rejection, and the exact session-bound MIC input. An
independent HMAC-backed test mechanism drives both library roles through multi-round context
establishment, adjacent final-token/MIC delivery, integrity and no-integrity completion, mechanism
status and error tokens, client abandonment followed by a fresh authentication request, context
cleanup, and rejection of an invalid MIC before application policy. This validates the SSH state
machine without claiming interoperability for any particular external GSS-API provider.

Wire codecs are tested independently of OpenSSH with fixed byte strings derived from the protocol
formats. The channel vector suites cover `direct-tcpip`, `forwarded-tcpip`, TCP forwarding global
requests, all four OpenSSH stream-local forwarding messages, allocated-port responses, PTY and
terminal modes, environment, window changes, signals, RFC 4254 `xon-xoff`, RFC 4335 BREAK,
subsystems, both RFC 9987 agent-forwarding request and channel-open name forms, X11 requests and
channel opens, session exit status and signal metadata,
`no-more-sessions@openssh.com`, window adjustment,
`keepalive@openssh.com`, standard data, stderr extended data, EOF, and CLOSE. Every vector is parsed
into asserted fields and serialized back to the exact original bytes.

Generic global-request integration sends concurrent requests through an awaited server hook and
proves their opaque replies remain ordered, covers deny-by-default and one-way notification paths,
and exercises ordered server-initiated requests through the client's awaited hook using the public
`ServerClient` API, including a request queued across rekey and one rejected on close. Real OpenSSH
peers reject private unknown requests initiated in either direction, proving standards-compatible
failure handling for both public APIs.

Agent-forwarding integration also connects the library's client and server directly, verifies the
literal `agent-forward` version `0` advertisement, and proves that `forwardAgent()` selects
`agent-req` followed by `agent-connect`. Replacement-extension coverage proves that omitting the
advertisement clears the capability instead of retaining stale negotiation state.
Fixed public agent-protocol exchanges also prove that a contained later policy failure cannot
release an earlier identity list or cryptographic signature.
Management exchanges independently apply that failure ordering to identity and token additions,
individual and bulk identity removal, and token removal.
Stateful agent tests additionally prove that later failures cannot transition lock state, expose an
extension result or advertised list, or retain a proposed session binding.

RFC 8308 no-flow-control coverage checks the literal `p` and `s` values and every bilateral
preference outcome. In-process peers transfer data in both directions after their advertised
windows are exhausted, ignore otherwise overflowing window adjustments, refuse a second live
channel, permit another after complete close, and disable the capability when a replacement server
extension set omits it. Packet-size checks remain active while channel-window accounting is
disabled.

RFC 8308 elevation coverage fixes the complete extension packets for the registered `y`, `n`, and
`d` values and the exact post-authentication one-way global request. In-process peers prove that
authentication waits for asynchronous server policy, both boolean outcomes reach the client, and
an omitted advertisement uses server-default policy without sending an unsolicited result.
Malformed result framing is rejected through the encrypted connection. A real encrypted session
also proves that a later contained policy failure suppresses an earlier elevation result without
undoing otherwise successful authentication.

Session interoperability sends a BREAK from the modern client to a real OpenSSH PTY and delivers
an `xon-xoff` notification from the modern server to the system OpenSSH client. In-process peers
also prove that BREAK policy hooks are awaited, success and failure replies match the completed
operation, requested durations are preserved, and client notifications carry the exact boolean.

In-process forwarding tests additionally open server-initiated TCP and UNIX channels through the
public connection APIs only after matching requests have been accepted. They assert every source
and destination field, exchange data in both directions through the bounded channel streams, and
reject attempts after cancellation.

Transport tests likewise use deterministic identification, binary framing, encryption-boundary,
MAC, AEAD, fragmentation, and maximum-size vectors. AES-GCM is checked against a published NIST
primitive vector. ChaCha20 and Poly1305 are checked against RFC 8439 vectors. Both AEAD packet
layouts have fixed SSH packets generated independently of the TypeScript codec. This keeps exact
packet parsing failures local and diagnosable instead of relying on an external implementation to
reject malformed bytes.

RFC 5647 coverage also fixes the registered `AEAD_AES_128_GCM` packet ciphertext and tag for an
independently generated key, IV, payload, padding, and authenticated length. Negotiation tests
require ordinary SSH preference rules to select the same registered name in the cipher and MAC
lists for each direction and reject either kind of mismatched selection. In-process client and
server peers force both registered key sizes through authenticated traffic and rekey while checking
that handshake metadata reports the RFC MAC name.

RFC 8731 Curve448 coverage uses RFC 7748's literal Alice and Bob private keys, public values, and
shared secret. It also verifies the required reduction of a non-canonical field coordinate, exact
56-byte SSH-string framing, rejection of wrong-length and low-order peers, and defensive ownership
of ephemeral state. A forced in-process client/server connection exchanges authenticated traffic
before and after rekey with `curve448-sha512`, proving both SSH roles preserve the first session ID
while deriving a new exchange hash and transport keys.

RFC 9941 coverage reproduces the published SHA-512 combination of the sntrup761 KEM and X25519
secrets, including the exact 64-byte SSH-string encoding. KEM tests cover fixed object sizes,
encapsulation, decapsulation, implicit rejection of a changed ciphertext, and defensive ownership
of hybrid public values. In-process peers force both the standardized method and its deployed alias
through protected traffic and rekey. The system OpenSSH client then forces the alias against the
library server and initiates a low-limit rekey; a separate library client executes commands before
and after an explicit rekey against the pinned OpenSSH server.

The registered ML-KEM hybrid coverage checks ML-KEM-768 and ML-KEM-1024 key generation against
fixed SHA-256 digests of NIST ACVP FIPS 203 test cases 26 and 51. Independent fixed inputs cover the
specified SHA-256 and SHA-384 `K_PQ || K_CL` combiners. Tests exercise exact client/server message
sizes, compressed and uncompressed NIST points, invalid ML-KEM and classical values, ciphertext
implicit rejection, and defensive buffer ownership. In-process peers force all three registered
method names through authenticated traffic and rekeys initiated by both roles.

Standalone ML-KEM coverage fixes all three FIPS 203 encapsulation-key parameter sets to NIST ACVP
vectors and checks the SHA-256 digest of each published encapsulation key. It verifies exact
800/1184/1568 byte client keys, exact 768/1088/1568 byte server ciphertexts, non-canonical key
rejection, same-length ciphertext implicit rejection, and the specification's distinct raw-string
exchange-hash encoding. In-process client/server tests force each IANA name through authenticated
traffic and rekeys initiated by both roles; SHA-256 and SHA-384 exchange-hash lengths are checked
separately.

RFC 4250 name tests cover the 64-character boundary, extension-domain form, non-ASCII and control
input, commas, empty entries, and duplicate name-list members. Packet tests separately prove that
the validation is applied to services, extensions, channels, and requests rather than existing
only as an unused utility.

Disconnect integration covers both peer directions over encrypted connections. It verifies the
typed event precedes close, preserves immutable RFC metadata, rejects a pending request with the
typed error, and interrupts connection setup immediately rather than waiting for the readiness
deadline. Graceful shutdown tests independently verify that both public connection roles report
transport EOF through `end` before terminal `close` cleanup. Real half-open injected TCP transports
also verify that EOF terminates both peer roles immediately rather than leaving setup pending until
a readiness or handshake deadline.

Server admission integration verifies that the public connection event receives an immutable
snapshot of both TCP endpoints and retains it after the peer closes. A separate real SSH handshake
proves that a rejected async `preconnect` chain fails closed even when an earlier handler allowed
the connection. Encrypted client/server tests apply the same multi-handler failure to host-key trust
and user authentication, proving that a contained later rejection cannot retain an earlier allow
decision. The same real transport seam verifies channel admission, TCP and stream-local listener
creation, and application global requests in both peer directions.
Private channel requests are exercised in both directions. Session tests separately prove that a
later policy failure cannot retain earlier approval for shell, exec, subsystem, PTY, environment,
BREAK, agent-forwarding, or X11 requests and cannot publish the corresponding accepted state or
event.

Server shell integration verifies RFC 4254 directional half-close semantics: ending stdout sends
EOF without CLOSE, the client sends additional stdin afterward, and explicit close then completes
the channel lifecycle.

An independently written unknown message is also sent in both directions over an encrypted
in-process connection; each peer returns the exact rejected sequence in `SSH_MSG_UNIMPLEMENTED` and
continues with later traffic. The system OpenSSH client independently returns the same response to
an unknown server message.

RFC 4419 group-exchange request, group, init, and reply messages use independently written fixed
frames, including the context-specific opcode 31. Primitive tests select RFC 8270-sized safe groups,
prove both sides derive the same secret, and reject invalid ranges, composite groups, non-canonical
mpints, and out-of-range public values.

Compression tests use independently generated RFC 1950 streams with the RFC 4253 partial flush at
each packet boundary. They prove dictionary continuity across packets, exact payload-only framing,
malformed-stream rejection, and bounded expansion. In-process peers exercise both immediate `zlib`
and delayed `zlib@openssh.com` through multi-packet bidirectional transfers and rekeying.

RFC 8308 delay-compression tests use the specification's literal two-name-list value, a complete
fixed extension packet, and the one-byte opcode-8 `NEWCOMPRESS` trigger. In-process peers begin with
`none`, activate each `zlib` direction at its distinct authentication trigger, exchange compressed
traffic, and prove that a subsequent rekey overrides the extension. Coverage also includes
bilateral gating, a server offer delayed until authentication policy, non-mutual negotiation,
locally blocked premature rekeys, the bounded trigger deadline, and wrong-direction or duplicate
triggers.

Transport ping coverage uses fixed opcode 192/193 packet vectors and exercises concurrent ordered
echoes plus a ping queued across rekey against the in-process server. The pinned OpenSSH fixture
predates `ping@openssh.com`; the client verifies that absence of its RFC 8308 advertisement rejects
the API call before any extension packet is sent.

The agent suite sends fixed RFC 9987 identity-list and signing frames through fragmented UNIX-socket
reads. A separate integration test starts the system OpenSSH `ssh-agent`, loads an independently
generated Ed25519 key with `ssh-add`, lists it through `modernssh`, and verifies a delegated
signature cryptographically.

Security-key coverage uses fixed Ed25519, P-256, and WebAuthn wire values derived independently from
the published FIDO/U2F format. Negative cases change the signed counter, WebAuthn challenge,
authenticator-data flag, origin, and extension-present state. The system `ssh-keygen` issues both
security-key certificate types; the library parses their exact vendor algorithm names and verifies
the certificate authority signature. An in-process non-interactive agent completes host-bound
public-key authentication with a security-key signature through the awaited server policy hook.
Fixed private containers cover both published key-handle layouts, including encrypted storage and
ownership checks. A literal `sk-provider@openssh.com` constrained-add frame is exercised in both
agent roles, and the system OpenSSH agent independently accepts, lists, and removes the synthetic
provider-backed identity without requiring the physical authenticator.

Legacy Cygwin transport coverage uses the
[socket descriptor and security exchange published by Cygwin's maintainers](https://cygwin.com/pipermail/cygwin-developers/2014-May/011417.html).
A loopback TCP fixture verifies the exact per-uint32 byte order of the
16-byte socket secret, fragmented secret echoes, the zero-credential discovery connection, the
second connection's process ID and discovered UID/GID, and subsequent RFC 9987 listing and signing.
Negative cases cover non-ASCII, malformed, and oversized descriptors, a mismatched secret, an idle
deadline, and destruction of the silent peer. This is deterministic protocol coverage and does not
claim execution inside a Cygwin installation.

Private-key interoperability tests generate passphrase-protected Ed25519 keys with `ssh-keygen`
using every cipher accepted by OpenSSH 9.6 (3DES-CBC, AES-CBC, AES-CTR, AES-GCM, and OpenSSH
ChaCha20-Poly1305), then decrypt, sign, and verify each key. They also cover encrypted RSA keys,
missing and incorrect passphrases, authenticated-data tampering, and `DiskAgent` passphrase
resolution. No JavaScript SSH implementation supplies expected key data.

The inverse path serializes a generated key with every supported cipher and asks `ssh-keygen -y`
to decrypt and derive its public key. Those outputs must match the generated public key exactly.
Repeated encryption proves fresh salt generation, while incorrect passphrases, modified output,
empty secrets, and invalid bcrypt round counts are rejected.

Multi-key private-container tests combine Ed25519, ECDSA, and Ed448 entries in independently
parsed raw and armored envelopes, with and without authenticated encryption. They verify order,
comments, signing, public/private matching, singular-API rejection, count bounds, and padding.

PEM import interoperability uses OpenSSL to create Ed25519 and RSA PKCS#8, traditional PKCS#1 RSA,
SEC1 ECDSA, and encrypted ECDSA PKCS#8 inputs. Each imported key signs data and is converted to an
OpenSSH private-key container whose derived public key is checked by `ssh-keygen`. An unsupported
X25519 PKCS#8 key is rejected explicitly.

Public PEM interoperability covers generic SubjectPublicKeyInfo for Ed25519, RSA, and every RFC
5656 ECDSA curve, plus traditional PKCS#1 RSA public keys. Each converted key verifies a signature
from its independently imported private half, and `ssh-keygen` accepts and fingerprints the
canonical SSH public-key output. Unsupported X25519 public keys are rejected explicitly.

RFC 4716 public-key import is checked against the document's literal RSA example and strict
malformed framing, continuation, line-length, UTF-8, and base64 cases. A generated Ed25519 key is
exported in RFC 4716 form by `ssh-keygen` and parsed through the package's unified key router;
`ssh-keygen` also imports the fixed RFC example and produces the same canonical SSH key.

PPK import uses the RFC 8032 Ed25519 seed, public key, and empty-message signature as a fixed
private-key vector in both version 2 and version 3 envelopes. The system `puttygen` independently
accepts those fixtures, and generated version 3 fixtures cover RSA, DSA, Ed25519, Ed448, and every
supported ECDSA curve. Encrypted tests cover version 2 plus Argon2d, Argon2i, and Argon2id version 3
files, including incorrect passphrases, integrity failures, malformed framing, and resource bounds.
Every generated key signs through the library and is matched to `puttygen`'s public output; key
families understood by the system OpenSSH build are also reserialized and checked with
`ssh-keygen -y`.

Ed448 coverage uses RFC 8032's empty-message key and signature vector, wrapped in the exact RFC
8709 SSH public-key and signature encodings. A native Node subprocess independently generates an
Ed448 PKCS#8 and SubjectPublicKeyInfo pair, imports both, and verifies a signature; generated
library keys also round-trip through the private-key container.

Legacy DSS coverage makes the signer reproduce the RFC 6979 DSA-1024/SHA-1 vector with RFC 4253's
literal four-mpint key blob and fixed 40-byte signature. OpenSSH-generated private, public, and PEM
containers are parsed, signed, serialized, and derived again with `ssh-keygen`. With the method
explicitly enabled, OpenSSH verifies the library server's DSS host signature; the library also
verifies OpenSSH's DSS host signature while OpenSSH verifies a library DSS user-authentication
signature. Default offers are separately checked to exclude DSS and the other legacy-only algorithm
families.

OpenSSH private-key tests also generate every required ECDSA curve and prove parsing, public-key
matching, signing, and verification. The signer reproduces RFC 6979's P-256/SHA-256,
P-384/SHA-384, and P-521/SHA-512 signatures, independently encoded as RFC 5656 pairs of SSH mpints.

Generated-key interoperability creates Ed25519, 2048-bit RSA, and every required ECDSA curve through
the public `generateKeyPair()` API. OpenSSH `ssh-keygen` derives and fingerprints each generated
private key, while independent signing checks prove that each returned public key matches. A
separate default-generation test verifies the documented 3072-bit RSA modulus.

Direct client private-key authentication loads the same RSA identity authorized by the OpenSSH
fixture, connects without a password or external agent, and executes a command. In-process coverage
also loads an encrypted key through `privateKey` and `passphrase`, exercises host-bound
authentication, and verifies that encoded secrets are not retained in client options.

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
Separate encrypted client/server cases prove that contained later failures stop authentication
method selection and discard earlier password, password-change, and keyboard-interactive values
before those values cross the wire.

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

Known-hosts interoperability hashes a real database with `ssh-keygen -H` and verifies that the
library finds its hidden hostname. In the other direction, `ssh-keygen -F` finds an independently
salted hashed entry written by the library. Certificate-authority coverage generates and signs a
host certificate with `ssh-keygen`, then exercises hostname principals, validity, authority trust,
and authority revocation through the public `KnownHosts` API.

Public-key authentication also exercises the version-0 host-bound extension in both roles. Fixed
wire bytes prove that the exact negotiated server host key is part of the signature preimage; live
tests prove the unsigned key probe followed by a bound signed request and reject a mismatched host
key before application authorization.

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

The optional RFC 4253 `blowfish-cbc` and `cast128-cbc` methods have separate in-process evidence
because current OpenSSH builds no longer offer them. The original published 128-bit-key Blowfish
CBC vector verifies four chained blocks exactly. RFC 2144's CAST-128 vector and an independent
two-block OpenSSL CBC value verify its primitive and chaining. Forced client/server exchanges then
verify protected traffic and rekey in both library roles. This is compatibility evidence, not a
recommendation to deploy a 64-bit block cipher.

Truncated HMAC-SHA1 interoperability forces both RFC 4253 `hmac-sha1-96` and the deployed
`hmac-sha1-96-etm@openssh.com` method in both peer roles with AES-128-CTR. Each direction explicitly
rekeys and executes a command, while fixed RFC 2202 bytes independently verify that the tag is the
first 12 bytes of the complete HMAC-SHA1 result.

Legacy HMAC-MD5 interoperability similarly forces the full and 96-bit RFC 4253 methods and both
deployed encrypt-then-MAC forms with AES-128-CTR. OpenSSH and the modern client each transfer data
and rekey for every name in both peer roles. An RFC 2202 vector independently verifies the full
digest and first-12-byte truncation; these methods remain last and are not recommended for new use.

Legacy HMAC-RIPEMD160 coverage forms RFC 2286's literal `Hi There` input through the SSH sequence
number and packet fields and checks its complete 20-byte digest. An in-process client and server
then force `hmac-ripemd160` with AES-128-CTR, exchange authenticated traffic in both directions,
and rekey. The method remains an explicit compatibility choice; the system OpenSSH fixture does not
advertise it.

UMAC coverage checks the RFC 4418 messages from empty through 32 MiB, including verified erratum
3507 for the long-message polynomial transition, plus 32-, 64-, and 96-bit output iterations. The
system SSH client then forces each deployed 64-/128-bit ordinary and encrypt-then-MAC variant and
exchanges channel traffic in both directions across an explicit rekey.

End-of-write coverage uses the literal one-way channel-request frame, verifies awaited half-close
state in both channel roles, and rejects replies, arguments, duplicates, and non-session use. The
system client accepts a capability-gated server request, stops its input side, and still receives
the server's remaining output before normal exit.

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
