# Repository Guidelines

## Project Structure & Module Organization

This repository provides `modernssh`, a typed, ESM-native SSH client and server library for Node.js
22+. Production TypeScript lives in `src/`: protocol packets are in `src/packets/`, channels in
`src/channels/`, authentication methods in `src/auth/`, algorithms in `src/algorithms/`, and shared
primitives in `src/utils/`. Public exports are assembled in `src/index.ts`. Tests mirror these
concerns under `__tests__/`, with dedicated `integration/`, `openssh/`, `packets/`, `transport/`, and
`package/` suites. User and protocol documentation belongs in `docs/`. Compiled JavaScript,
declarations, and source maps are generated in `dist/`; do not edit them directly.

## Build, Test, and Development Commands

- `pnpm install` installs the pinned pnpm 10 dependencies.
- `pnpm build` removes `dist/` and compiles strict TypeScript.
- `pnpm dev` runs the TypeScript compiler in watch mode.
- `pnpm test` builds first, then runs all suites with Bun. OpenSSH server interoperability uses
  Docker and the digest-pinned fixture in `__tests__/openssh/Dockerfile`.
- `pnpm lint` checks JavaScript and TypeScript with ESLint.
- `pnpm format:check` verifies Prettier formatting; `pnpm format` applies it.
- `pnpm pack` creates a local installable archive for consumer testing.

Before submitting changes, run `pnpm test`, `pnpm lint`, and `pnpm format:check`.

## Coding Style & Naming Conventions

Use strict TypeScript and NodeNext ESM semantics; include `.js` extensions in relative imports.
Prettier enforces four-space indentation, double quotes, no semicolons, 100-character lines, and
trailing commas. Use PascalCase for classes and their files (`BinaryPacket.ts`), camelCase for
functions and variables, and descriptive lowercase names for algorithm modules
(`hmac-sha2-256.ts`). Keep protocol constants and wire behavior close to the relevant RFC-oriented
module. Export new public APIs explicitly from `src/index.ts`.

## Testing Guidelines

Tests use Bun's Jest-compatible `describe`, `test`, and `expect` APIs. Place tests in the matching
`__tests__/<area>/` directory and follow the source file's PascalCase filename, such as
`__tests__/transport/BinaryPacket.ts`. Cover success, failure, boundary, and fragmented-input cases
for protocol changes.

Packet parsing and serialization tests must use fixed, independently written known byte vectors
from the applicable RFC or protocol document. Do not generate an expected packet with the codec
being tested. Cross-implementation tests must use OpenSSH (`/usr/bin/ssh` or the containerized
`sshd` fixture). Keep external-process assertions deterministic and suppress incidental client
logging. No numeric coverage threshold is configured; prioritize focused regression tests and
meaningful wire-level behavior.

## Protocol and Library Practices

- Public asynchronous operations are Promise-only. Do not add Node-style completion callbacks,
  callback overloads, or callback-returning aliases; callers can chain `.then()` when desired.
  Hooker policies and EventEmitter notifications remain the application extension mechanisms.
  Callbacks required internally by Node stream, socket, HTTP agent, or crypto interfaces are not
  public API flows.

- Implement behavior from the RFCs in `../rfcs`; fetch missing RFCs from an authoritative source
  when needed.
- Treat third-party implementations only as a short-lived feature-gap inventory. Do not mention,
  cite, imitate, or use them as behavioral authorities in tracked source, tests, documentation, or
  API rationale. Derive behavior and naming from protocol specifications and this library's own
  design; validate it with independent fixed vectors and real OpenSSH peers.
- The SSH agent client follows RFC 9987. Keep its framing bounded to OpenSSH's 256 KiB limit and
  validate it with fixed frames plus the system `ssh-agent`, never another JavaScript SSH library.
  Client agent socket-path shorthand must normalize eagerly to the same `SSHAgent` implementation;
  an omitted option must remain disabled instead of implicitly consulting the environment.
- Connection-wide agent forwarding remains opt-in, is applied before each high-level session
  program request, and may be explicitly disabled or enabled per session. It must still require a
  forwardable agent and the normal vendor capability gate.
- OpenSSH private-key encryption follows upstream `PROTOCOL.key`. Keep passphrase and derived-key
  buffers short-lived, validate authenticated modes before parsing plaintext, compare the public
  envelope with the private key, and exercise both decryption and serialization for every supported
  cipher with real `ssh-keygen` output. Serialization copies caller passphrases, uses fresh salts,
  validates bcrypt rounds, and clears derived material plus temporary plaintext key buffers.
- Private-key containers may contain multiple ordered public/private entries. Keep singular parsers
  explicit about rejecting them; use the `parseAll`/`fromStringAll`/`parseKeys` surfaces when a
  collection is expected, validate every public envelope against its private entry, and apply one
  integrity check plus one final padding sequence to the complete private section.
- Public key generation accepts semantic Ed25519, Ed448, RSA, and ECDSA family names, uses 3072-bit RSA and
  P-256 defaults, restricts ECDSA to the three RFC 5656 curves, and propagates a line-safe comment to
  both returned key objects. Validate every family with signing plus real `ssh-keygen` derivation
  and fingerprinting, including the documented RSA default.
- RFC 5656 ECDSA constructors normalize and validate public points, derive each public point from
  its private scalar, and copy caller-owned point and scalar buffers before retaining them.
- RSA constructors require canonical positive mpints, validate the public exponent, modulus/factor
  product, probable primes, CRT inverse, and private exponent congruence, and copy every retained
  component.
- Signature envelopes strictly validate their SSH algorithm name, reject trailing fields, copy
  caller-owned payload bytes, and revalidate mutable metadata at serialization.
- RFC 8709 Ed448 uses exact 57-byte public keys and 114-byte signatures, remains explicit rather
  than default, and is validated with RFC 8032 vectors. Use the portable curve primitive for core
  operations so Bun tests remain meaningful; verify private seeds derive their claimed public keys,
  and validate PKCS#8/SPKI conversion in native Node.
- RFC 8709 Ed25519 public keys are exactly 32 octets and signatures are exactly 64 octets. Validate
  fixed wire widths at construction and parsing boundaries, verify that private seeds derive their
  claimed public keys, and copy caller-owned key storage.
- RFC 4253 DSS is legacy opt-in only: enforce 1024-bit `p`, 160-bit `q`, canonical positive mpints,
  prime and subgroup checks, matching private/public values, SHA-1, and fixed 20-byte `r` plus
  20-byte `s`. Validate the RFC 6979 vector and both signing roles with OpenSSH. Keep DSS, SHA-1 key
  exchange/signatures, CBC/3DES, and MD5/SHA-1 MACs out of every default offer while retaining
  explicit configuration paths.
- RFC 4418 UMAC derives its AES-128 subkeys once per traffic key, uses the SSH uint64 encoding of
  the uint32 packet sequence as its nonce, and must reject nonce reuse before wrap. Cover every
  universal-hash layer with the RFC vectors, including verified erratum 3507, and exercise all four
  deployed ordinary/ETM variants with the system SSH client.
- Direct client private-key authentication parses key objects or encoded containers during
  construction, rejects ambiguous agent configuration, and removes encoded keys and passphrases
  from retained client options. Keep multi-key in-memory signing in `PrivateKeyAgent`, and validate
  the direct option against real OpenSSH without password fallback.
- Server host-key inputs accept parsed private keys, encoded containers, and explicit per-key
  passphrases. Parse them eagerly, reject public keys and ambiguous passphrases, retain only parsed
  private-key objects, and validate encrypted input through a real OpenSSH client connection.
- Private-key PEM import delegates PKCS#8, PKCS#1, SEC1, and their encrypted forms to Node's native
  parser, then converts only Ed25519, Ed448, RSA, and the three RFC 5656 ECDSA curves into validated SSH
  key objects. Reject unsupported families and prove every accepted container with OpenSSL input,
  signing, OpenSSH serialization, and `ssh-keygen` public-key derivation.
- Unified key parsing must route by explicit container framing rather than exception-driven parser
  fallback. Public PEM import accepts only Ed25519, Ed448, RSA, and the three RFC 5656 ECDSA curves;
  validate converted keys through signing and real `ssh-keygen` fingerprinting.
- Certificate public keys preserve the exact signed wire prefix, expose serials and validity times
  as `bigint`, reject certificate CA keys and malformed option ordering, and verify the CA signature
  separately from application authorization. Callers must still enforce role, time, principals,
  trusted CA policy, and every critical option before accepting a certificate.
- Certificate option and extension names are fatal UTF-8 and strictly increase by their encoded
  wire bytes, not JavaScript UTF-16 ordering; reject duplicates while preserving opaque values.
- Support the standard SSH certificate key types as explicit algorithms, including Ed448 and RSA
  SHA-2 certificate names, without adding draft-only names to interoperable default offers.
- Exercise standard certificate types in both host and user authentication. Certificate request
  names wrap the underlying signature name, and awaited policy still owns CA/principal trust.
- Certificate user authentication pairs the issued public certificate with its underlying private
  key, negotiates certificate key names while encoding the underlying signature name, and verifies
  possession before awaited policy. Reject invalid CA signatures, non-user roles, and expired or
  not-yet-valid certificates before policy; leave CA trust, principals, critical options, and
  restriction composition to the hook. Validate both peer roles with OpenSSH.
- Certificate host authentication offers the certificate only when it is paired with the matching
  private host key, retains the plain-key fallback, and uses underlying signature names in the key
  exchange reply. Before awaited host policy, verify possession, CA signature, host role, and time;
  leave CA trust and hostname/address principal matching to the hook. Validate both host roles with
  OpenSSH.
- User authentication follows RFC 4252 and RFC 4256. Decode method-specific opcode 60 from the
  active authentication context, never as a globally fixed packet. Honor advertised continuation
  lists and partial success, and await application method selection without permitting an
  unconfigured, already-failed, or unadvertised choice. Keep at most one keyboard-interactive
  request outstanding, and test prompts, banners, and password changes with fixed vectors plus
  OpenSSH.
- Authentication reply envelopes validate algorithm fields as SSH names and snapshot caller-owned
  metadata. Preserve advertised failure method order and repetitions exactly so multi-step method
  selection follows the peer's wire message.
- Snapshot banner, password-change, and keyboard-interactive packet metadata, including nested
  prompt objects and response arrays. Revalidate mutable public packet fields when serializing.
- Authentication method constructors snapshot password and keyboard-interactive metadata before a
  request retains them. Keep the deliberate signature slot mutable only where signing occurs after
  the public-key request envelope is assembled.
- An awaited client keyboard-interactive hook enables that method only when the caller did not
  provide an explicit authentication order. Resolve this at connect time without mutating retained
  options; explicit orders remain strict allow-lists across every partial-success stage.
- Enforce higher-layer phases before parsing method-specific payloads: authentication packets are
  valid only during the negotiated authentication phase and only in their assigned peer direction;
  connection packets are valid only after authentication. Reject cross-phase traffic with reason 2
  while continuing to permit transport diagnostics and key exchange.
- `Client.canConnect` promises reuse after `close`. Preserve configuration, event listeners, and
  hooks across connections, but reset every transport parser, sequence, negotiated algorithm,
  secret, extension, authentication continuation, channel, and forwarding field before opening the
  next socket. Treat an injected `sock` as a one-connection transport and reject concurrent setup.
- RFC 4252 host-based authentication signs the session identifier and complete request fields,
  including the claimed client hostname and username. Verify that signature before invoking the
  awaited server policy hook; the hook must separately authorize the target user, host key,
  hostname, client user, and observed peer address. Validate with a fixed signature preimage,
  invalid-signature rejection, and real OpenSSH machine keys in both roles.
- Host-bound public-key authentication is selected only for an exact
  `publickey-hostbound@openssh.com` version-0 advertisement. Include the exact negotiated server
  host-key blob in the signed request, reject mismatches before application policy, expose the
  binding through the existing awaited public-key hook, and validate the preimage with literal
  bytes plus OpenSSH in both roles.
- Host-key rotation announcements are untrusted until every returned proof signature is checked
  over the extension name, current session identifier, and exact public-key blob. Emit only verified
  keys, never treat rotation as a substitute for authenticating the initial host key, and cover the
  preimage with independently written bytes plus a real OpenSSH server.
- SFTP follows revision 3 of `draft-ietf-secsh-filexfer-02`, matching OpenSSH. Preserve uint64
  values as `bigint`, treat paths and handles as opaque bytes in the wire layer, bound messages to
  256 KiB and handles to 256 bytes, and test codecs with independently written vectors. Keep
  OpenSSH extensions separate and gate every request on the advertised extension version. Validate
  status messages as UTF-8, status language tags with the shared language codec, and extension
  identifiers as SSH names without applying text decoding to filename or payload bytes. Path-return
  helpers default to fatal UTF-8 but must offer an explicit owned-Buffer result for binary names.
  Validate string paths and extension text before writing; Buffer paths remain byte-exact.
- Derive OpenSSH SFTP extension layouts and response types from upstream `PROTOCOL`; automatically
  negotiate advertised `limits@openssh.com` v1, retain exact limit values as `bigint`, and keep
  conservative sizes when the server rejects the request. Never accept a malformed successful
  limits reply as a downgrade.
- Generic SFTP application extensions must be advertised before the client sends them. Copy opaque
  request data, optionally gate an exact version, require callers to declare every accepted success
  response type, and treat an undeclared successful type as a fatal protocol mismatch. Exercise the
  client against the server's awaited `EXTENDED` hook as well as literal frames.
- Keep high-level SFTP transfers within negotiated request sizes. Parallel workers must stop
  scheduling after the first error but settle every in-flight operation before closing handles;
  preserve the primary operation error if cleanup also fails.
- SFTP streams use absolute uint64 offsets and Node stream backpressure. Complete each writable
  callback only after its remote write, treat range ends as inclusive, close handles exactly once,
  and make `autoClose: false` transfer handle ownership to the caller on natural completion.
- Keep the SFTP wire codec's attribute representation plain and exact. Add client ergonomics by
  wrapping responses in `SFTPStats`; derive file types only from the POSIX type mask and never
  coerce uint64 sizes away from `bigint`.
- SFTP truncation is an exact size-only `SETSTAT` or `FSETSTAT` request. Accept safe non-negative
  numbers or uint64 bigints, reject invalid lengths before allocating a request id, and route the
  server operation through the ordinary awaited request hook.
- Implement vendor extensions from their upstream protocol documents (for example OpenSSH's
  `PROTOCOL`), and keep them explicitly named and separately tested from RFC behavior.
- Treat OpenSSH's `no-more-sessions@openssh.com` request as irreversible. Existing sessions remain
  usable, later session opens bypass application policy and fail, and an incoming SSH disconnect
  must close the transport so pending channel and global-request promises settle.
- Treat `eow@openssh.com` as a one-way session writable-half close, not EOF or CLOSE. Validate its
  empty arguments and false reply flag, await the dedicated hook before changing state, stop
  outbound writes while retaining the readable half, deduplicate it, and capability-gate sends to
  identified OpenSSH peers unless callers explicitly override detection.
- RFC 4254 session exit results are one-way and singular. Accept `exit-status` and `exit-signal`
  only on session channels with a false reply flag; validate signal names, fatal UTF-8 decoding,
  RFC 3066 language tags, and complete framing before publishing any exit metadata. Validate local
  exit-signal diagnostic text before sending the result.
- Channel data, extended data, open arguments, and request arguments are opaque owned buffers.
  Packet construction and parsing must not leave them aliased to caller or transport-frame storage.
- Channel open results own type-specific reply bytes, and every scalar channel-control packet
  snapshots its constructor metadata before queuing or asynchronous observation.
- Global-request arguments and successful-response payloads follow the same owned-buffer rule;
  asynchronous request matching must never depend on mutable caller or parser-frame storage.
- Parse SSH boolean fields as false only for zero; accept every nonzero byte as true, while emitting
  canonical zero and one values for local booleans.
- Preserve name-list order and repeated entries exactly. RFC 4251 permits repeated names; reject
  only malformed names and framing, not duplicates.
- Treat KEXINIT as a fixed-layout packet: require its 16-byte cookie, all eight non-empty algorithm
  lists, zero reserved field, and no trailing data before publishing an offer.
- KEXINIT owns its cookie and copies every algorithm and language list during construction and
  parsing. Configuration arrays and transport frames must not alias a queued or published offer.
- Scalar transport, service, and group-exchange request packets snapshot constructor metadata.
  Zero-field protocol markers reject stray fields instead of silently retaining or ignoring them.
- Snapshot outbound KEXINIT payloads where they are written and hash those exact immutable bytes in
  every key-exchange method; never reconstruct a transcript from a mutable packet object. Keep the
  stored snapshot runtime-private, return copies to observers, and bind capture to the active offer.
- Copy inbound KEXINIT payloads before publishing packet events and reparse the private snapshot for
  negotiation. Event-visible packet objects and payload copies must never alias transcript state.
- Keep the first exchange hash as a runtime-private session identifier and return only defensive
  copies. Authentication proofs and every rekey must continue using the original internal bytes.
- Disk-backed identity discovery and direct lookup use the same whitespace-tolerant public-key
  parser, including multiword comments. Normalize the configured directory and await diagnostics
  for malformed skipped identities.
- Decode textual public-key blobs with strict canonical standard base64. Permit canonical omitted
  trailing padding, but reject ignored characters, misplaced padding, invalid lengths, and pad bits.
- RFC 9987 agent identity comments use fatal UTF-8 decoding. Reject malformed response text rather
  than publishing replacement characters, while continuing to skip unsupported key algorithms.
- Enforce the fixed one-byte payload of RFC 9987 generic agent failure replies; never treat trailing
  fields on `SSH_AGENT_FAILURE` as an ordinary refusal.
- Validate KEXINIT language preference entries as RFC 3066 tags, not algorithm identifiers. Preserve
  list order and repeats without imposing the 64-byte algorithm-name limit.
- Packet tunnel channels use the `tun@openssh.com` layout from upstream `PROTOCOL`. Preserve each
  IP datagram or Ethernet frame in exactly one channel-data message, wait asynchronously for enough
  remote window rather than splitting it, and validate mode-specific framing before emitting data.
- SSH keepalives use reply-requesting `keepalive@openssh.com` global requests. Count both success
  and failure as liveness, bound consecutive unanswered requests, unref timers, and clear them on
  every connection shutdown path. Server configuration creates independent timers and failure
  counters for each authenticated client; timing out one peer must not affect the listener or its
  other connections.
- Unknown RFC 4254 global requests are deny-by-default async `Hooker` policy surfaces on both peer
  roles. Copy opaque arguments into the hook context, serialize handlers to preserve reply order,
  require Buffer success payloads, invoke one-way notifications without replying, and settle every
  outbound client or server request on reply or close. Queue outbound requests across rekey and
  keep built-in requests on their dedicated validation paths. Treat success or failure replies
  without a pending request as protocol errors in both roles.
- Transport ping uses negotiated `ping@openssh.com` version 0 and opcodes 192/193 with an opaque
  echoed string. Never send it without the RFC 8308 advertisement, preserve FIFO reply ordering,
  reject mismatched echoes, settle pending calls on close, and queue pings and pongs across rekey.
  Cover its codec with literal vectors and keep older OpenSSH peers as a negative negotiation case.
- RFC 8308 client EXT_INFO is valid only immediately after the client's first NEWKEYS. Server
  EXT_INFO is valid immediately after its first NEWKEYS and immediately before USERAUTH_SUCCESS;
  the second set replaces the first. Preserve unknown binary values, expose deep-copied complete
  sets in both roles, clear omitted capabilities on replacement, and reject messages elsewhere.
- Client readiness deadlines cover TCP connection, identification, key exchange, and
  authentication, including supplied duplex transports. Clear the timer on authentication and
  every terminal path; test expiry against a real silent TCP peer rather than a mocked transport.
- Host verification runs only after the exchange-hash signature is cryptographically valid and
  before `NEWKEYS`. Pass the exact serialized host-key blob (or the requested Node hash as lowercase
  hex), honor synchronous and promised decisions once, and reverify the key on every rekey. Use a
  real OpenSSH host key to prove the public verifier contract.
- Identification compatibility options must still pass through the RFC 4253 validator. Preserve
  greeting bytes and line endings until the peer identifier arrives, emit the combined greeting
  once, and retain the existing per-line observability events. Normalize configured server
  greetings to CRLF and reject values that could be mistaken for an SSH identification.
- OpenSSH-only client requests are vendor-gated by default from the authenticated peer's validated
  identification. Apply the same gate to all Promise APIs, allow an explicit compatibility
  override, and prove rejection before a request reaches a non-OpenSSH server.
- RFC 4253 rekeying preserves the first exchange hash as the session identifier while deriving all
  new transport keys from the current exchange hash. Queue application output after sending
  `KEXINIT`, switch each direction exactly at its own `NEWKEYS`, preserve sequence numbers and open
  channels, and test both initiator roles against OpenSSH. Honor rekey initiation after the initial
  exchange during service negotiation and authentication as well as after login.
- After receiving a peer's `KEXINIT`, accept only RFC 4253 generic transport messages other than
  service messages, algorithm negotiation, and method-specific key-exchange messages until that
  peer sends `NEWKEYS`. Preserve the separate allowance for application packets already in flight
  before the peer's `KEXINIT` arrives.
- Accept `NEWKEYS` and method-specific key-exchange messages only while an exchange is active.
  Reject late or unsolicited exchange packets with an RFC protocol-error disconnect before parsing
  their method-specific payload or changing packet protection.
- Track inbound NEWKEYS readiness independently of whether local NEWKEYS was sent: RFC directions
  may switch in either order. Reset readiness at each exchange, enable it only after deriving fresh
  inbound keys and protection objects with a validated compression selection, and consume it on the
  first peer NEWKEYS so premature and duplicate messages cannot install stale or undefined state.
- Model every negotiated key exchange as a single-consumption inbound packet sequence. Include both
  current and legacy group-exchange request opcodes only at the request stage, then replace the
  expected set before resuming buffered input. Reject duplicates, skipped stages, wrong-method
  opcodes, and extra KEXINIT messages with a protocol-error disconnect before method parsing.
- Honor RFC 4253 `first_kex_packet_follows`: compare both guessed KEX and host-key names with the
  negotiated pair, silently discard exactly one following packet only when either guess is wrong,
  and leave the real method-stage expectation unconsumed. Validate this in both peer directions.
- RFC 4253 unknown message numbers receive `SSH_MSG_UNIMPLEMENTED` with the rejected inbound packet
  sequence and must not stop later buffered processing. Keep malformed known packets fatal, and
  classify strict initial-KEX non-KEX traffic before this recovery path so it still disconnects.
  Cover the literal response frame, both encrypted peer directions, and a real OpenSSH peer.
- Human-readable SSH fields use fatal UTF-8 decoding and RFC 3066 ASCII language tags; never allow
  replacement decoding before authentication or policy. Apply the same strict encoder to locally
  configured identification comments and suffixes. Preserve unknown uint32 disconnect reasons so
  future and private-use assignments still produce a clean terminal disconnect.
- Configured diagnostic sinks and `debug` events receive the same semantic arguments. Route both
  through the existing redaction path; never expose passwords, prompt responses, passphrases,
  private key inputs, derived secrets, or transport keys in either surface.
- RFC 4253 service negotiation is a single exact request/accept exchange after initial key
  exchange. Reject unavailable services with reason 7 and wrong-role, mismatched, premature, or
  repeated service messages with reason 2; keep transport and rekey traffic transparent to the
  outstanding negotiation.
- User-authentication request envelopes use fatal UTF-8 usernames and strict SSH service/method
  names, copy caller metadata and unknown payload bytes, and revalidate mutable text when serialized.
- Preserve all inbound RFC 4253 debug fields in an immutable semantic event. Copy outbound ignore
  bytes at the API boundary, keep ignore payloads semantically opaque, and queue both debug and
  ignore messages across key exchange so they cannot violate strict-KEX ordering. Transport-level
  messages must not disrupt service or multi-round authentication waits, and KEX completion events
  must run only after outbound traffic has stopped targeting the exchange queue.
- Publish inbound RFC 4253 disconnect metadata immutably before close in both roles. Reject every
  active packet wait and pending operation with the typed peer-disconnect error; clean socket closes
  without a protocol message retain contextual ordinary errors and must never leave setup hanging.
- RFC 4250 names are 1-to-64-byte printable US-ASCII values without commas. Validate the single
  at-sign plus domain form for local extensions, reject empty and duplicate name-list entries, and
  apply the shared codec to services, methods, algorithms, extensions, channels, requests, and
  subsystems on both parse and serialization paths.
- Ordinary and host-bound public-key authentication use the strict SSH-name codec for their
  signature algorithm field and copy caller-owned method metadata before retaining it.
- Host-based authentication applies the same strict algorithm codec and metadata isolation, and
  maps certificate request names to their underlying signature algorithm.
- Public and private key envelopes bind their validated SSH algorithm name to the contained key
  implementation, require private/public identity agreement, and copy caller-owned envelope data.
- Key comments use fatal UTF-8, exclude NUL and line endings on every construction and parse path,
  and are revalidated at serialization because key metadata remains intentionally mutable.
- Strict key exchange advertises both the standard and deployed marker pairs only in the initial
  KEXINIT. Enable it only for a matching pair, require the peer's initial KEXINIT at sequence zero,
  reject any pre-completion sequence wrap, reject non-KEX and duplicate KEX messages during that
  exchange, and reset each direction's implicit sequence number immediately after every NEWKEYS.
  Validate with fixed negotiation and counter tests plus OpenSSH in both roles.
- RFC 4253 algorithm negotiation follows the client's name-list order independently for every
  category and direction. Clear all prior selections before each exchange, reject missing overlap
  instead of retaining rekey state, and validate supported compression explicitly.
- Algorithm configuration resolves once per client or server without mutating global registries,
  rejects unsupported names and empty offers, preserves exact preference order, filters server host
  key offers to keys actually present, and remains stable across rekeys. Reject malformed modifier
  objects and matcher values at construction instead of silently retaining defaults.
- Emit negotiated handshake details only after inbound and outbound NEWKEYS are active. Report both
  directions on initial exchange and rekey, and emit `handshake` before the corresponding `rekey`.
- RFC 8731 Curve25519 messages use raw 32-byte SSH strings for ephemeral public keys, not mpints.
  Method-specific KEX packets own ephemeral public values, host-key blobs, and signatures on both
  construction and parsing paths; exchange verification must not alias external frame storage.
  DH and ECDH public-key getters and shared-secret results return defensive buffers; never expose
  mutable internal state that will later feed the exchange hash or key derivation.
  Interpret the X25519 output as a network-order unsigned integer only when encoding the shared
  secret mpint, reject incorrect point lengths and all-zero secrets, and validate with RFC 7748
  vectors plus OpenSSH in both peer roles.
- RFC 5656 ECDH messages use SEC1-encoded point strings and the shared point's x-coordinate as the
  secret mpint. Validate received points on the negotiated curve, select SHA-256/384/512 by curve
  size, and cover every required NIST curve with RFC 5903 vectors plus both OpenSSH peer roles.
- RFC 4419 group exchange uses KEX-specific opcodes 30 through 34 and includes the requested sizes,
  p, and g in its distinct exchange hash. The legacy opcode 30 hashes only its single preferred
  size. Enforce RFC 8270's 2048-to-8192-bit range, accept only canonical positive mpints and
  safe-prime groups, validate public values and shared secrets against p, and cover both hash
  variants with fixed frames plus OpenSSH in both roles across rekey. Copy staged host-key and peer
  public-value buffers before retaining them for the final hash. Keep SHA-1 last.
- RFC 4432 `rsa2048-sha256` uses a fresh server-only transient RSA key, SHA-256 RSAES-OAEP over the
  complete shared-secret mpint, and its distinct opcode 30/31/32 flow and exchange hash. Enforce the
  2048-bit transient minimum, discard the private-key reference after decryption, disconnect on OAEP
  failure, and keep this non-forward-secret RFC 9142 MAY method outside defaults. Cover exact frames,
  an independent hash vector, malformed keys, and rekey from both initiator roles.
- RFC 5656 ECDSA host keys preserve their SEC1 point encoding in the serialized key blob, validate
  points before use, encode signatures as canonical positive `r` and `s` mpints, and select
  SHA-256/384/512 by curve size. Cover every required NIST curve with authoritative fixed vectors
  plus OpenSSH host-key and rekey tests in both peer roles.
- RFC 6668 HMAC-SHA-2 authenticates the RFC 4253 sequence number followed by the plaintext packet
  and uses the full digest. OpenSSH ETM leaves the packet length clear, encrypts the packet body,
  authenticates sequence number plus clear length plus ciphertext, and must verify the tag before
  decrypting. Keep ETM padding aligned to the encrypted body rather than the clear length.
- RFC 4253 `hmac-sha1-96` computes the complete HMAC-SHA1 over sequence number plus packet, then
  truncates it to the first 12 bytes. Its ETM form authenticates the clear length plus ciphertext
  and verifies before decryption. Keep both behind stronger choices and validate them with RFC 2202
  bytes plus OpenSSH in both peer roles across rekey.
- RFC 4253 HMAC-MD5 uses a 16-byte key and either its full 16-byte digest or the first 12 bytes for
  the `-96` method. Apply the same truncation only after computing the complete digest in ETM mode,
  keep every MD5 method last for explicit legacy compatibility, and validate RFC 2202 bytes plus
  OpenSSH in both peer roles across rekey.
- RFC 5647 AES-GCM leaves the four-byte packet length clear as authenticated data, encrypts the
  block-aligned body, appends the full 16-byte tag, and uses no separate MAC key. Treat the IV's
  trailing eight bytes as a per-packet invocation counter, never permit it to wrap, and validate
  with authoritative primitive vectors plus OpenSSH in both roles across rekey.
- OpenSSH ChaCha20-Poly1305 uses the first 32 derived key bytes for payload encryption and Poly1305
  key generation and the second 32 bytes for independent length encryption. Use the uint64-encoded
  packet sequence as nonce, authenticate encrypted length plus body before decrypting the body,
  reject nonce reuse, and cover the primitives with RFC 8439 vectors plus both peer roles.
- RFC 4253 zlib compression is stateful per direction, applies only to the payload, uses a partial
  flush at every packet boundary, and resets at that direction's NEWKEYS. Delayed zlib activates
  only after USERAUTH_SUCCESS but starts immediately on later authenticated rekeys. Bound expanded
  payloads and cover immediate mode independently plus delayed mode with both OpenSSH peer roles.
- RFC 4253 CBC encryption is stateful across packet boundaries and uses SSH packet padding without
  cipher-level padding. Preserve chaining when the decoder decrypts the first block before the
  packet remainder, reset each direction only with its newly derived key and IV at NEWKEYS, and
  require a separately negotiated MAC. Keep CBC ciphers behind modern choices and validate them
  with independent fixed vectors plus OpenSSH in both roles across rekey.
- RFC 8332 RSA SHA-2 keeps the serialized public-key format as `ssh-rsa` while negotiating and
  encoding `rsa-sha2-256` or `rsa-sha2-512` signatures. Advertise user-auth signature support with
  RFC 8308 `server-sig-algs`, and validate both host and user signatures against OpenSSH.
- Use `Hooker` for application request and policy surfaces whose handlers may need asynchronous
  work. Await hooks before sending protocol success or failure; reserve `EventEmitter` for
  observation and stream-style notifications that do not control a reply.
- Runtime session controls such as `window-change` and `signal` are one-way RFC notifications, but
  adapters may still require ordered asynchronous work. Await their Hooker handlers before emitting
  observation events or processing the next channel request, and reject an invalid reply request.
- Generic channel requests use awaited, deny-by-default hooks and FIFO reply matching. Copy opaque
  request arguments before exposing them, invoke one-way notifications without replying, reject
  pending outbound requests when a channel closes, and suppress replies from handlers that finish
  after close. Validate both peer roles with OpenSSH.
- Reserve each peer channel identifier before asynchronous open policy and across the full
  bidirectional CLOSE handshake. Reject active reuse with an RFC protocol-error disconnect, release
  rejected and fully closed identifiers, and keep fatal behavior independent of TCP fragmentation
  or coalescing by sharing the direct and deferred packet-processing error path. Settle every
  channel open exactly once; a confirmation followed by a failure (or the reverse) is fatal in both
  roles and must not silently remove an established channel.
- Classify established-channel wire violations separately from local stream and application
  failures. Send reason-code 2 for window overflow, data beyond window or EOF, oversized channel
  packets, duplicate results, and unexpected replies in both roles; accept a zero window adjustment
  as the RFC-compatible no-op that it is.
- Bound server authentication with an absolute post-service deadline and a rejected-request
  ceiling. Do not count `none`, intermediate challenge messages, or `partialSuccess`; after expiry,
  an awaited policy hook must not admit the client. Clear and unref deadline timers, and flush the
  RFC disconnect packet before closing the transport.
- After awaited preconnect admission, bound every accepted server socket through identification,
  initial key exchange, and exact user-auth service acceptance with a separate unreferenced
  handshake timer. Clear it before authentication policy begins, clear it on all terminal paths,
  and destroy silent pre-identification peers because binary disconnect framing is not yet
  available.
- High-level session helpers must issue setup requests before the program request: agent forwarding,
  environment, PTY, X11, then exec/shell/subsystem. Treat automatic environment requests as
  best-effort without replies, but require replies for security- or terminal-sensitive setup.
  Decode command, terminal, and environment text fatally before awaited policy hooks, and validate
  outbound JavaScript strings before serializing a request.
- Keep the public RFC 4254 terminal-mode registry complete and numerically exact. Named constants
  are conveniences, not a closed-world parser: accept future opcodes 1 through 159, preserve them in
  the server's mode map, validate uint32 values, and always append the terminal end marker.
- RFC 4335 BREAK requests are valid only for a started session program and require an awaited,
  deny-by-default policy decision after the application performs the operation. Preserve the uint32
  requested duration, document the RFC's safe 500-to-3000 ms guidance, and treat console BREAK as
  privileged. RFC 4254 `xon-xoff` travels only from server to client and must never request a reply.
- Injected server sockets must pass through the same `preconnect`, client tracking, authentication,
  error cleanup, and close cleanup as listener-accepted sockets. Keep ownership of the outer
  listener with the injector and ownership of the connected socket with `ServerClient`.
- Graceful shutdown is symmetric: `Client.end()` and `ServerClient.end()` must send an RFC 4253
  `BY_APPLICATION` disconnect before ending their transports. Reserve immediate destruction for
  `destroy()`/`terminate()` and explicit protocol failures for `disconnect(error)`.
- A client-supplied duplex transport is already connected and is owned by the `Client` after
  `connect()`. Apply the same data/error/close cleanup as TCP sockets, never wait for a synthetic
  `connect` event, reject destroyed transports, and validate hopping through a real SSH channel.
- Direct client TCP options must reach Node's real socket connection: preserve explicit source
  address and port bindings, apply an address-family restriction only when exactly one force flag
  is set, and ignore all direct-connect options for supplied transports.
- HTTP(S) agents create each pooled socket through an authenticated RFC 4254 `direct-tcpip` channel.
  Treat configured source addresses as originator metadata rather than local binds, retain TLS
  end-to-end for HTTPS, close each owned SSH client with its channel or agent, and exercise the
  packaged API through Node's real HTTP client against OpenSSH.
- Treat local and remote channel identifiers, windows, maximum packet sizes, EOF, and CLOSE state as
  independent protocol state. All channel streams must preserve bounded backpressure.
- New public APIs and public types must be exported from `src/index.ts`, documented under `docs/`,
  exercised through the packed ESM entry point when relevant, and free of import-time side effects.
- Deny security-sensitive forwarding and server-initiated behavior by default. Require explicit
  policy hooks and document the trust boundary. Decode forwarding addresses and stream-local paths
  with the fatal UTF-8 codec before authorization or lookup; never allow replacement decoding to
  change a peer-supplied policy key.
- Agent forwarding requires a successful per-session request before accepting or opening agent
  channels. Test both directions with a real OpenSSH agent and document its transitive trust risk.
- X11 forwarding authorization is session-scoped. Enforce single-connection consumption, remove
  unused authorization when the session closes, and test OpenSSH cookie substitution end to end.
- Scope remote-forwarding TCP and UNIX-socket listeners to the authenticated connection that
  requested them. Stop accepting immediately on cancellation and close every owned listener on SSH
  disconnect. Never unlink a pre-existing UNIX-socket path on the client's behalf.
- Server-initiated forwarded TCP and stream-local channels must match a currently accepted request
  on that authenticated connection. Preserve all RFC source/destination metadata, expose bounded
  channel streams, and reject explicit opens immediately after cancellation.
- Do not add temporary compatibility shims, test-only production branches, or silent protocol
  fallbacks. Fail malformed or out-of-order protocol input explicitly.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects: `feat:`, `fix:`, `test:`, and `chore:`.
Keep subjects imperative and scoped to one logical change. Pull requests should explain the
behavior and motivation, link relevant issues or RFC sections, identify compatibility impact, and
list validation performed. Update `docs/` or the interoperability matrix when public behavior
changes; screenshots are generally unnecessary for this library.
