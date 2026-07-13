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

- Implement behavior from the RFCs in `../rfcs`; fetch missing RFCs from an authoritative source
  when needed.
- The SSH agent client follows RFC 9987. Keep its framing bounded to OpenSSH's 256 KiB limit and
  validate it with fixed frames plus the system `ssh-agent`, never another JavaScript SSH library.
- OpenSSH private-key encryption follows upstream `PROTOCOL.key`. Keep passphrase and derived-key
  buffers short-lived, validate authenticated modes before parsing plaintext, compare the public
  envelope with the private key, and exercise every supported cipher with real `ssh-keygen` output.
- User authentication follows RFC 4252 and RFC 4256. Decode method-specific opcode 60 from the
  active authentication context, never as a globally fixed packet. Honor advertised continuation
  lists and partial success, keep at most one keyboard-interactive request outstanding, and test
  prompts, banners, and password changes with fixed vectors plus OpenSSH.
- RFC 4252 host-based authentication signs the session identifier and complete request fields,
  including the claimed client hostname and username. Verify that signature before invoking the
  awaited server policy hook; the hook must separately authorize the target user, host key,
  hostname, client user, and observed peer address. Validate with a fixed signature preimage,
  invalid-signature rejection, and real OpenSSH machine keys in both roles.
- Host-key rotation announcements are untrusted until every returned proof signature is checked
  over the extension name, current session identifier, and exact public-key blob. Emit only verified
  keys, never treat rotation as a substitute for authenticating the initial host key, and cover the
  preimage with independently written bytes plus a real OpenSSH server.
- SFTP follows revision 3 of `draft-ietf-secsh-filexfer-02`, matching OpenSSH. Preserve uint64
  values as `bigint`, treat paths and handles as opaque bytes in the wire layer, bound messages to
  256 KiB and handles to 256 bytes, and test codecs with independently written vectors. Keep
  OpenSSH extensions separate and gate every request on the advertised extension version.
- Derive OpenSSH SFTP extension layouts and response types from upstream `PROTOCOL`; automatically
  negotiate advertised `limits@openssh.com` v1, retain exact limit values as `bigint`, and keep
  conservative sizes when the server rejects the request. Never accept a malformed successful
  limits reply as a downgrade.
- Keep high-level SFTP transfers within negotiated request sizes. Parallel workers must stop
  scheduling after the first error but settle every in-flight operation before closing handles;
  preserve the primary operation error if cleanup also fails.
- SFTP streams use absolute uint64 offsets and Node stream backpressure. Complete each writable
  callback only after its remote write, treat range ends as inclusive, close handles exactly once,
  and make `autoClose: false` transfer handle ownership to the caller on natural completion.
- Keep the SFTP wire codec's attribute representation plain and exact. Add client ergonomics by
  wrapping responses in `SFTPStats`; derive file types only from the POSIX type mask and never
  coerce uint64 sizes away from `bigint`.
- Implement vendor extensions from their upstream protocol documents (for example OpenSSH's
  `PROTOCOL`), and keep them explicitly named and separately tested from RFC behavior.
- Treat OpenSSH's `no-more-sessions@openssh.com` request as irreversible. Existing sessions remain
  usable, later session opens bypass application policy and fail, and an incoming SSH disconnect
  must close the transport so pending channel and global-request promises settle.
- SSH keepalives use reply-requesting `keepalive@openssh.com` global requests. Count both success
  and failure as liveness, bound consecutive unanswered requests, unref timers, and clear them on
  every connection shutdown path.
- Unknown RFC 4254 global requests are deny-by-default async `Hooker` policy surfaces on both peer
  roles. Copy opaque arguments into the hook context, serialize handlers to preserve reply order,
  require Buffer success payloads, invoke one-way notifications without replying, and settle every
  outbound request on reply or close. Keep built-in requests on their dedicated validation paths.
- Transport ping uses negotiated `ping@openssh.com` version 0 and opcodes 192/193 with an opaque
  echoed string. Never send it without the RFC 8308 advertisement, preserve FIFO reply ordering,
  reject mismatched echoes, settle pending calls on close, and queue pings and pongs across rekey.
  Cover its codec with literal vectors and keep older OpenSSH peers as a negative negotiation case.
- Client readiness deadlines cover TCP connection, identification, key exchange, and
  authentication, including supplied duplex transports. Clear the timer on authentication and
  every terminal path; test expiry against a real silent TCP peer rather than a mocked transport.
- Host verification runs only after the exchange-hash signature is cryptographically valid and
  before `NEWKEYS`. Pass the exact serialized host-key blob (or the requested Node hash as lowercase
  hex), honor synchronous and callback decisions once, and reverify the key on every rekey. Use a
  real OpenSSH host key to prove the public verifier contract.
- Identification compatibility options must still pass through the RFC 4253 validator. Preserve
  greeting bytes and line endings until the peer identifier arrives, emit the combined greeting
  once, and retain the existing per-line observability events. Normalize configured server
  greetings to CRLF and reject values that could be mistaken for an SSH identification.
- OpenSSH-only client requests are vendor-gated by default from the authenticated peer's validated
  identification. Apply the same gate to promise and callback APIs, allow an explicit compatibility
  override, and prove rejection before a request reaches a non-OpenSSH server.
- RFC 4253 rekeying preserves the first exchange hash as the session identifier while deriving all
  new transport keys from the current exchange hash. Queue application output after sending
  `KEXINIT`, switch each direction exactly at its own `NEWKEYS`, preserve sequence numbers and open
  channels, and test both initiator roles against OpenSSH.
- Strict key exchange advertises both the standard and deployed marker pairs only in the initial
  KEXINIT. Enable it only for a matching pair, require the peer's initial KEXINIT at sequence zero,
  reject non-KEX and duplicate KEX messages during that exchange, and reset each direction's
  implicit sequence number immediately after every NEWKEYS. Validate with fixed negotiation and
  counter tests plus OpenSSH in both roles.
- RFC 4253 algorithm negotiation follows the client's name-list order independently for every
  category and direction. Clear all prior selections before each exchange, reject missing overlap
  instead of retaining rekey state, and validate supported compression explicitly.
- Algorithm configuration resolves once per client or server without mutating global registries,
  rejects unsupported names and empty offers, preserves exact preference order, filters server host
  key offers to keys actually present, and remains stable across rekeys.
- Emit negotiated handshake details only after inbound and outbound NEWKEYS are active. Report both
  directions on initial exchange and rekey, and emit `handshake` before the corresponding `rekey`.
- RFC 8731 Curve25519 messages use raw 32-byte SSH strings for ephemeral public keys, not mpints.
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
  variants with fixed frames plus OpenSSH in both roles across rekey. Keep SHA-1 last.
- RFC 5656 ECDSA host keys preserve their SEC1 point encoding in the serialized key blob, validate
  points before use, encode signatures as canonical positive `r` and `s` mpints, and select
  SHA-256/384/512 by curve size. Cover every required NIST curve with authoritative fixed vectors
  plus OpenSSH host-key and rekey tests in both peer roles.
- RFC 6668 HMAC-SHA-2 authenticates the RFC 4253 sequence number followed by the plaintext packet
  and uses the full digest. OpenSSH ETM leaves the packet length clear, encrypts the packet body,
  authenticates sequence number plus clear length plus ciphertext, and must verify the tag before
  decrypting. Keep ETM padding aligned to the encrypted body rather than the clear length.
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
- Bound server authentication with an absolute post-service deadline and a rejected-request
  ceiling. Do not count `none`, intermediate challenge messages, or `partialSuccess`; after expiry,
  an awaited policy hook must not admit the client. Clear and unref deadline timers, and flush the
  RFC disconnect packet before closing the transport.
- High-level session helpers must issue setup requests before the program request: agent forwarding,
  environment, PTY, X11, then exec/shell/subsystem. Treat automatic environment requests as
  best-effort without replies, but require replies for security- or terminal-sensitive setup.
- RFC 4335 BREAK requests are valid only for a started session program and require an awaited,
  deny-by-default policy decision after the application performs the operation. Preserve the uint32
  requested duration, document the RFC's safe 500-to-3000 ms guidance, and treat console BREAK as
  privileged. RFC 4254 `xon-xoff` travels only from server to client and must never request a reply.
- Injected server sockets must pass through the same `preconnect`, client tracking, authentication,
  error cleanup, and close cleanup as listener-accepted sockets. Keep ownership of the outer
  listener with the injector and ownership of the connected socket with `ServerClient`.
- A client-supplied duplex transport is already connected and is owned by the `Client` after
  `connect()`. Apply the same data/error/close cleanup as TCP sockets, never wait for a synthetic
  `connect` event, reject destroyed transports, and validate hopping through a real SSH channel.
- Direct client TCP options must reach Node's real socket connection: preserve explicit source
  address and port bindings, apply an address-family restriction only when exactly one force flag
  is set, and ignore all direct-connect options for supplied transports.
- Treat local and remote channel identifiers, windows, maximum packet sizes, EOF, and CLOSE state as
  independent protocol state. All channel streams must preserve bounded backpressure.
- New public APIs and public types must be exported from `src/index.ts`, documented under `docs/`,
  exercised through the packed ESM entry point when relevant, and free of import-time side effects.
- Deny security-sensitive forwarding and server-initiated behavior by default. Require explicit
  policy hooks and document the trust boundary.
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
