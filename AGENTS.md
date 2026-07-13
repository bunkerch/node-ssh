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
`sshd` fixture), not `ssh2`; `ssh2` is the feature-parity reference, not the protocol oracle. Keep
external-process assertions deterministic and suppress incidental client logging. No numeric
coverage threshold is configured; prioritize focused regression tests and meaningful wire-level
behavior.

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
- Do not add temporary compatibility shims, test-only production branches, or silent protocol
  fallbacks. Fail malformed or out-of-order protocol input explicitly.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects: `feat:`, `fix:`, `test:`, and `chore:`.
Keep subjects imperative and scoped to one logical change. Pull requests should explain the
behavior and motivation, link relevant issues or RFC sections, identify compatibility impact, and
list validation performed. Update `docs/` or the interoperability matrix when public behavior
changes; screenshots are generally unnecessary for this library.
