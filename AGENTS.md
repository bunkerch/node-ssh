# Repository Guidelines

## Project Direction

`modernssh` is a typed, ESM-native SSH client and server library for Node.js 20+. Work toward
production-ready protocol correctness, broad client/server functionality, stable public APIs, and
meaningful interoperability. Implement complete, reviewable slices; do not add shortcuts,
temporary fixes, test-only production branches, or speculative compatibility behavior.

Keep this file limited to durable project-wide practices. Feature-specific wire layouts, limits,
algorithm details, and implementation history belong in source comments, focused tests, and the
relevant file under `docs/`.

## Repository Layout

- Production TypeScript lives in `src/`.
- Protocol packets are in `src/packets/`, channels in `src/channels/`, authentication methods in
  `src/auth/`, algorithms in `src/algorithms/`, SFTP in `src/sftp/`, and shared primitives in
  `src/utils/`.
- Public exports are assembled in `src/index.ts`.
- Tests mirror the implementation under `__tests__/`, including `integration/`, `openssh/`,
  `packets/`, `transport/`, `utils/`, and `package/`.
- User-facing and protocol documentation lives in `docs/`.
- `dist/` is generated. Never edit it directly.

## Commands

- `pnpm install`: install the pinned dependencies.
- `pnpm build`: clean and compile strict TypeScript.
- `pnpm dev`: compile in watch mode.
- `pnpm test`: build and run the complete Bun suite, including OpenSSH interoperability.
- `pnpm lint`: run ESLint, including type-aware async-event checks.
- `pnpm format`: apply Prettier.
- `pnpm format:check`: verify formatting.
- `pnpm docs:api`: rebuild the generated package-root API reference from emitted declarations.
- `pnpm docs:api:check`: verify that the generated API reference matches the shipped declarations.
- `pnpm pack`: build a consumer-installable archive.

GitHub Actions jobs run on the Linux `bunkerch-sysbox` runner. Do not add Windows-hosted jobs or
Windows test matrices unless the maintainer explicitly requests them.

Before committing, run the focused tests for the change, then `pnpm build`, `pnpm lint`,
`pnpm format:check`, and `pnpm test`. Do not bypass the Husky/pre-commit checks.

## TypeScript and Code Style

- Use strict TypeScript and NodeNext ESM semantics. Relative imports include the `.js` extension.
- Prettier defines formatting: four-space indentation, double quotes, no semicolons, 100-character
  lines, and trailing commas.
- Use PascalCase for classes and their files, camelCase for functions and variables, and descriptive
  lowercase names for algorithm modules.
- Keep protocol constants and state transitions near the relevant implementation.
- Validate at public and wire boundaries instead of relying on downstream coercion or assertions.
- Copy caller- and packet-owned buffers or metadata before retaining them. Revalidate intentionally
  mutable public metadata when serializing it.
- Bound peer-controlled lengths, queues, windows, packet sizes, and decompression. Preserve stream
  backpressure.
- Never log or expose passwords, passphrases, private-key material, derived secrets, transport keys,
  prompt responses, or unredacted option objects.

## Public API and Async Model

- Public asynchronous operations are Promise-only. Do not add Node-style completion callbacks,
  callback overloads, or callback-returning aliases. Internal callbacks required by Node stream,
  socket, HTTP, or crypto interfaces are fine.
- Use `Hooker` for application policy and request handling that may perform asynchronous work.
  Trigger and await the hook before sending protocol success/failure or advancing ordered state.
  Hooks are deny-by-default where authorization or security-sensitive behavior is involved.
- `Hooker` awaits async handlers and contains rejected handlers through its
  `uncaughtException` policy. Do not replace those policy surfaces with `EventEmitter`.
- Reserve `EventEmitter` for observation and stream-style notifications. Never pass an `async`
  function directly to `on()` or `once()`; EventEmitter ignores returned promises. A synchronous
  listener that starts async work must attach explicit rejection handling and route failure back
  through the owning operation.
- For ordinary one-shot event waiting, use `once()` from `node:events` and await it. Protocol
  internals may use a direct listener bridge only when synchronous packet ordering or error
  propagation requires it and focused tests cover that behavior. Do not hand-roll event Promises
  in documentation.
- Keep normalized client and server configuration private. Do not add a public options bag that
  exposes credentials, private keys, policy handlers, or mutable transport settings; expose
  legitimate runtime state through narrow, readonly APIs instead.
- New public APIs and types must be exported from `src/index.ts`, documented in `docs/`, covered
  through the source API, and exercised through the packed ESM entry point when relevant.
- Public modules must be free of import-time side effects.

## Protocol Implementation

- Derive RFC behavior from the authoritative documents in `../rfcs`. Fetch missing RFCs from an
  authoritative source when necessary.
- Derive vendor extensions from their published upstream protocol documents and keep them clearly
  separated from standardized behavior.
- Other implementations may be inspected briefly to inventory missing features only. Do not
  mention or cite a competing JavaScript implementation in tracked source, tests, docs, commit
  rationale, or API design, and never use one as a behavioral authority.
- Preserve exact SSH phase, direction, request/reply, rekey, sequence, and channel-lifetime rules.
  Malformed, contradictory, duplicated, or out-of-order protocol input must fail explicitly.
- Use fatal UTF-8 decoding before authentication, authorization, lookup, or policy. Protocol names
  and language tags use the shared strict codecs; opaque byte fields remain opaque.
- Treat extension messages as complete negotiated sets. Exact version advertisements enable
  behavior; replacement sets clear capabilities they omit.
- Keep secure, interoperable algorithms in defaults. Legacy cryptography may remain available only
  through explicit configuration and must stay behind modern choices.
- Keep security-sensitive forwarding, server-initiated access, authentication, certificate trust,
  and similar decisions disabled until an awaited application policy explicitly approves them.
  Document the trust boundary.
- Every pending Promise must settle on success, rejection, disconnect, channel close, timeout, and
  transport failure. Rekey must preserve valid higher-layer state while correctly queueing traffic.

## Testing

- Tests use Bun's Jest-compatible `describe`, `test`, and `expect` APIs. Put them in the matching
  `__tests__/<area>/` directory.
- Cover success, failure, bounds, malformed input, state ordering, ownership/aliasing, fragmentation,
  cleanup, and reconnection where applicable.
- Packet parsing and serialization tests use fixed, independently written byte vectors from an RFC
  or protocol document. Never generate expected bytes with the codec under test.
- Cryptographic behavior uses authoritative published vectors or an independent standard primitive,
  plus negative cases. Do not use another JavaScript SSH implementation as an oracle.
- Cross-implementation tests use the system OpenSSH tools or the digest-pinned Docker fixture in
  `__tests__/openssh/Dockerfile`. Exercise both peer roles when behavior differs by role.
- Use real `ssh`, `sshd`, `ssh-keygen`, `ssh-agent`, SFTP, OpenSSL, or other authoritative
  tools when they materially validate interoperability. Keep external-process assertions
  deterministic and suppress incidental logging.
- Add in-process integration tests for async ordering, policy decisions, lifecycle cleanup, and
  exact negotiated behavior that external peers cannot isolate reliably.
- Package tests must verify the supported root ESM API, generated declarations, Promise-only
  signatures, and absence of import-time side effects.

## Documentation

- Update the relevant Markdown under `docs/` whenever public behavior changes.
- Regenerate `docs/api/` with `pnpm docs:api` whenever the package-root declaration surface changes;
  never edit generated API-reference files by hand.
- Examples use Promise APIs and awaited Hooker handlers. EventEmitter examples keep listeners
  synchronous and handle async failures explicitly.
- Event-waiting examples import `once` from `node:events`.
- Explain defaults, opt-ins, compatibility gates, lifecycle, error behavior, and security risks.
- Keep interoperability claims tied to an actual fixed-vector, integration, package, or OpenSSH
  test.
- Keep `AGENTS.md` current when project-wide workflow or design policy changes, but do not append a
  rule for every completed feature.

## Git and Delivery

- Preserve unrelated user changes in a dirty worktree. Never use destructive reset or checkout
  commands to discard them.
- Use focused Conventional Commit subjects such as `feat:`, `fix:`, `test:`, `docs:`, and
  `chore:`. Commit and push complete logical slices frequently.
- Before committing, run `git diff --check` and the tracked-file terminology gate:

    ```sh
    prohibited='ssh''2'
    pattern='\b'"${prohibited}"'\b'
    if git ls-files -z | xargs -0 rg -n -i "$pattern"; then exit 1; fi
    ```

- Push `master` explicitly over SSH, then fetch the same branch and verify both object IDs:

    ```sh
    git push git@github.com:bunkerch/node-ssh.git master
    git fetch git@github.com:bunkerch/node-ssh.git master
    test "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)"
    ```

- Do not claim a push succeeded until the fetch verification matches. Report the commit ID and the
  build/lint/format/test results for each delivered slice.
