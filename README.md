# modernssh

A typed, ESM-native SSH client and server library for Node.js.

The project implements SSH from its standards and is actively expanding its client and server
feature surface. Transport identification, binary packet framing, key exchange, encryption, MAC
verification, host keys, and core authentication flows are implemented today.

The current release is available from `npm.manaf.ch`:

```sh
pnpm add @bunkerch/modernssh --registry https://npm.manaf.ch
```

The package will also target the public npm registry in a future release.

See [Getting started](docs/getting-started.md) for client and server examples and
[SSH transport behavior](docs/transport.md) for protocol-level details. The
[authentication guide](docs/authentication.md) covers passwords, keyboard-interactive prompts,
banners, and multi-factor flows. The [client channel guide](docs/channels.md) covers commands and
stream behavior, the [SFTP guide](docs/sftp.md) covers remote file operations, and the
[TCP/IP forwarding guide](docs/forwarding.md) covers direct and remote forwarding, while the
[packet tunnel guide](docs/tunnels.md) covers layer-3 and layer-2 tunnel channels. The
[SSH agent protocol guide](docs/agent-protocol.md) covers identity management, constraints,
locking, extensions, and restricted agent endpoints. The
[public-key management guide](docs/public-key-subsystem.md) covers the RFC 4819 subsystem for
adding, removing, and listing an authenticated user's authorized keys. The
[global request guide](docs/global-requests.md) covers connection-wide application extensions. The
[ControlMaster guide](docs/control-master.md) covers sharing one authenticated connection with
local OpenSSH processes through a protected Unix control socket. The
[known-hosts guide](docs/known-hosts.md) covers persistent host verification, host certificates,
revocation, and key rotation, while the
[key revocation list guide](docs/key-revocation-lists.md) covers binary key and certificate
revocation policy, and the [detached signature guide](docs/signatures.md) covers namespace-bound
signing and verification with private keys or agents. The
[interoperability matrix](docs/interoperability.md) records cross-implementation coverage, and the
[standards coverage index](docs/rfc-coverage.md) maps each implemented RFC to production code,
tests, and remaining evidence gaps.

## Development

```sh
pnpm install
pnpm test
pnpm lint
pnpm format:check
```

`pnpm test` builds the distributable entry point before running unit and integration tests.
