# modernssh

A typed, ESM-native SSH client and server library for Node.js.

The project implements SSH from its standards and is actively expanding its client and server
feature surface. Transport identification, binary packet framing, key exchange, encryption, MAC
verification, host keys, and core authentication flows are implemented today.

Until the first registry release, build a local installable archive with `pnpm pack` and add the
resulting `modernssh-1.0.0.tgz` file to an application with its package manager.

See [Getting started](docs/getting-started.md) for client and server examples and
[SSH transport behavior](docs/transport.md) for protocol-level details. The
[authentication guide](docs/authentication.md) covers passwords, keyboard-interactive prompts,
banners, and multi-factor flows. The [client channel guide](docs/channels.md) covers commands and
stream behavior, the [SFTP guide](docs/sftp.md) covers remote file operations, and the
[TCP/IP forwarding guide](docs/forwarding.md) covers direct and remote forwarding, while the
[packet tunnel guide](docs/tunnels.md) covers layer-3 and layer-2 tunnel channels. The
[SSH agent protocol guide](docs/agent-protocol.md) covers identity management, constraints,
locking, extensions, and restricted agent endpoints. The
[global request guide](docs/global-requests.md) covers connection-wide application extensions. The
[known-hosts guide](docs/known-hosts.md) covers persistent host verification, host certificates,
revocation, and key rotation. The
[interoperability matrix](docs/interoperability.md) records cross-implementation coverage.

## Development

```sh
pnpm install
pnpm test
pnpm lint
pnpm format:check
```

`pnpm test` builds the distributable entry point before running unit and integration tests.
