# modernssh

A typed, ESM-native SSH client and server library for Node.js.

The project is implementing the SSH protocol from its RFCs and is actively expanding toward the
feature surface of `ssh2`. Transport identification, binary packet framing, key exchange,
encryption, MAC verification, host keys, and core authentication flows are implemented today.

Until the first registry release, build a local installable archive with `pnpm pack` and add the
resulting `modernssh-1.0.0.tgz` file to an application with its package manager.

See [Getting started](docs/getting-started.md) for client and server examples and
[SSH transport behavior](docs/transport.md) for protocol-level details. The
[client channel guide](docs/channels.md) covers commands and stream behavior, while the
[TCP/IP forwarding guide](docs/forwarding.md) covers direct tunnels. The
[interoperability matrix](docs/interoperability.md) records cross-implementation coverage.

## Development

```sh
pnpm install
pnpm test
pnpm lint
pnpm format:check
```

`pnpm test` builds the distributable entry point before running unit and integration tests.
