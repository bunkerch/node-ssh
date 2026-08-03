# modernssh

A typed, ESM-native SSH client and server library for Node.js 20.19 or newer.

The project implements SSH from its standards and includes typed client, server, channel,
forwarding, agent, key-management, and SFTP APIs. Public asynchronous operations return Promises;
awaited application policy is handled through `Hooker`. Normal installs use no native dependency;
automatic Pageant discovery on Windows is the only optional FFI integration.

Install the package from the public npm registry:

```sh
pnpm add @bunkerch/modernssh
```

## Quick start

This example verifies the server against the user's known-hosts file, authenticates, runs a command,
and waits for the channel to close:

```ts
import { once } from "node:events"
import { homedir } from "node:os"
import { join } from "node:path"
import { Client, KnownHosts } from "@bunkerch/modernssh"

const hostname = "ssh.example.com"
const knownHosts = await KnownHosts.load(join(homedir(), ".ssh", "known_hosts"))
const client = new Client({
    hostname,
    username: "deploy",
    password: process.env.SSH_PASSWORD,
})
client.hooker.hook("hostKey", knownHosts.hostKeyHook(hostname))

client.on("error", (error) => console.error("SSH connection error", error))

try {
    await client.connect()
    const command = await client.exec("uname -a")
    command.pipe(process.stdout)
    command.stderr.pipe(process.stderr)
    await once(command, "close")
} finally {
    client.end()
}
```

EventEmitter listeners are observation-only and should remain synchronous. Authorization and other
asynchronous policy decisions belong in awaited `Hooker` handlers.

## Documentation

Browse the hosted documentation at [modernssh.bunkerx.dev](https://modernssh.bunkerx.dev).

| Goal                                                              | Guide                                                                                       |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Connect a client or create a server                               | [Getting started](docs/getting-started.md)                                                  |
| Copy practical recipes                                            | [Examples](docs/examples.md)                                                                |
| Look up every package export and its exact TypeScript declaration | [API reference](docs/api/index.md)                                                          |
| Configure authentication and multi-factor flows                   | [Authentication](docs/authentication.md)                                                    |
| Run commands, shells, and subsystems                              | [Channels](docs/channels.md)                                                                |
| Transfer and manage files                                         | [SFTP](docs/sftp.md)                                                                        |
| Create direct, remote, HTTP, and tunnel forwarding                | [Forwarding](docs/forwarding.md) and [packet tunnels](docs/tunnels.md)                      |
| Verify and rotate host keys                                       | [Known hosts](docs/known-hosts.md)                                                          |
| Publish or verify DNS host-key fingerprints                       | [SSHFP DNS records](docs/sshfp.md)                                                          |
| Use or expose an authentication agent                             | [Agent protocol](docs/agent-protocol.md)                                                    |
| Check implemented standards and tested peers                      | [Standards coverage](docs/rfc-coverage.md) and [interoperability](docs/interoperability.md) |

Protocol-level and specialist guides cover [transport behavior](docs/transport.md),
[connection-wide requests](docs/global-requests.md),
[public-key management](docs/public-key-subsystem.md),
[key revocation lists](docs/key-revocation-lists.md), and
[detached signatures](docs/signatures.md).

## Development

```sh
pnpm install
pnpm test
pnpm lint
pnpm format:check
pnpm docs:api
pnpm docs:dev
pnpm docs:build
```

`pnpm test` builds the distributable entry point before running unit and integration tests.
CI installs `putty-tools` and SoftHSM alongside the system OpenSSH and Docker tools used by the
interoperability suite. The SoftHSM token fixture is skipped locally when its provider is absent.
`pnpm docs:api` rebuilds the package and regenerates the complete declaration reference under
`docs/api/`. `pnpm docs:dev` starts the local Fumadocs site, and `pnpm docs:build` verifies the
production documentation build. The documentation toolchain requires Node.js 22 or newer; the
published library supports Node.js 20.19 and newer.
