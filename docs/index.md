---
title: modernssh
description: Typed, Promise-based SSH client and server APIs for modern Node.js.
---

# modernssh

`modernssh` is a typed, ESM-native SSH client and server library for Node.js. It includes client,
server, channel, forwarding, authentication-agent, key-management, and SFTP APIs.

Public asynchronous operations return Promises. Application policy runs through awaited `Hooker`
handlers so authorization decisions remain ordered and rejected handlers are contained.

## Install

Install the package from the public npm registry:

```sh
pnpm add @bunkerch/modernssh
```

`modernssh` is an ESM package for Node.js 20 and newer.

## Explore

- [Getting started](getting-started.md) covers secure client connections, server setup, and
  lifecycle management.
- [Examples](examples.md) provides copyable command, shell, SFTP, jump-host, forwarding, and server
  recipes.
- [API reference](api/index.md) contains every package-root export and its generated public
  TypeScript declaration.
- [Standards coverage](rfc-coverage.md) maps implemented behavior to production code and test
  evidence.

## First connection

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
    agent: process.env.SSH_AUTH_SOCK,
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
    await client.close()
}
```

Continue with [Getting started](getting-started.md), copy a task from
[Examples](examples.md), or look up a declaration in the [API reference](api/index.md).
