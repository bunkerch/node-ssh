---
layout: home
titleTemplate: false

hero:
    name: modernssh
    text: Typed SSH for modern Node.js
    tagline: Promise-based client, server, channel, forwarding, agent, key-management, and SFTP APIs.
    actions:
        - theme: brand
          text: Get started
          link: /getting-started
        - theme: alt
          text: Browse examples
          link: /examples
        - theme: alt
          text: API reference
          link: /api/

features:
    - title: Client and server
      details: Build both SSH roles with strict TypeScript, Node.js streams, and explicit lifecycle control.
      link: /getting-started
    - title: Promise-first
      details: Public asynchronous operations return Promises. Awaited Hooker handlers keep policy decisions ordered.
      link: /authentication
    - title: Protocol-focused
      details: Behavior is derived from SSH standards and exercised with fixed vectors and OpenSSH interoperability tests.
      link: /rfc-coverage
    - title: Complete API reference
      details: Every package-root export is documented directly from the TypeScript declarations shipped by the package.
      link: /api/
---

## Install

The current release is available from `npm.manaf.ch`:

```sh
pnpm add @bunkerch/modernssh --registry https://npm.manaf.ch
```

`modernssh` is an ESM package for Node.js 20 and newer.

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
    hostVerifier: knownHosts.verifier(hostname),
})

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

Continue with [Getting started](getting-started.md), copy a task from
[Examples](examples.md), or look up a declaration in the [API reference](api/index.md).
