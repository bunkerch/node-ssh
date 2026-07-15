# OpenSSH ControlMaster

`ControlMaster` exposes an authenticated `Client` through the version 4 OpenSSH control-multiplex
protocol on a local Unix socket. This is separate from SSH channel multiplexing: `Client` already
carries many channels over one encrypted transport, while a control master lets other local
processes request work through that existing client.

Create the master only after the client connects. The socket is changed to mode `0600` before
`listen()` resolves. The path must not already be in use; the module never removes an arbitrary
pre-existing filesystem entry.

```ts
import { Client, ControlMaster, ControlMultiplexMessageType } from "@bunkerch/modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    privateKey: process.env.SSH_PRIVATE_KEY,
})

await client.connect()

const master = new ControlMaster(client, { path: "/run/user/1000/modernssh-control" })
master.hooker.hook("request", async (_hook, request, decision) => {
    decision.allow =
        request.type === ControlMultiplexMessageType.StopListening ||
        request.type === ControlMultiplexMessageType.Terminate
})
await master.listen()
```

Health checks are read-only and do not require policy. Every state-changing or channel-opening
request is deny-by-default and passes through the awaited `request` Hooker. A rejected Hooker or a
decision that leaves `allow` false returns `MUX_S_PERMISSION_DENIED`; set `reason` to return a
non-secret explanation.

The current public lifecycle supports OpenSSH `ssh -S path -O check`, `-O stop`, and `-O exit`.
`stop` closes the listener but does not terminate the authenticated SSH connection. `exit` ends the
owned client after policy approval. `close()` removes the listener and closes active local control
connections without ending the SSH client.

The decoder accepts fragmented and adjacent frames, caps each frame at 256 KiB, caps session
environment lists at 4096 entries, requires hello version 4 before requests, rejects duplicate
hello and extension values, and uses strict UTF-8 for textual fields. Passenger sessions, stdio
forwarding, proxy mode, and forwarding requests are parsed but currently return a failure after
policy approval; they will become active only when their full lifecycle is implemented.
