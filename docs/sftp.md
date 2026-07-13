# SFTP

`modernssh` implements version 3 of the SSH File Transfer Protocol from
`draft-ietf-secsh-filexfer-02`, the version used by OpenSSH. SFTP runs in an SSH session channel;
authentication, host-key verification, encryption, channel flow control, and SFTP framing remain
separate layers.

## Client sessions

Open and negotiate a session after connecting:

```ts
import { Client } from "modernssh"

const client = new Client({ hostname: "files.example.com", username: "deploy" })
// Configure the host-key hook and authentication before connecting.
await client.connect()

const sftp = await client.sftp()
```

`Client.sftp(callback)` is also available for callback-based setup. The resulting `SFTPClient`
exposes the negotiated version, the duplicate-preserving `extensions` announcement list, and
`supportsExtension(name, version?)`.

The baseline operations are Promise-based:

- `open`, `close`, `read`, and `write` operate on opaque handles. `write` splits large buffers into
  server-safe requests; independent requests may be outstanding concurrently and responses are
  matched by request identifier.
- `stat`, `lstat`, `fstat`, `setstat`, and `fsetstat` retrieve or change attributes. `chmod`,
  `fchmod`, `chown`, `fchown`, `utimes`, and `futimes` are focused helpers.
- `opendir` and `readdir` expose incremental directory scanning. `readDirectory` reads all batches,
  filters the conventional `.` and `..` entries, and closes the directory handle even after an
  error.
- `mkdir`, `rmdir`, `unlink`/`remove`, `rename`, `realpath`, `readlink`, and `symlink` cover the
  remaining version 3 operations.

For example:

```ts
const handle = await sftp.open("incoming/archive.bin", "wx", { permissions: 0o640 })
try {
    await sftp.write(handle, archive, 0n)
    const attributes = await sftp.fstat(handle)
    console.log(attributes.size) // bigint | undefined
} finally {
    await sftp.close(handle)
}

for (const entry of await sftp.readDirectory("incoming")) {
    console.log(entry.filename.toString("utf8"), entry.attributes.size)
}
```

Call `sftp.end()` to send EOF to the subsystem once no requests remain. `sftp.destroy(error?)`
aborts it.

## Paths, offsets, and attributes

String paths are encoded as UTF-8. Pass a `Buffer` when a server-side filename must be preserved as
opaque bytes. File handles are always opaque `Buffer` values and are limited to the protocol's
256-byte maximum.

Offsets and file sizes are unsigned 64-bit wire values. The API accepts `bigint` positions and
returns `bigint` sizes so values larger than JavaScript's safe integer range remain exact. Numeric
positions are accepted only when they are non-negative safe integers. Access and modification
times are version 3's unsigned 32-bit Unix seconds.

`SFTPAttributes` contains only fields present on the wire:

```ts
interface SFTPAttributes {
    size?: bigint
    uid?: number
    gid?: number
    permissions?: number
    accessTime?: number
    modificationTime?: number
    extended?: readonly { type: Buffer; data: Buffer }[]
}
```

The paired `uid`/`gid` and `accessTime`/`modificationTime` fields must be supplied together when
encoding an attribute update.

## Errors and limits

Remote failure statuses reject with `SFTPStatusError`. Its numeric `code`, `requestId`, and
`languageTag` properties preserve the complete response. Compare `code` with `SFTPStatusCode`, for
example `SFTPStatusCode.NoSuchFile` or `SFTPStatusCode.PermissionDenied`.

Malformed frames, unexpected response identifiers, wrong response types, duplicate initialization,
and unsupported attribute flags are fatal protocol errors. Messages are bounded to OpenSSH's 256
KiB ceiling before allocation, handles to 256 bytes, and outstanding client requests to 1024. The
initial read and write request size is 32 KiB, which every conforming server is expected to support.

OpenSSH reverses the two wire arguments of the standard `SSH_FXP_SYMLINK` request. The client uses
the peer's SSH identification to apply that published OpenSSH behavior while preserving the draft's
ordering for other implementations.

## Server sessions

SFTP access is denied by the ordinary session-subsystem policy hook until explicitly accepted. The
server does not expose the host filesystem automatically: mapping virtual paths, enforcing a root,
authorizing operations, allocating opaque handles, and translating operating-system errors are
application policy.

```ts
server.hooker.hook("channelOpenRequest", (_hook, channel, decision) => {
    decision.allowOpen = channel instanceof SessionChannel
})

server.on("connection", (connection) => {
    connection.on("channel", (channel) => {
        if (!(channel instanceof SessionChannel)) return

        channel.hooker.hook("subsystemRequest", (_hook, context, decision) => {
            decision.success = context.subsystem === "sftp"
        })
        channel.events.on("sftp", (sftp) => {
            sftp.on("STAT", (request) => {
                void lookupAuthorizedAttributes(request.path).then(
                    (attributes) => sftp.attributes(request.requestId, attributes),
                    () => sftp.status(request.requestId, SFTPStatusCode.NoSuchFile),
                )
            })
        })
    })
})
```

`SFTPServer` emits the uppercase request events used by the protocol: `OPEN`, `CLOSE`, `READ`,
`WRITE`, `LSTAT`, `FSTAT`, `SETSTAT`, `FSETSTAT`, `OPENDIR`, `READDIR`, `REMOVE`, `MKDIR`, `RMDIR`,
`REALPATH`, `STAT`, `RENAME`, `READLINK`, `SYMLINK`, and `EXTENDED`. When no specific listener is
registered, the generic `request` event is used as a fallback. An entirely unhandled request gets
`SFTPStatusCode.OperationUnsupported`. `requestReceived` is a passive observation event and does not
take ownership of the response.

Complete each request exactly once with the appropriate method:

- `status(requestId, code, message?, languageTag?)` reports success for operations without result
  data or a failure for any operation.
- `handle`, `data`, `name`, and `attributes` return the corresponding baseline result.
- `extendedReply` returns extension-specific bytes.

The implementation rejects duplicate outstanding identifiers, invalid response types, oversized
read results, empty name responses, server use of client-only connection status codes, and a second
response. Requests are dispatched one at a time in arrival order. This conservative scheduling
guarantees the draft's ordering semantics for operations on the same file and provides fairness
without requiring an application handler to infer which opaque handles alias one resource. The
bounded queue accepts at most 1024 waiting requests.

Advertise extension name/version pairs through `decision.sftp.extensions` only when every advertised
operation is actually implemented:

```ts
decision.success = true
decision.sftp = {
    extensions: [{ name: "example@example.com", data: Buffer.from("1") }],
}
```

For `SYMLINK`, call `sftp.symlinkPaths(request)` to obtain semantic `targetPath` and `linkPath`
values. Session integration detects OpenSSH and Dropbear identifications and normalizes OpenSSH's
published argument reversal; `openSSHSymlinkArguments` can be set explicitly for a proxied or
otherwise unusual peer.

Never use a client-supplied path directly with a local filesystem API. Resolve it beneath an
application-owned root, reject traversal outside that root, validate every opaque handle against
per-session state, close all remaining resources on the SFTP `close` event, and apply authorization
to every operation rather than only `OPEN`.
