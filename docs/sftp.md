---
title: SFTP
description: Promise-based remote file operations, streams, extensions, and server policy.
---

# SFTP

`modernssh` implements version 3 of the SSH File Transfer Protocol from
`draft-ietf-secsh-filexfer-02`, the version used by OpenSSH. SFTP runs in an SSH session channel;
authentication, host-key verification, encryption, channel flow control, and SFTP framing remain
separate layers.

## Client sessions

Open and negotiate a session after connecting:

```ts
import { Client } from "@bunkerch/modernssh"

const client = new Client({ hostname: "files.example.com", username: "deploy" })
// Configure the host-key hook and authentication before connecting.
await client.connect()

const sftp = await client.sftp({}, { requestTimeout: 30_000 })
```

The resulting `SFTPClient` exposes the negotiated version, the duplicate-preserving `extensions`
announcement list, `supportsExtension(name, version?)`, and its immutable `requestTimeout`.
Each `extensions` read is a frozen defensive snapshot; changing an advertised data buffer cannot
enable, disable, or alter the capabilities used internally by `supportsExtension`.
Version matching compares the advertised opaque bytes exactly with the requested UTF-8 version;
non-ASCII bytes cannot alias an ASCII version through lossy decoding.
The timeout defaults to the connection's `replyTimeout`; direct `SFTPClient.connect()` calls default
to 30 seconds. It must be a positive finite number.
Client environment and option bags must be plain objects, environment values must be strings, and
only `undefined` selects the inherited or 30-second timeout default. Explicit `null` is rejected
before a session channel is allocated or initialization is sent. Direct `SFTPClient.connect()`
calls also require an actual boolean compatibility flag.

The baseline operations are Promise-based:

- `open`, `close`, `read`, and `write` operate on opaque handles. The three-argument `read` returns a
  newly allocated `Buffer`; its five-argument overload reads into a selected range of a caller
  buffer and returns `{ bytesRead, buffer }`. The corresponding five-argument `write` overload
  writes only the selected caller-buffer range and returns `{ bytesWritten, buffer }`. These are
  Promise APIs and do not accept completion callbacks. `write` splits large buffers into server-safe
  requests; independent requests may be outstanding concurrently and responses are matched by
  request identifier. A write snapshots its handle and selected data when it starts, so caller
  mutation while an earlier chunk awaits acknowledgement cannot alter later chunks. The negotiated
  chunk limit is also fixed for the operation, preventing overlap if public limit metadata is
  changed while a chunk is pending. Assigning an invalid `maxWriteLength` rejects locally before a
  request is sent; the value must be a positive safe integer. `read` applies the same requirement
  to `maxReadLength` before treating a zero requested length as an empty result, so whole-file reads
  cannot mistake an invalid limit for end-of-file. Buffer offsets and lengths must be non-negative
  safe integers whose range fits within the supplied buffer.
- `writeFile` copies Buffer input before opening the remote file; mutation during the open request
  cannot change the eventual contents.
- `stat`, `lstat`, `fstat`, `setstat`, and `fsetstat` retrieve or change attributes. `chmod`,
  `fchmod`, `chown`, `fchown`, `utimes`, `futimes`, `truncate`, and `ftruncate` are focused helpers.
- `opendir` and `readdir` expose individual directory requests. `iterateDirectory` provides a
  bounded-memory async iterator, filters the conventional `.` and `..` entries, snapshots Buffer
  paths, and closes its handle on completion, failure, or early loop exit. `readDirectory` collects
  that iterator with default limits of 100,000 entries and 16 MiB of retained name and extended
  attribute bytes. Set `maxEntries` or `maxBytes` to a smaller or larger non-negative safe integer;
  exceeding either limit rejects after closing the handle.
- `mkdir`, `rmdir`, `unlink`/`remove`, `rename`, `realpath`, `readlink`, and `symlink` cover the
  remaining version 3 operations.

For example:

```ts
const handle = await sftp.open("incoming/archive.bin", "wx", { permissions: 0o640 })
try {
    await sftp.write(handle, archive, 0n)
    const header = Buffer.alloc(16)
    const { bytesRead } = await sftp.read(handle, header, 0, header.length, 0n)
    await sftp.write(handle, header, 0, bytesRead, 4096n)
    await sftp.ftruncate(handle, 4_294_967_297n)
    const attributes = await sftp.fstat(handle)
    console.log(attributes.size) // bigint | undefined
} finally {
    await sftp.close(handle)
}

for await (const entry of sftp.iterateDirectory("incoming")) {
    console.log(entry.filename.toString("utf8"), entry.attributes.size)
}

const boundedEntries = await sftp.readDirectory("incoming", {
    maxEntries: 1_000,
    maxBytes: 4 * 1024 * 1024,
})
```

Whole-file helpers follow Node-style flags while returning Promises:

```ts
await sftp.writeFile("incoming/message.txt", "first line\n", { mode: 0o640 })
await sftp.appendFile("incoming/message.txt", "second line\n")
const message = await sftp.readFile("incoming/message.txt", "utf8")
```

`readFile` returns a `Buffer` unless an encoding is requested. Its optional `maxBytes` limit rejects
oversized files before allocation when the server reports a size and while reading when it does
not. `exists` returns `false` only for `SFTPStatusCode.NoSuchFile`; permission and transport errors
remain visible.

`fastGet(remotePath, localPath, options?)` and `fastPut(localPath, remotePath, options?)` transfer
disjoint chunks concurrently. `concurrency` defaults to 64 and is bounded by the request engine;
`chunkSize` defaults to 32 KiB and is clamped to negotiated server limits. `fastPut` also accepts a
remote `mode`. Transfer completion is Promise-only. For observational progress, attach synchronous
`downloadProgress` or `uploadProgress` listeners to the client:

```ts
sftp.on("downloadProgress", ({ remotePath, localPath, transferred, chunk, total }) => {
    console.log({ remotePath, localPath, transferred, chunk, total })
})

await sftp.fastGet("remote.bin", "local.bin")
```

Each progress event identifies both paths and reports the cumulative bytes, completed chunk size,
and total size. The remote path is a fresh Buffer owned by the event, so listener mutation cannot
alter the transfer or later events. Progress listeners are EventEmitter observers: keep them
synchronous and do not pass an `async` function to `on()`.
`fastGet` snapshots a Buffer remote path and its transfer options before its separate `STAT` and
`OPEN` requests.
`fastPut` snapshots its remote path and options before opening or inspecting the local file.
Both helpers accept only plain option objects and validate `chunkSize`, `concurrency`, an explicit
upload `mode`, and their public `maxReadLength` or `maxWriteLength` metadata before remote or local
I/O begins. Transfer limits must remain positive safe integers.
All workers settle before either handle is closed, and an operation error is preserved over a
secondary close failure.

For backpressure-aware pipelines, `createReadStream` and `createWriteStream` return Node streams:

```ts
const range = sftp.createReadStream("archive.bin", { start: 1024n, end: 2047n })
range.pipe(process.stdout)

const upload = sftp.createWriteStream("incoming/archive.bin", { mode: 0o640 })
source.pipe(upload)
```

Read ranges use inclusive `start` and `end` offsets. Both stream types accept an already-open
`handle`, expose exact `bigint` `bytesRead`/`bytesWritten` counters, emit `open` and `ready` after a
path is opened, and close their handle exactly once by default. With `autoClose: false`, natural
completion leaves the handle open and ownership passes to the caller; calling the stream's `close`
method still drains pending writes and closes it explicitly. `close()` also closes a retained handle
after the local stream has already been destroyed, and its Promise settles when that remote close
finishes. Read requests are clamped to the negotiated limit, and writable backpressure is released
only after the corresponding SFTP write has completed.

Buffer paths and already-open handles are snapshotted when the stream is constructed. The `path`
and `handle` properties and the handle passed to the `open` event are defensive copies as well, so
mutating them cannot redirect later reads, writes, or close operations. A supplied handle must be
active and issued by the same `SFTPClient`, in addition to satisfying the protocol's 256-byte
maximum.

Call `sftp.end()` to send EOF to the subsystem once no requests remain. `sftp.destroy(error?)`
aborts it. An abort rejects every pending request and handle allocation with the supplied error;
subsequent operations reject because the SFTP session is closed.

## Paths, offsets, and attributes

String paths are validated and encoded as UTF-8 before a request is written. Pass a `Buffer` when a
server-side filename must be preserved as opaque bytes. File handles are always opaque `Buffer`
values and are limited to the protocol's
256-byte maximum. `realpath()`, `readlink()`, `opensshExpandPath()`, and `homeDirectory()` return a
strict UTF-8 string by default; pass `"buffer"` as their final argument to receive the returned name
as an owned `Buffer` without decoding it.

Every handle-taking client method validates the Buffer type, 256-byte limit, and live session
ownership before allocating or writing a request, including zero-length reads, empty writes,
attribute helpers, and extensions. Fabricated and closed handles reject locally. `READ` and `WRITE`
also reject directory handles, while `READDIR` rejects file handles; an extension-issued handle is
type-agnostic because its extension defines the resource. The method snapshots a valid handle
before retaining it across asynchronous work, so later caller mutation cannot change the request.

Text arguments to extensions receive the same strict encoding. OpenSSH user/group lookup names are
strictly decoded as UTF-8; malformed replies fail instead of exposing replacement characters.

Offsets and file sizes are unsigned 64-bit wire values. The API accepts `bigint` positions and
returns `bigint` sizes so values larger than JavaScript's safe integer range remain exact. Numeric
positions are accepted only when they are non-negative safe integers. Access and modification
times are version 3's unsigned 32-bit Unix seconds. Truncation lengths accept a non-negative safe
integer or exact uint64 `bigint`; invalid lengths fail before a request identifier is allocated.

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

Client `stat`, `lstat`, and `fstat` results—and directory-entry attributes—are `SFTPStats`
instances. They retain the exact fields above and add `isDirectory`, `isFile`, `isBlockDevice`,
`isCharacterDevice`, `isSymbolicLink`, `isFIFO`, and `isSocket`. The convenience `mode`, `atime`,
and `mtime` aliases map to `permissions`, `accessTime`, and `modificationTime`; sizes remain `bigint`
rather than losing uint64 precision. Returned directory names, long names, and extended-attribute
buffers are owned snapshots rather than aliases into protocol input or caller-owned attributes.

`stringToFlags` and `flagsToString` provide nullable conversions. The legacy `OPEN_MODE` and
`STATUS_CODE` exports use uppercase keys, while `SFTPOpenFlags` and
`SFTPStatusCode` remain the typed modern enums. `sftpOpenFlags` is the strict converter used for
requests and throws on invalid strings, unknown bits, or invalid flag combinations.

## Errors and limits

Remote failure statuses reject with `SFTPStatusError`. Its numeric `code`, `requestId`, and
`languageTag` properties preserve the complete response. Compare `code` with `SFTPStatusCode`, for
example `SFTPStatusCode.NoSuchFile` or `SFTPStatusCode.PermissionDenied`.

Malformed frames, unexpected response identifiers, wrong response types, duplicate initialization,
duplicate live handles, unsupported attribute flags, and status codes used outside their defined
request context are fatal protocol errors. Semantic reply checks use the same fatal path as framing:
empty or oversized `DATA`, empty baseline directory `NAME`, the wrong number of names for
single-name operations, empty or slash-containing `READDIR` filenames, non-absolute `REALPATH`
results, malformed negotiated-extension replies, and invalid returned UTF-8 all close the SFTP
channel before rejecting the operation. A server-sent `NoConnection` or
`ConnectionLost` is also fatal because those two pseudo-statuses are local to clients and must never
appear on the wire. A successful positive-length read must return at least one byte; end-of-file is
reported with `SFTPStatusCode.EOF` only for `READ`, `READDIR`, or an extension that defines it.
Rejecting no-progress responses prevents silent file truncation and unbounded directory scans.
Messages are bounded to OpenSSH's 256 KiB ceiling before allocation, handles to 256 bytes, and
outstanding client requests to 1024. The initial read and write request size is 32 KiB, which every
conforming server is expected to support. Status messages use fatal UTF-8 validation, status
language tags use the RFC 5646 grammar (with the empty protocol value retained for an unspecified
language), and extension identifiers are validated SSH names. Filenames, long names, paths, handles,
and extension payloads remain opaque bytes. The wire codec never replacement-decodes them. Decoded
opaque fields are owned buffers rather than
views into the input frame, and the streaming parser snapshots any incomplete chunk it must retain
across calls.
Fatal errors, including EOF in the middle of a frame, close the SFTP channel in both peer roles and
reject pending client operations. They do not tear down an otherwise healthy SSH connection.
Initialization and every tagged request reply are bounded by `requestTimeout`. Expiry rejects the
operation and closes only that SFTP channel, which prevents a late response or eventually reused
request identifier from corrupting a later exchange while leaving the SSH connection available.
Local request-encoding failures reject without consuming an outstanding-request slot, so repeated
invalid calls cannot exhaust or poison an otherwise healthy SFTP session.

OpenSSH reverses the two wire arguments of the standard `SSH_FXP_SYMLINK` request. The client uses
the peer's SSH identification to apply that published OpenSSH behavior while preserving the draft's
ordering for other implementations.

## Application extensions

Applications can use negotiated extensions without bypassing the bounded request engine. The
server must advertise the extension name; an optional `version` requires its payload to match
exactly. `extended()` copies the opaque request data and defaults to accepting
`SSH_FXP_EXTENDED_REPLY`:

```ts
const reply = await sftp.extended("lookup@example.com", Buffer.from("alice"), {
    version: "1",
})

if (reply.type === SFTPPacketType.ExtendedReply) console.log(reply.data)
```

Extension names follow the RFC 4251 name grammar: 1–64 printable US-ASCII characters, no comma,
and at most one non-leading `@` followed by a valid DNS domain. `supportsExtension()` validates the
same grammar. `extended()` rejects malformed names before consuming a request identifier or
writing a packet.

Extensions that define another successful response packet declare it explicitly:

```ts
await sftp.extended("notify@example.com", payload, {
    expectedTypes: [SFTPPacketType.Status],
})
```

A non-success status becomes `SFTPStatusError`. A successful response type outside the declared
set is a protocol error and closes the SFTP session, preventing a malformed response from being
interpreted as another extension's layout. When `expectedTypes` includes `SFTPPacketType.Handle`, a
returned handle is registered as active, counts against the negotiated handle limit, and remains
valid for extension-defined operations until `close()`. On the server, advertise application
extensions through `SFTPServerOptions.extensions` and handle them with the awaited `EXTENDED` hook;
reply with `extendedReply()`, `status()`, or the response method specified by that extension.
Generic extension responses may use empty `DATA` or `NAME` payloads when their own protocol defines
that meaning; baseline positive-length `READ` and `READDIR` responses retain their progress
requirements.

## OpenSSH extensions

Every extension method checks the exact version advertised in `SSH_FXP_VERSION` before sending a
request. The client supports OpenSSH's published `posix-rename`, `statvfs`, `fstatvfs`, `hardlink`,
`fsync`, `lsetstat`, `limits`, and `expand-path` extensions, plus the standardized `copy-data` and
`home-directory` extensions and OpenSSH's `users-groups-by-id` extension.

The main methods are `opensshPosixRename`, `opensshStatVFS`, `opensshFStatVFS`, `opensshHardlink`,
`opensshFSync`, `opensshLSetStat`, `opensshLimits`, `opensshExpandPath`, `copyData`, `homeDirectory`,
and `usersGroups`. The `ext_openssh_*` aliases preserve earlier public spellings where they differ
from the preferred method names.

Server handlers can decode the published request bodies with the exported strict helpers. Use
`decodeSFTPExtensionString()` for path and username requests,
`decodeSFTPHandleExtension()` for `fstatvfs` and `fsync`, and
`decodeSFTPTwoPathExtension()` for POSIX rename and hard links. Dedicated decoders cover
`lsetstat`, `copy-data`, and `users-groups-by-id`. Every decoder requires the complete layout,
rejects truncation and trailing bytes, and returns owned buffers. Handle decoders enforce the SFTP
256-byte handle bound. `copy-data` offsets and lengths remain `bigint`; user and group identifiers
remain unsigned 32-bit numbers.

Successful `statvfs` and `fstatvfs` hooks can pass `encodeSFTPStatVFS()` to
`sftp.extendedReply()`. A `users-groups-by-id` hook uses `encodeSFTPUsersGroups()` for its two
ordered name lists. These response encoders are exact inverses of the client decoders, retain all
unsigned 64-bit filesystem values, and reject invalid UTF-8 names before writing a response.

The published `copy-data` protocol requires `SFTPStatusCode.InvalidParameter` when both handles are
the same. The server permits this registered status only for `EXTENDED` requests; baseline SFTP v3
requests retain the v3 status-code set.

When `limits@openssh.com` version 1 is advertised, session setup requests it automatically. The
exact unsigned 64-bit reply remains available as `sftp.limits`; safe request sizes are reflected in
`maxReadLength` and `maxWriteLength`, and `maxOpenHandles` is `Infinity` when the server reports no
fixed handle limit. Pending `open`, `opendir`, and extension requests that may return a handle count
toward a finite handle limit; attempts beyond it reject locally without sending a request. The
client invalidates a handle as soon as its `CLOSE` frame is accepted for writing, before the reply,
so concurrent reuse or a second close rejects locally. A close or flush failure does not revive the
handle. A local failure before the frame is accepted keeps it tracked. Reuse of an active opaque
value by the server is a fatal protocol error. A server status failure while negotiating limits
leaves the conservative 32 KiB defaults in place, but a malformed successful reply aborts setup as
a protocol error.

A `modernssh` server advertises version 1 of this extension by default and answers it internally;
the request does not enter the application `EXTENDED` hook. Its default reply reports a 256 KiB
packet bound, 254 KiB read and write bounds, and 256 handles. The exported `encodeSFTPLimits()` and
`decodeSFTPLimits()` helpers encode and decode the four exact uint64 fields for applications that
deliberately provide a separate extension implementation.

```ts
const handle = await sftp.open("incoming/archive.bin", "r")
try {
    const filesystem = await sftp.opensshFStatVFS(handle)
    console.log(filesystem.blockSize) // bigint
} finally {
    await sftp.close(handle)
}

await sftp.opensshPosixRename("incoming/new", "incoming/current")
```

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
            sftp.hooker.hook("STAT", async (_hook, request) => {
                try {
                    const attributes = await lookupAuthorizedAttributes(request.path)
                    await sftp.attributes(request.requestId, attributes)
                } catch {
                    await sftp.status(request.requestId, SFTPStatusCode.NoSuchFile)
                }
            })
        })
    })
})
```

An application-owned extension remains an awaited policy operation. Advertise the exact supported
version and decode its complete request before touching the backing store:

```ts
import { decodeSFTPTwoPathExtension, SFTPServer, SFTPStatusCode } from "modernssh"

const sftp = new SFTPServer(shell, {
    extensions: [{ name: "posix-rename@openssh.com", data: Buffer.from("1") }],
})

sftp.hooker.hook("EXTENDED", async (_hook, request) => {
    if (request.request !== "posix-rename@openssh.com") {
        await sftp.status(request.requestId, SFTPStatusCode.OperationUnsupported)
        return
    }

    const { firstPath, secondPath } = decodeSFTPTwoPathExtension(request.data)
    await renameWithinAuthorizedRoot(firstPath, secondPath)
    await sftp.status(request.requestId, SFTPStatusCode.Ok)
})
```

`SFTPServer.hooker` provides the uppercase request hooks used by the protocol: `OPEN`, `CLOSE`, `READ`,
`WRITE`, `LSTAT`, `FSTAT`, `SETSTAT`, `FSETSTAT`, `OPENDIR`, `READDIR`, `REMOVE`, `MKDIR`, `RMDIR`,
`REALPATH`, `STAT`, `RENAME`, `READLINK`, `SYMLINK`, and `EXTENDED`. Hooks may be async and are
awaited by the request that triggered them. When no specific hook is registered, the generic
`request` hook is used as a fallback. An entirely unhandled request gets
`SFTPStatusCode.OperationUnsupported`. The EventEmitter `requestReceived` event is passive
observation and does not take ownership of the response. Its request object and nested metadata are
frozen, and its buffers are owned copies: changing observed bytes cannot alter the request later
delivered to an awaited Hooker handler.

Complete each request exactly once with the appropriate method:

- `status(requestId, code, message?, languageTag?)` reports success for operations without result
  data or a failure for any operation. `EOF` is limited to `READ`, `READDIR`, and extensions;
  `InvalidParameter` is extension-only; client-local connection statuses are never emitted.
- `handle`, `data`, `name`, and `attributes` return the corresponding baseline result.
- `extendedReply` returns extension-specific bytes.

Every response method returns a Promise. Await it from the Hooker handler: it resolves only after
the response has been accepted by the SSH channel write, and rejects if that write fails. The
request retains its concurrency slot until both the handler and response write complete. Opaque
response values are validated as Buffers and snapshotted before encoding; response handles also
enforce the 256-byte protocol limit.

The implementation rejects duplicate outstanding identifiers, invalid response types,
out-of-context status codes, oversized read results, empty baseline name responses, server use of
client-only connection status codes, and a second response. A hook rejection becomes an SFTP
failure response and is observable through the hooker's `uncaughtException` event; returning
without a response also produces a failure instead of leaving the client pending. A locally invalid
or oversized response throws before claiming the request, so the handler may catch that error and
send an appropriate failure status instead.

SFTP clients pipeline tagged requests and may receive their responses out of order. The server
therefore runs up to 64 request hooks concurrently by default while keeping each response and
contained hook failure associated with its own request identifier. Set `maxConcurrentRequests` in
the session's `decision.sftp` options to a safe integer from 1 through 1024 when backend capacity
requires another bound; setting it to 1 deliberately restores serial dispatch. At most 1024 total
queued and active requests are accepted.

The scheduler preserves SFTP v3's same-file receive order. Requests sharing an opaque handle or an
exact path wait for the earlier handler and response write, while unrelated handles and paths may
run concurrently. Handles returned by `OPEN` and `OPENDIR` are associated with their requested path,
so a path operation cannot overtake an outstanding operation through that handle. Two-path
operations reserve both paths, and an opaque `EXTENDED` request is an ordering barrier because its
resource cannot be inferred from the baseline packet. A `CLOSE` response discards the handle's path
association even when it reports failure, because the protocol invalidates the handle when the
request is sent. If an application maps distinct path byte strings to the same backend object—for
example through aliases outside the virtual path model—it must additionally serialize those backend
aliases because the protocol layer cannot discover that identity.

The server rejects a fabricated, unknown, or closed handle with `SFTPStatusCode.Failure` before any
request Hooker handler runs. It also rejects `READDIR` through a file handle and `READ` or `WRITE`
through a directory handle. Handles returned by an `EXTENDED` request remain valid but
type-agnostic because the extension defines their semantics. Applications still own the mapping
from each issued opaque value to its backend resource and must not trust the bytes as a filesystem
identifier.

The server allows 256 active or pending `OPEN`, `OPENDIR`, or extension-issued handles by default. Set
`maxOpenHandles` to a non-negative safe integer to match the backend's resource budget. Once the
limit is reached, another baseline open request receives `SFTPStatusCode.Failure` before its Hooker
handler runs, so no backend handle should be allocated for it. An extension handler attempting to
return another handle receives a local error and can return an appropriate status instead. A
successful handle value must remain unique within the session until the corresponding `CLOSE`
response has been written; that response releases the capacity even when it reports failure.
Baseline `READDIR` responses accept only non-empty relative entry names without `/`, and
`REALPATH` responses must contain one absolute name. Invalid application responses are rejected
locally before serialization, mirroring the client-side peer checks.

An `OPEN` request with unknown flag bits, or with `EXCL` but no `CREAT`, receives
`SFTPStatusCode.BadMessage` before the `OPEN` Hooker handler runs. `TRUNC` without `CREAT` remains
valid for truncating an existing file. This enforces the mandatory v3 flag relationship at the wire
boundary instead of requiring every filesystem backend to repeat it.

The server's default maximum `READ` length and `WRITE` data length are both 254 KiB. Set
`maxReadLength` or `maxWriteLength` to a smaller positive safe integer when the backend needs a
tighter per-operation bound. Oversized requests receive `SFTPStatusCode.Failure` before their
Hooker handler runs, preventing an untrusted peer from driving a larger backend allocation. These
values and `maxOpenHandles` are the limits returned by the built-in extension.

A peer may reuse a numeric request identifier after receiving its response; if the prior Hooker
handler is still completing, the reused identifier remains queued until that handler returns. This
prevents late code in the prior handler from accidentally responding to the newer request, without
serializing unrelated identifiers.

Advertise extension name/version pairs through `decision.sftp.extensions` only when every advertised
operation is actually implemented:

```ts
decision.success = true
decision.sftp = {
    extensions: [{ name: "example@example.com", data: Buffer.from("1") }],
    maxConcurrentRequests: 32,
    maxOpenHandles: 128,
    maxReadLength: 64 * 1024,
    maxWriteLength: 64 * 1024,
}
```

Extension names are validated when the server session is constructed. The configured array,
entries, and opaque data buffers are snapshotted before use, so later application mutation cannot
change the version advertisement already assigned to that session. The server's public
`extensions` getter returns a new frozen snapshot, so mutating one of its data buffers cannot change
the live advertisement either. Extension data must be supplied as a `Buffer`. Set
`advertiseLimits: false` only when the application must suppress or independently implement the
limits extension. The built-in advertisement rejects a configured extension with the same name to
avoid two authorities. A zero `maxOpenHandles` disables opening handles and suppresses the built-in
advertisement by default because zero has the incompatible wire meaning “no fixed limit”; explicitly
combining that capacity with `advertiseLimits: true` is rejected.
The server option bag must be a plain object, `extensions` must be an array, and
`openSSHSymlinkArguments` must be a boolean. Explicit `null` values are rejected rather than
selecting defaults, including for every limit and `advertiseLimits`.

For `SYMLINK`, call `sftp.symlinkPaths(request)` to obtain semantic `targetPath` and `linkPath`
values. Session integration detects OpenSSH and Dropbear identifications and normalizes OpenSSH's
published argument reversal; `openSSHSymlinkArguments` can be set explicitly for a proxied or
otherwise unusual peer. The returned paths are owned copies and cannot mutate the request passed to
the Hooker handler.

Never use a client-supplied path directly with a local filesystem API. Resolve it beneath an
application-owned root, reject traversal outside that root, map issued opaque handles to
application-owned per-session resources, close all remaining resources on the SFTP `close` event,
and apply authorization to every operation rather than only `OPEN`.
