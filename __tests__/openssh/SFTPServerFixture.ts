import { constants } from "node:fs"
import {
    chmod,
    chown,
    lstat,
    link,
    mkdir,
    open,
    readdir,
    readlink,
    rename,
    rmdir,
    stat,
    statfs,
    symlink,
    truncate,
    unlink,
    utimes,
    type FileHandle,
} from "node:fs/promises"
import { posix, resolve, sep } from "node:path"
import SFTPServer from "../../src/sftp/SFTPServer.js"
import { SFTPOpenFlags, SFTPStatusCode } from "../../src/sftp/constants.js"
import {
    decodeSFTPCopyDataExtension,
    decodeSFTPExtensionString,
    decodeSFTPHandleExtension,
    decodeSFTPTwoPathExtension,
    decodeSFTPUsersGroupsExtension,
    encodeSFTPStatVFS,
    encodeSFTPUsersGroups,
} from "../../src/sftp/openssh.js"
import type { SFTPAttributes, SFTPExtension } from "../../src/sftp/types.js"

interface FileResource {
    type: "file"
    file: FileHandle
}

interface DirectoryResource {
    type: "directory"
    path: string
    read: boolean
}

type Resource = FileResource | DirectoryResource

const FILESYSTEM_EXTENSION_VERSIONS: readonly (readonly [string, string])[] = [
    ["posix-rename@openssh.com", "1"],
    ["statvfs@openssh.com", "2"],
    ["hardlink@openssh.com", "1"],
    ["fsync@openssh.com", "1"],
    ["expand-path@openssh.com", "1"],
    ["copy-data", "1"],
    ["home-directory", "1"],
    ["users-groups-by-id@openssh.com", "1"],
]

export const FILESYSTEM_SFTP_EXTENSIONS: readonly SFTPExtension[] = Object.freeze(
    FILESYSTEM_EXTENSION_VERSIONS.map(([name, version]) =>
        Object.freeze({ name, data: Buffer.from(version) }),
    ),
)

export function attachFilesystemSFTPServer(server: SFTPServer, root: string): void {
    const resources = new Map<string, Resource>()
    let nextHandle = 0

    const issueHandle = (resource: Resource): Buffer => {
        const handle = Buffer.allocUnsafe(4)
        handle.writeUInt32BE(nextHandle++)
        resources.set(handle.toString("hex"), resource)
        return handle
    }
    const getResource = (handle: Buffer): Resource => {
        const resource = resources.get(handle.toString("hex"))
        if (!resource) throw Object.assign(new Error("Invalid SFTP handle"), { code: "EBADF" })
        return resource
    }
    const resolvePath = (encoded: Buffer): string => {
        const value = encoded.toString("utf8")
        const virtual = posix.resolve("/", value || ".")
        const resolved = resolve(root, `.${virtual}`)
        if (resolved !== root && !resolved.startsWith(`${root}${sep}`)) {
            throw Object.assign(new Error("Path escapes SFTP root"), { code: "EACCES" })
        }
        return resolved
    }
    const virtualPath = (encoded: Buffer): string =>
        posix.resolve("/", encoded.toString("utf8") || ".")
    const respond = async <T>(
        requestId: number,
        operation: () => Promise<T>,
        success: (value: T) => Promise<void>,
    ): Promise<void> => {
        try {
            await success(await operation())
        } catch (error) {
            const code = (error as NodeJS.ErrnoException).code
            const status =
                code === "ENOENT"
                    ? SFTPStatusCode.NoSuchFile
                    : code === "EACCES" || code === "EPERM"
                      ? SFTPStatusCode.PermissionDenied
                      : code === "ENOSYS" || code === "ENOTSUP"
                        ? SFTPStatusCode.OperationUnsupported
                        : SFTPStatusCode.Failure
            await server.status(
                requestId,
                status,
                error instanceof Error ? error.message : String(error),
            )
        }
    }

    server.hooker.hook("OPEN", async (_hook, request) => {
        const path = resolvePath(request.filename)
        await respond(
            request.requestId,
            () => open(path, nodeOpenFlags(request.flags), request.attributes.permissions ?? 0o666),
            (file) => server.handle(request.requestId, issueHandle({ type: "file", file })),
        )
    })
    server.hooker.hook("CLOSE", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const key = request.handle.toString("hex")
                const resource = getResource(request.handle)
                resources.delete(key)
                if (resource.type === "file") await resource.file.close()
            },
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("READ", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const resource = getResource(request.handle)
                if (resource.type !== "file")
                    throw Object.assign(new Error("Not a file"), { code: "EBADF" })
                const buffer = Buffer.allocUnsafe(request.length)
                const { bytesRead } = await resource.file.read(
                    buffer,
                    0,
                    request.length,
                    safePosition(request.offset),
                )
                return buffer.subarray(0, bytesRead)
            },
            (data) =>
                data.length === 0
                    ? server.status(request.requestId, SFTPStatusCode.EOF)
                    : server.data(request.requestId, data),
        )
    })
    server.hooker.hook("WRITE", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const resource = getResource(request.handle)
                if (resource.type !== "file")
                    throw Object.assign(new Error("Not a file"), { code: "EBADF" })
                let written = 0
                while (written < request.data.length) {
                    const result = await resource.file.write(
                        request.data,
                        written,
                        request.data.length - written,
                        safePosition(request.offset) + written,
                    )
                    if (result.bytesWritten === 0) throw new Error("File write made no progress")
                    written += result.bytesWritten
                }
            },
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("STAT", async (_hook, request) => {
        await respond(
            request.requestId,
            () => stat(resolvePath(request.path)),
            (value) => server.attributes(request.requestId, attributes(value)),
        )
    })
    server.hooker.hook("LSTAT", async (_hook, request) => {
        await respond(
            request.requestId,
            () => lstat(resolvePath(request.path)),
            (value) => server.attributes(request.requestId, attributes(value)),
        )
    })
    server.hooker.hook("FSTAT", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const resource = getResource(request.handle)
                if (resource.type !== "file") return stat(resource.path)
                return resource.file.stat()
            },
            (value) => server.attributes(request.requestId, attributes(value)),
        )
    })
    server.hooker.hook("SETSTAT", async (_hook, request) => {
        await respond(
            request.requestId,
            () => applyPathAttributes(resolvePath(request.path), request.attributes),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("FSETSTAT", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const resource = getResource(request.handle)
                if (resource.type !== "file")
                    throw Object.assign(new Error("Not a file"), { code: "EBADF" })
                await applyFileAttributes(resource.file, request.attributes)
            },
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("OPENDIR", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const path = resolvePath(request.path)
                await readdir(path)
                return path
            },
            (path) =>
                server.handle(
                    request.requestId,
                    issueHandle({ type: "directory", path, read: false }),
                ),
        )
    })
    server.hooker.hook("READDIR", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => {
                const resource = getResource(request.handle)
                if (resource.type !== "directory")
                    throw Object.assign(new Error("Not a directory"), { code: "EBADF" })
                if (resource.read) return null
                resource.read = true
                const names = await readdir(resource.path)
                return Promise.all(
                    names.map(async (filename) => ({
                        filename: Buffer.from(filename),
                        longname: Buffer.from(filename),
                        attributes: attributes(await lstat(resolve(resource.path, filename))),
                    })),
                )
            },
            (names) =>
                !names || names.length === 0
                    ? server.status(request.requestId, SFTPStatusCode.EOF)
                    : server.name(request.requestId, names),
        )
    })
    server.hooker.hook("REMOVE", async (_hook, request) => {
        await respond(
            request.requestId,
            () => unlink(resolvePath(request.path)),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("MKDIR", async (_hook, request) => {
        await respond(
            request.requestId,
            () => mkdir(resolvePath(request.path), { mode: request.attributes.permissions }),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("RMDIR", async (_hook, request) => {
        await respond(
            request.requestId,
            () => rmdir(resolvePath(request.path)),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("REALPATH", async (_hook, request) => {
        await respond(
            request.requestId,
            async () => virtualPath(request.path),
            (path) =>
                server.name(request.requestId, {
                    filename: Buffer.from(path),
                    longname: Buffer.from(path),
                    attributes: {},
                }),
        )
    })
    server.hooker.hook("RENAME", async (_hook, request) => {
        await respond(
            request.requestId,
            () => rename(resolvePath(request.firstPath), resolvePath(request.secondPath)),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("READLINK", async (_hook, request) => {
        await respond(
            request.requestId,
            () => readlink(resolvePath(request.path)),
            (target) =>
                server.name(request.requestId, {
                    filename: Buffer.from(target),
                    longname: Buffer.from(target),
                    attributes: {},
                }),
        )
    })
    server.hooker.hook("SYMLINK", async (_hook, request) => {
        const { targetPath, linkPath } = server.symlinkPaths(request)
        await respond(
            request.requestId,
            () => symlink(targetPath.toString("utf8"), resolvePath(linkPath)),
            () => server.status(request.requestId, SFTPStatusCode.Ok),
        )
    })
    server.hooker.hook("EXTENDED", async (_hook, request) => {
        switch (request.request) {
            case "posix-rename@openssh.com":
            case "hardlink@openssh.com": {
                const { firstPath, secondPath } = decodeSFTPTwoPathExtension(request.data)
                await respond(
                    request.requestId,
                    () =>
                        request.request === "posix-rename@openssh.com"
                            ? rename(resolvePath(firstPath), resolvePath(secondPath))
                            : link(resolvePath(firstPath), resolvePath(secondPath)),
                    () => server.status(request.requestId, SFTPStatusCode.Ok),
                )
                return
            }
            case "statvfs@openssh.com": {
                const path = decodeSFTPExtensionString(request.data)
                await respond(
                    request.requestId,
                    () => statfs(resolvePath(path), { bigint: true }),
                    (value) =>
                        server.extendedReply(
                            request.requestId,
                            encodeSFTPStatVFS({
                                blockSize: value.bsize,
                                fragmentSize: value.bsize,
                                blocks: value.blocks,
                                blocksFree: value.bfree,
                                blocksAvailable: value.bavail,
                                files: value.files,
                                filesFree: value.ffree,
                                filesAvailable: value.ffree,
                                filesystemId: 0n,
                                flags: 0n,
                                maximumFilenameLength: 255n,
                            }),
                        ),
                )
                return
            }
            case "fsync@openssh.com": {
                const handle = decodeSFTPHandleExtension(request.data)
                await respond(
                    request.requestId,
                    async () => {
                        const resource = getResource(handle)
                        if (resource.type !== "file") {
                            throw Object.assign(new Error("Not a file"), { code: "EBADF" })
                        }
                        await resource.file.sync()
                    },
                    () => server.status(request.requestId, SFTPStatusCode.Ok),
                )
                return
            }
            case "expand-path@openssh.com":
            case "home-directory": {
                const value = decodeSFTPExtensionString(request.data)
                const path =
                    request.request === "home-directory"
                        ? value.length === 0 || value.equals(Buffer.from("interop"))
                            ? "/"
                            : undefined
                        : value.equals(Buffer.from("~"))
                          ? "/"
                          : value.subarray(0, 2).equals(Buffer.from("~/"))
                            ? virtualPath(value.subarray(1))
                            : virtualPath(value)
                if (path === undefined) {
                    await server.status(request.requestId, SFTPStatusCode.NoSuchFile)
                    return
                }
                await server.name(request.requestId, {
                    filename: Buffer.from(path),
                    longname: Buffer.from(path),
                    attributes: {},
                })
                return
            }
            case "copy-data": {
                const copy = decodeSFTPCopyDataExtension(request.data)
                if (copy.sourceHandle.equals(copy.destinationHandle)) {
                    await server.status(request.requestId, SFTPStatusCode.InvalidParameter)
                    return
                }
                await respond(
                    request.requestId,
                    () => copyFileData(copy, getResource),
                    () => server.status(request.requestId, SFTPStatusCode.Ok),
                )
                return
            }
            case "users-groups-by-id@openssh.com": {
                const { uids, gids } = decodeSFTPUsersGroupsExtension(request.data)
                await server.extendedReply(
                    request.requestId,
                    encodeSFTPUsersGroups({
                        usernames: uids.map(String),
                        groupNames: gids.map(String),
                    }),
                )
                return
            }
            default:
                await server.status(request.requestId, SFTPStatusCode.OperationUnsupported)
        }
    })

    server.on("close", () => {
        for (const resource of resources.values()) {
            if (resource.type === "file") void resource.file.close().catch(() => undefined)
        }
        resources.clear()
    })
}

async function copyFileData(
    copy: ReturnType<typeof decodeSFTPCopyDataExtension>,
    getResource: (handle: Buffer) => Resource,
): Promise<void> {
    const source = getResource(copy.sourceHandle)
    const destination = getResource(copy.destinationHandle)
    if (source.type !== "file" || destination.type !== "file") {
        throw Object.assign(new Error("Not a file"), { code: "EBADF" })
    }
    let sourceOffset = safePosition(copy.sourceOffset)
    let destinationOffset = safePosition(copy.destinationOffset)
    let remaining = copy.length === 0n ? undefined : safePosition(copy.length)
    const buffer = Buffer.allocUnsafe(32 * 1024)
    while (remaining === undefined || remaining > 0) {
        const length = remaining === undefined ? buffer.length : Math.min(buffer.length, remaining)
        const { bytesRead } = await source.file.read(buffer, 0, length, sourceOffset)
        if (bytesRead === 0) break
        let written = 0
        while (written < bytesRead) {
            const result = await destination.file.write(
                buffer,
                written,
                bytesRead - written,
                destinationOffset + written,
            )
            if (result.bytesWritten === 0) throw new Error("File copy made no progress")
            written += result.bytesWritten
        }
        sourceOffset += bytesRead
        destinationOffset += bytesRead
        if (remaining !== undefined) remaining -= bytesRead
    }
}

function nodeOpenFlags(flags: number): number {
    let value =
        (flags & SFTPOpenFlags.Read) !== 0 && (flags & SFTPOpenFlags.Write) !== 0
            ? constants.O_RDWR
            : (flags & SFTPOpenFlags.Write) !== 0
              ? constants.O_WRONLY
              : constants.O_RDONLY
    if (flags & SFTPOpenFlags.Append) value |= constants.O_APPEND
    if (flags & SFTPOpenFlags.Create) value |= constants.O_CREAT
    if (flags & SFTPOpenFlags.Truncate) value |= constants.O_TRUNC
    if (flags & SFTPOpenFlags.Exclusive) value |= constants.O_EXCL
    return value
}

function safePosition(value: bigint): number {
    const position = Number(value)
    if (!Number.isSafeInteger(position))
        throw Object.assign(new Error("Offset is too large"), { code: "EFBIG" })
    return position
}

function attributes(value: Awaited<ReturnType<typeof stat>>): SFTPAttributes {
    return {
        size: BigInt(value.size),
        uid: value.uid,
        gid: value.gid,
        permissions: value.mode,
        accessTime: Math.floor(value.atimeMs / 1000),
        modificationTime: Math.floor(value.mtimeMs / 1000),
    }
}

async function applyPathAttributes(path: string, value: SFTPAttributes): Promise<void> {
    if (value.size !== undefined) await truncate(path, safePosition(value.size))
    if (value.uid !== undefined && value.gid !== undefined) await chown(path, value.uid, value.gid)
    if (value.permissions !== undefined) await chmod(path, value.permissions & 0o7777)
    if (value.accessTime !== undefined && value.modificationTime !== undefined) {
        await utimes(path, value.accessTime, value.modificationTime)
    }
}

async function applyFileAttributes(file: FileHandle, value: SFTPAttributes): Promise<void> {
    if (value.size !== undefined) await file.truncate(safePosition(value.size))
    if (value.uid !== undefined && value.gid !== undefined) await file.chown(value.uid, value.gid)
    if (value.permissions !== undefined) await file.chmod(value.permissions & 0o7777)
    if (value.accessTime !== undefined && value.modificationTime !== undefined) {
        await file.utimes(value.accessTime, value.modificationTime)
    }
}
