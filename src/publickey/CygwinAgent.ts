import { execFile } from "node:child_process"
import { timingSafeEqual } from "node:crypto"
import { open } from "node:fs/promises"
import { createConnection, type Socket } from "node:net"
import { promisify } from "node:util"

import PublicKey from "../utils/PublicKey.js"
import EncodedSignature from "../utils/Signature.js"
import Agent, { AgentError, AgentType } from "./Agent.js"
import { SSHAgentProtocolClient } from "./SSHAgentProtocol.js"

const execFileAsync = promisify(execFile)
const DEFAULT_HANDSHAKE_TIMEOUT = 10_000
const DEFAULT_MAX_SOCKET_FILE_LENGTH = 4096
const MAX_TIMER_DELAY = 0x7fff_ffff
const handshakeDeadlineCleanup = new WeakMap<Socket, () => void>()
const SOCKET_DESCRIPTOR = /^!<socket >([0-9]{1,5}) s ([0-9a-f]{8}(?:-[0-9a-f]{8}){3})\0?$/iu

export interface CygwinAgentOptions {
    /** Maximum idle milliseconds for each TCP handshake. Zero disables the deadline. */
    handshakeTimeout?: number
    /** Maximum bytes read from the Cygwin socket descriptor file. */
    maxSocketFileLength?: number
}

interface CygwinSocketDescriptor {
    port: number
    secret: Buffer
}

function validateOptions(options: CygwinAgentOptions): Required<CygwinAgentOptions> {
    const handshakeTimeout = options.handshakeTimeout ?? DEFAULT_HANDSHAKE_TIMEOUT
    const maxSocketFileLength = options.maxSocketFileLength ?? DEFAULT_MAX_SOCKET_FILE_LENGTH
    if (
        !Number.isSafeInteger(handshakeTimeout) ||
        handshakeTimeout < 0 ||
        handshakeTimeout > MAX_TIMER_DELAY
    ) {
        throw new RangeError(
            "Cygwin agent handshake timeout must be an integer between zero and 2147483647",
        )
    }
    if (
        !Number.isSafeInteger(maxSocketFileLength) ||
        maxSocketFileLength < 1 ||
        maxSocketFileLength > 1024 * 1024
    ) {
        throw new RangeError(
            "Cygwin agent socket-file limit must be an integer between one and 1048576",
        )
    }
    return { handshakeTimeout, maxSocketFileLength }
}

async function readBoundedFile(path: string, maximumLength: number): Promise<Buffer> {
    const handle = await open(path, "r")
    try {
        const data = Buffer.alloc(maximumLength + 1)
        let length = 0
        while (length < data.length) {
            const result = await handle.read(data, length, data.length - length, length)
            if (result.bytesRead === 0) break
            length += result.bytesRead
        }
        if (length === 0 || length > maximumLength) {
            throw new CygwinAgentError("Cygwin agent socket descriptor has an invalid length")
        }
        return data.subarray(0, length)
    } finally {
        await handle.close()
    }
}

function parseSocketDescriptor(data: Buffer): CygwinSocketDescriptor {
    if (!data.every((value) => value <= 0x7f)) {
        throw new CygwinAgentError("Cygwin agent socket descriptor must contain only ASCII")
    }
    const match = SOCKET_DESCRIPTOR.exec(data.toString("ascii"))
    if (!match) throw new CygwinAgentError("Malformed Cygwin agent socket descriptor")
    const port = Number(match[1])
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
        throw new CygwinAgentError("Cygwin agent socket descriptor contains an invalid port")
    }
    const secret = Buffer.from(match[2].replaceAll("-", ""), "hex")
    if (secret.length !== 16) {
        throw new CygwinAgentError("Cygwin agent socket descriptor contains an invalid secret")
    }
    secret.swap32()
    return { port, secret }
}

async function readExactly(socket: Socket, length: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const result = Buffer.alloc(length)
        let offset = 0
        const cleanup = (): void => {
            socket.off("readable", onReadable)
            socket.off("end", onEnd)
            socket.off("close", onClose)
            socket.off("error", onError)
        }
        const fail = (error: Error): void => {
            cleanup()
            result.fill(0)
            reject(error)
        }
        const onEnd = (): void =>
            fail(new CygwinAgentError("Cygwin agent closed during its security handshake"))
        const onClose = (): void =>
            fail(new CygwinAgentError("Cygwin agent closed during its security handshake"))
        const onError = (error: Error): void => fail(error)
        const onReadable = (): void => {
            while (offset < length) {
                const chunk = socket.read(length - offset) as Buffer | null
                if (chunk === null) break
                chunk.copy(result, offset)
                offset += chunk.length
            }
            if (offset !== length) return
            cleanup()
            resolve(result)
        }
        socket.on("readable", onReadable)
        socket.once("end", onEnd)
        socket.once("close", onClose)
        socket.once("error", onError)
        onReadable()
    })
}

async function writeAll(socket: Socket, data: Buffer): Promise<void> {
    if (socket.destroyed || !socket.writable) {
        throw new CygwinAgentError("Cygwin agent closed during its security handshake")
    }
    if (socket.write(data)) return
    await new Promise<void>((resolve, reject) => {
        const cleanup = (): void => {
            socket.off("drain", onDrain)
            socket.off("close", onClose)
            socket.off("error", onError)
        }
        const onDrain = (): void => {
            cleanup()
            resolve()
        }
        const onClose = (): void => {
            cleanup()
            reject(new CygwinAgentError("Cygwin agent closed during its security handshake"))
        }
        const onError = (error: Error): void => {
            cleanup()
            reject(error)
        }
        socket.once("drain", onDrain)
        socket.once("close", onClose)
        socket.once("error", onError)
    })
}

/** A signing agent transported through Cygwin's legacy AF_UNIX socket-file protocol. */
export default class CygwinAgent extends Agent<string> {
    readonly type = AgentType.NonInteractive
    readonly socketPath: string
    readonly options: Readonly<Required<CygwinAgentOptions>>

    constructor(socketPath: string, options: CygwinAgentOptions = {}) {
        super()
        if (
            typeof socketPath !== "string" ||
            socketPath.length === 0 ||
            socketPath.includes("\0")
        ) {
            throw new TypeError(
                "Cygwin agent socket path must be a non-empty string without NUL bytes",
            )
        }
        this.socketPath = socketPath
        this.options = Object.freeze(validateOptions(options))
    }

    getPublicKeys(): Promise<[string, PublicKey][]> {
        return this.#withProtocol((protocol) => protocol.getPublicKeys())
    }

    getPublicKey(id: string): Promise<PublicKey> {
        return this.#withProtocol((protocol) => protocol.getPublicKey(id))
    }

    sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        if (!Buffer.isBuffer(data)) {
            return Promise.reject(new TypeError("Cygwin agent signing data must be a buffer"))
        }
        const message = Buffer.from(data)
        return this.#withProtocol((protocol) => protocol.sign(id, message, algorithm))
    }

    async getStream(): Promise<Socket> {
        const descriptor = await this.#readSocketDescriptor()
        const emptyCredentials = Buffer.alloc(12)
        let discoveredCredentials: Buffer | undefined
        let credentials: Buffer | undefined
        try {
            const discovery = await this.#connect(descriptor)
            try {
                discoveredCredentials = await this.#negotiate(
                    discovery,
                    descriptor.secret,
                    emptyCredentials,
                )
            } finally {
                handshakeDeadlineCleanup.get(discovery)?.()
                discovery.destroy()
            }

            credentials = Buffer.from(discoveredCredentials)
            credentials.writeUInt32LE(process.pid, 0)
            const socket = await this.#connect(descriptor)
            try {
                const peerCredentials = await this.#negotiate(
                    socket,
                    descriptor.secret,
                    credentials,
                )
                peerCredentials.fill(0)
                handshakeDeadlineCleanup.get(socket)?.()
                return socket
            } catch (error) {
                handshakeDeadlineCleanup.get(socket)?.()
                socket.destroy()
                throw error
            }
        } finally {
            descriptor.secret.fill(0)
            emptyCredentials.fill(0)
            discoveredCredentials?.fill(0)
            credentials?.fill(0)
        }
    }

    async #readSocketDescriptor(): Promise<CygwinSocketDescriptor> {
        let path = this.socketPath
        let data: Buffer
        try {
            data = await readBoundedFile(path, this.options.maxSocketFileLength)
        } catch (initialError) {
            const missingPath =
                typeof initialError === "object" &&
                initialError !== null &&
                "code" in initialError &&
                (initialError.code === "ENOENT" || initialError.code === "ENOTDIR")
            if (process.platform !== "win32" || !missingPath) {
                if (initialError instanceof CygwinAgentError) throw initialError
                throw new CygwinAgentError("Could not read the Cygwin agent socket descriptor", {
                    cause: initialError,
                })
            }
            try {
                const result = await execFileAsync("cygpath", ["-w", path], {
                    encoding: "utf8",
                    maxBuffer: this.options.maxSocketFileLength,
                    windowsHide: true,
                })
                path = result.stdout.replace(/[\r\n]+$/u, "")
                if (path.length === 0) throw new Error("cygpath returned an empty path")
                data = await readBoundedFile(path, this.options.maxSocketFileLength)
            } catch (error) {
                throw new CygwinAgentError("Could not read the Cygwin agent socket descriptor", {
                    cause: error,
                })
            }
        }
        try {
            return parseSocketDescriptor(data)
        } finally {
            data.fill(0)
        }
    }

    async #connect(descriptor: CygwinSocketDescriptor): Promise<Socket> {
        const socket = createConnection({ host: "127.0.0.1", port: descriptor.port })
        const onTimeout = (): void => {
            socket.destroy(new CygwinAgentError("Cygwin agent security handshake timed out"))
        }
        if (this.options.handshakeTimeout !== 0) {
            socket.setTimeout(this.options.handshakeTimeout)
            socket.once("timeout", onTimeout)
            handshakeDeadlineCleanup.set(socket, () => {
                socket.setTimeout(0)
                socket.off("timeout", onTimeout)
                handshakeDeadlineCleanup.delete(socket)
            })
        }
        try {
            await new Promise<void>((resolve, reject) => {
                const cleanup = (): void => {
                    socket.off("connect", onConnect)
                    socket.off("error", onError)
                }
                const onConnect = (): void => {
                    cleanup()
                    resolve()
                }
                const onError = (error: Error): void => {
                    cleanup()
                    reject(error)
                }
                socket.once("connect", onConnect)
                socket.once("error", onError)
            })
            return socket
        } catch (error) {
            handshakeDeadlineCleanup.get(socket)?.()
            socket.destroy()
            if (error instanceof CygwinAgentError) throw error
            throw new CygwinAgentError("Could not connect to the Cygwin agent", { cause: error })
        }
    }

    async #negotiate(socket: Socket, secret: Buffer, credentials: Buffer): Promise<Buffer> {
        let echoedSecret: Buffer | undefined
        try {
            await writeAll(socket, secret)
            echoedSecret = await readExactly(socket, secret.length)
            if (!timingSafeEqual(echoedSecret, secret)) {
                throw new CygwinAgentError("Cygwin agent returned the wrong socket secret")
            }
            await writeAll(socket, credentials)
            return await readExactly(socket, 12)
        } catch (error) {
            if (error instanceof CygwinAgentError) throw error
            throw new CygwinAgentError("Cygwin agent security handshake failed", { cause: error })
        } finally {
            echoedSecret?.fill(0)
        }
    }

    async #withProtocol<T>(
        operation: (protocol: SSHAgentProtocolClient) => Promise<T>,
    ): Promise<T> {
        const socket = await this.getStream()
        const protocol = new SSHAgentProtocolClient(socket)
        try {
            return await operation(protocol)
        } catch (error) {
            throw new CygwinAgentError("Cygwin agent request failed", { cause: error })
        } finally {
            protocol.destroy()
        }
    }
}

export class CygwinAgentError extends AgentError {
    name = "CygwinAgentError"
}
