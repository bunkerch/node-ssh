import { existsSync } from "node:fs"
import { createConnection, type Socket } from "node:net"
import PublicKey from "../utils/PublicKey.js"
import {
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import EncodedSignature from "../utils/Signature.js"
import { decodeSSHUTF8 } from "../utils/SSHText.js"
import Agent, { AgentError, AgentType } from "./Agent.js"

const SSH_AGENT_FAILURE = 5
const SSH_AGENTC_REQUEST_IDENTITIES = 11
const SSH_AGENT_IDENTITIES_ANSWER = 12
const SSH_AGENTC_SIGN_REQUEST = 13
const SSH_AGENT_SIGN_RESPONSE = 14
const SSH_AGENT_RSA_SHA2_256 = 2
const SSH_AGENT_RSA_SHA2_512 = 4
const MAX_AGENT_MESSAGE_LENGTH = 256 * 1024

export default class SSHAgent implements Agent<string> {
    type = AgentType.NonInteractive
    readonly socketPath: string

    constructor(socketPath = process.env.SSH_AUTH_SOCK) {
        if (!socketPath) {
            throw new SSHAgentError(
                "Could not find an SSH agent socket in $SSH_AUTH_SOCK; pass its path to new SSHAgent(path)",
            )
        }
        if (!existsSync(socketPath)) {
            throw new SSHAgentError(
                `SSH agent socket does not exist: ${JSON.stringify(socketPath)}`,
            )
        }
        this.socketPath = socketPath
    }

    async sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        const publicKey = await this.getPublicKey(id)
        const requestedAlgorithm = algorithm ?? publicKey.data.alg
        if (!publicKey.supportsSignatureAlgorithm(requestedAlgorithm)) {
            throw new SSHAgentError(
                `Signature algorithm ${requestedAlgorithm} is incompatible with ${publicKey.data.alg}`,
            )
        }
        const signatureAlgorithm = publicKey.signatureAlgorithmFor(requestedAlgorithm)
        const flags =
            signatureAlgorithm === "rsa-sha2-512"
                ? SSH_AGENT_RSA_SHA2_512
                : signatureAlgorithm === "rsa-sha2-256"
                  ? SSH_AGENT_RSA_SHA2_256
                  : 0
        const response = await this.request(
            Buffer.concat([
                Buffer.from([SSH_AGENTC_SIGN_REQUEST]),
                serializeBuffer(publicKey.serialize()),
                serializeBuffer(data),
                serializeUint32(flags),
            ]),
        )
        this.expectResponseType(response, SSH_AGENT_SIGN_RESPONSE, "sign data")

        try {
            const [signature, remaining] = readNextBuffer(response.subarray(1))
            if (remaining.length !== 0) throw new Error("signature response has trailing data")
            const encoded = EncodedSignature.parse(signature)
            if (encoded.data.alg !== signatureAlgorithm) {
                throw new Error(
                    `agent returned ${encoded.data.alg} instead of ${signatureAlgorithm}`,
                )
            }
            return encoded
        } catch (error) {
            throw new SSHAgentError("SSH agent returned an invalid signature response", {
                cause: error,
            })
        }
    }

    async getPublicKeys(): Promise<[string, PublicKey][]> {
        const response = await this.request(Buffer.from([SSH_AGENTC_REQUEST_IDENTITIES]))
        this.expectResponseType(response, SSH_AGENT_IDENTITIES_ANSWER, "list identities")

        try {
            let raw = response.subarray(1)
            const [count, afterCount] = readNextUint32(raw)
            raw = afterCount
            const keys: [string, PublicKey][] = []
            for (let index = 0; index < count; index++) {
                let keyBlob: Buffer
                let comment: Buffer
                ;[keyBlob, raw] = readNextBuffer(raw)
                ;[comment, raw] = readNextBuffer(raw)
                const decodedComment =
                    comment.length === 0
                        ? undefined
                        : decodeSSHUTF8(comment, "SSH agent identity comment")
                let publicKey: PublicKey
                try {
                    publicKey = PublicKey.parse(keyBlob)
                } catch {
                    continue
                }
                publicKey.data.comment = decodedComment
                keys.push([keyBlob.toString("base64"), publicKey])
            }
            if (raw.length !== 0) throw new Error("identities response has trailing data")
            return keys
        } catch (error) {
            throw new SSHAgentError("SSH agent returned an invalid identities response", {
                cause: error,
            })
        }
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        const identity = (await this.getPublicKeys()).find(([candidate]) => candidate === id)
        if (!identity) throw new SSHAgentError("SSH agent identity is no longer available")
        return identity[1]
    }

    getStream(): Promise<Socket> {
        return new Promise((resolve, reject) => {
            const socket = createConnection(this.socketPath)
            socket.once("connect", () => resolve(socket))
            socket.once("error", (error) => {
                socket.destroy()
                reject(new SSHAgentError("Could not connect to the SSH agent", { cause: error }))
            })
        })
    }

    private request(payload: Buffer): Promise<Buffer> {
        if (payload.length < 1 || payload.length > MAX_AGENT_MESSAGE_LENGTH) {
            return Promise.reject(new SSHAgentError("SSH agent request has an invalid length"))
        }

        return new Promise((resolve, reject) => {
            const socket = createConnection(this.socketPath)
            let settled = false
            let received = Buffer.alloc(0)
            const fail = (error: Error): void => {
                if (settled) return
                settled = true
                socket.destroy()
                reject(
                    error instanceof SSHAgentError
                        ? error
                        : new SSHAgentError("SSH agent request failed", { cause: error }),
                )
            }

            socket.once("connect", () => socket.write(serializeBuffer(payload)))
            socket.setTimeout(10_000, () =>
                fail(new SSHAgentError("SSH agent did not reply within 10 seconds")),
            )
            socket.on("data", (data: Buffer) => {
                if (settled) return
                received = Buffer.concat([received, data])
                if (received.length < 4) return
                const length = received.readUInt32BE(0)
                if (length < 1 || length > MAX_AGENT_MESSAGE_LENGTH) {
                    fail(new SSHAgentError("SSH agent response has an invalid length"))
                    return
                }
                if (received.length < length + 4) return
                if (received.length !== length + 4) {
                    fail(new SSHAgentError("SSH agent sent unsolicited response data"))
                    return
                }
                settled = true
                socket.destroy()
                resolve(received.subarray(4))
            })
            socket.once("error", fail)
            socket.once("end", () => fail(new SSHAgentError("SSH agent closed before replying")))
            socket.once("close", () => fail(new SSHAgentError("SSH agent closed before replying")))
        })
    }

    private expectResponseType(response: Buffer, expected: number, operation: string): void {
        if (response[0] === SSH_AGENT_FAILURE) {
            throw new SSHAgentError(`SSH agent refused to ${operation}`)
        }
        if (response[0] !== expected) {
            throw new SSHAgentError(
                `SSH agent returned response type ${String(response[0])} while trying to ${operation}`,
            )
        }
    }
}

export class SSHAgentError extends AgentError {
    name = "SSHAgentError"
}
