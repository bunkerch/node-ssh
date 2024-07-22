import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import Client from "../Client.js"
import PublicKey from "../utils/PublicKey.js"
import { AgentType } from "../publickey/Agent.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthPKOK from "../packets/UserAuthPKOK.js"
import { serializeMpintBufferToBuffer } from "../utils/mpint.js"

export interface PublicKeyAuthMethodData {
    publicKey: PublicKey
    signature?: Buffer
}
export default class PublicKeyAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.PublicKey

    data: PublicKeyAuthMethodData
    constructor(data: PublicKeyAuthMethodData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PublicKeyAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(this.data.signature !== undefined))
        buffers.push(serializeBuffer(Buffer.from(this.data.publicKey.data.alg, "utf-8")))
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        if (this.data.signature) {
            buffers.push(serializeBuffer(this.data.signature))
        }

        return Buffer.concat(buffers)
    }

    serializeForSignature(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PublicKeyAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(true))
        buffers.push(serializeBuffer(Buffer.from(this.data.publicKey.data.alg, "utf-8")))
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): AuthMethod {
        let hasSignature: boolean
        ;[hasSignature, raw] = readNextBinaryBoolean(raw)

        let publicKeyAlgorithmName: Buffer
        ;[publicKeyAlgorithmName, raw] = readNextBuffer(raw)

        let publicKeyBlob: Buffer
        ;[publicKeyBlob, raw] = readNextBuffer(raw)

        const publicKey = PublicKey.parse(publicKeyBlob)
        assert(publicKeyAlgorithmName.toString("utf-8") === publicKey.data.alg)

        let signature: Buffer | undefined
        if (hasSignature) {
            ;[signature, raw] = readNextBuffer(raw)
        }

        assert(raw.length === 0)

        return new PublicKeyAuthMethod({
            publicKey: publicKey,
            signature: signature,
        })
    }

    static async handleAuthentication(client: Client): Promise<boolean> {
        const keys = await client.options.agent.getPublicKeys()
        for (const key of keys) {
            try {
                client.debug(
                    `[Authentication]`,
                    `[PublicKey]`,
                    `Trying publickey authentication with key ${key[0]} ${key[1].toString()}`,
                )

                const method = new PublicKeyAuthMethod({
                    publicKey: key[1],
                })
                const packet = new UserAuthRequest({
                    username: client.options.username,
                    service_name: SSHServiceNames.Connection,
                    method: method,
                })

                // if this does not require any input from the user
                // that would be otherwise annoying, we directly sign
                // the packet. That will save us one packet if the pk
                // is correct.
                if (client.options.agent.type === AgentType.NonInteractive) {
                    method.data.signature = await client.options.agent.sign(
                        key[0],
                        packet.serializeForSignature(client),
                    )
                }

                while (true) {
                    const seqno = client.sendPacket(packet)
                    const answer = await AuthMethod.waitForAnswer!(client, seqno)

                    if (answer instanceof UserAuthSuccess) {
                        // public key accepted
                        // tell the client it's ok
                        return true
                    } else if (answer instanceof UserAuthFailure) {
                        // this public key won't be accepted.
                        // go try another one or fail
                        break
                    } else if (answer instanceof UserAuthPKOK) {
                        assert(
                            !method.data.signature,
                            "Server requested a public key signature, but a signature was already provided.",
                        )

                        const keys = await client.options.agent.getPublicKeys()
                        const key = keys.find((key) => key[1].equals(method.data.publicKey))
                        assert(
                            key,
                            "Server requested a signature from a public key that was not provided by the agent",
                        )

                        method.data.signature = await client.options.agent.sign(
                            key[0],
                            packet.serializeForSignature(client),
                        )
                    } else {
                        client.debug(
                            `[Authentication]`,
                            `[PublicKey]`,
                            `Unknown response to "UserAuthRequest" with method "publickey":`,
                            answer,
                        )
                        break
                    }
                }
            } catch (err) {
                client.debug(
                    `[Authentication]`,
                    `[PublicKey]`,
                    `Public Key authentication threw an error`,
                    err,
                )
            }
        }

        return false
    }
}
