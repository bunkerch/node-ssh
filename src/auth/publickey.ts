import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import Client from "../Client.js"
import PublicKey from "../utils/PublicKey.js"
import { AgentType } from "../publickey/Agent.js"
import { SSHServiceNames } from "../constants.js"

export interface PublicKeyAuthMethodData {
    publicKey: PublicKey
    signature?: Buffer
}
export default class PublicKeyAuthMethod implements AuthMethod {
    static method_name = "publickey"

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
            // eslint-disable-next-line no-extra-semi
            ;[signature, raw] = readNextBuffer(raw)
        }

        assert(raw.length === 0)

        return new PublicKeyAuthMethod({
            publicKey: publicKey,
            signature: signature,
        })
    }

    static async *getPackets(client: Client): AsyncGenerator<UserAuthRequest> {
        const keys = await client.options.agent.getPublicKeys()
        for (const key of keys) {
            try {
                client.debug(
                    `Trying publickey authentication with key ${key[0]} ${key[1].toString()}`,
                )
                const packet = new UserAuthRequest({
                    username: client.options.username,
                    service_name: SSHServiceNames.Connection,
                    method: new PublicKeyAuthMethod({
                        publicKey: key[1],
                    }),
                })

                if (client.options.agent.type === AgentType.NonInteractive) {
                    // prettier and eslint are fighting over this semicolon
                    // eslint-disable-next-line no-extra-semi
                    ;(packet.data.method as PublicKeyAuthMethod).data.signature =
                        await client.options.agent.sign(
                            key[0],
                            packet.serializeForSignature(client),
                        )
                }

                yield packet
            } catch (err) {
                console.error(err)
            }
        }
    }
}
