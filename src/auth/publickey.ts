import assert from "assert"
import UserAuthRequest from "../packets/UserAuthRequest.js"
import AuthMethod, { type AuthenticationGenerationGuard } from "./AuthMethod.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import type Client from "../Client.js"
import { clientAuthenticationConfigurationFor } from "../ConnectionConfiguration.js"
import PublicKey from "../utils/PublicKey.js"
import Agent, { AgentType } from "../publickey/Agent.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthPKOK from "../packets/UserAuthPKOK.js"
import EncodedSignature from "../utils/Signature.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

interface AuthenticationAgentIdentity {
    readonly id: string
    readonly publicKey: PublicKey
}

function snapshotAgentIdentities(value: unknown): readonly AuthenticationAgentIdentity[] {
    if (!Array.isArray(value)) {
        throw new TypeError("SSH authentication agent returned an invalid identity list")
    }
    return Object.freeze(
        value.map((entry) => {
            if (
                !Array.isArray(entry) ||
                entry.length !== 2 ||
                typeof entry[0] !== "string" ||
                !(entry[1] instanceof PublicKey)
            ) {
                throw new TypeError("SSH authentication agent returned an invalid identity")
            }
            return Object.freeze({
                id: entry[0],
                publicKey: PublicKey.parse(entry[1].serialize()),
            })
        }),
    )
}

async function signAuthenticationRequest(
    agent: Agent,
    id: string,
    method: PublicKeyAuthMethod,
    packet: UserAuthRequest,
    client: Client,
    algorithm: string,
): Promise<EncodedSignature> {
    const signedData = packet.serializeForSignature(client)
    const agentData = Buffer.from(signedData)
    try {
        const suppliedSignature = await agent.sign(id, agentData, algorithm)
        if (!(suppliedSignature instanceof EncodedSignature)) {
            throw new TypeError("SSH authentication agent returned an invalid signature")
        }
        const signature = EncodedSignature.parse(suppliedSignature.serialize())
        assert(
            method.data.publicKey.verifySignature(signedData, signature),
            "SSH authentication agent returned an invalid signature",
        )
        return signature
    } finally {
        signedData.fill(0)
        agentData.fill(0)
    }
}

export interface PublicKeyAuthMethodData {
    publicKey: PublicKey
    algorithm?: string
    signature?: EncodedSignature
}

export interface HostboundPublicKeyAuthMethodData extends PublicKeyAuthMethodData {
    serverHostKey: Buffer
}
export default class PublicKeyAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.PublicKey
    get method_name() {
        return PublicKeyAuthMethod.method_name
    }

    data: PublicKeyAuthMethodData
    constructor(data: PublicKeyAuthMethodData) {
        const algorithm = data.algorithm ?? data.publicKey.data.alg
        encodeSSHName(algorithm, "SSH public-key signature algorithm")
        assert(
            data.publicKey.supportsSignatureAlgorithm(algorithm),
            `Signature algorithm ${algorithm} is incompatible with ${data.publicKey.data.alg}`,
        )
        this.data = { ...data, algorithm }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PublicKeyAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(this.data.signature !== undefined))
        buffers.push(
            serializeBuffer(
                encodeSSHName(this.data.algorithm!, "SSH public-key signature algorithm"),
            ),
        )
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        if (this.data.signature) {
            buffers.push(serializeBuffer(this.data.signature.serialize()))
        }

        return Buffer.concat(buffers)
    }

    serializeForSignature(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PublicKeyAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(true))
        buffers.push(
            serializeBuffer(
                encodeSSHName(this.data.algorithm!, "SSH public-key signature algorithm"),
            ),
        )
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
        const algorithm = decodeSSHName(
            publicKeyAlgorithmName,
            "SSH public-key signature algorithm",
        )
        assert(publicKey.supportsSignatureAlgorithm(algorithm))

        let signature: Buffer | undefined
        if (hasSignature) {
            ;[signature, raw] = readNextBuffer(raw)
        }

        assert(raw.length === 0)

        const encodedSignature = signature ? EncodedSignature.parse(signature) : undefined
        assert(
            !encodedSignature ||
                encodedSignature.data.alg === publicKey.signatureAlgorithmFor(algorithm),
        )
        return new PublicKeyAuthMethod({
            publicKey: publicKey,
            algorithm,
            signature: encodedSignature,
        })
    }

    static async handleAuthentication(
        client: Client,
        assertCurrent: AuthenticationGenerationGuard,
    ): Promise<boolean> {
        const agent = clientAuthenticationConfigurationFor(client).agent
        const keys = snapshotAgentIdentities(await agent.getPublicKeys())
        assertCurrent()
        for (const key of keys) {
            const configuredAlgorithms =
                clientAuthenticationConfigurationFor(client).authenticationSignatureAlgorithms
            const algorithms = key.publicKey.signatureAlgorithms.filter(
                (algorithm) =>
                    configuredAlgorithms.includes(algorithm) &&
                    (!client.serverSignatureAlgorithms ||
                        client.serverSignatureAlgorithms.includes(algorithm) ||
                        client.serverSignatureAlgorithms.includes(
                            key.publicKey.signatureAlgorithmFor(algorithm),
                        )),
            )
            for (const algorithm of algorithms) {
                try {
                    client.debug(
                        `[Authentication]`,
                        `[PublicKey]`,
                        `Trying publickey authentication with ${key.publicKey.data.alg} key ${key.publicKey.hash("sha256")}`,
                    )

                    const method = client.hostboundPublicKeyAuthentication
                        ? new HostboundPublicKeyAuthMethod({
                              publicKey: key.publicKey,
                              algorithm,
                              serverHostKey: Buffer.from(client.serverHostKey!),
                          })
                        : new PublicKeyAuthMethod({ publicKey: key.publicKey, algorithm })
                    const packet = new UserAuthRequest({
                        username: clientAuthenticationConfigurationFor(client).username,
                        service_name: SSHServiceNames.Connection,
                        method: method,
                    })

                    // if this does not require unknown input from the user
                    // that would be otherwise annoying, we directly sign
                    // the packet. That will save us one packet if the pk
                    // is correct.
                    if (
                        clientAuthenticationConfigurationFor(client).agent.type ===
                        AgentType.NonInteractive
                    ) {
                        method.data.signature = await signAuthenticationRequest(
                            agent,
                            key.id,
                            method,
                            packet,
                            client,
                            algorithm,
                        )
                        assertCurrent()
                    }

                    while (true) {
                        const seqno = client.sendPacket(packet)
                        const answer = await AuthMethod.waitForAnswer!(client, seqno)
                        assertCurrent()

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

                            const keys = snapshotAgentIdentities(await agent.getPublicKeys())
                            assertCurrent()
                            const key = keys.find((key) =>
                                key.publicKey.equals(method.data.publicKey),
                            )
                            assert(
                                key,
                                "Server requested a signature from a public key that was not provided by the agent",
                            )
                            assert(
                                answer.data.algorithm === algorithm &&
                                    answer.data.publicKey.equals(method.data.publicKey),
                                "Server requested a different public key algorithm",
                            )

                            method.data.signature = await signAuthenticationRequest(
                                agent,
                                key.id,
                                method,
                                packet,
                                client,
                                algorithm,
                            )
                            assertCurrent()
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
                } catch {
                    client.debug(
                        `[Authentication]`,
                        `[PublicKey]`,
                        `Public key authentication attempt failed`,
                    )
                    assertCurrent()
                }
            }
        }

        return false
    }
}

export class HostboundPublicKeyAuthMethod extends PublicKeyAuthMethod {
    static method_name = SSHAuthenticationMethods.HostboundPublicKey

    declare data: HostboundPublicKeyAuthMethodData

    constructor(data: HostboundPublicKeyAuthMethodData) {
        super(data)
        assert(
            data.serverHostKey.length > 0,
            "Host-bound authentication requires a server host key",
        )
        PublicKey.parse(data.serverHostKey)
        this.data = { ...data, serverHostKey: Buffer.from(data.serverHostKey) }
    }

    get method_name() {
        return HostboundPublicKeyAuthMethod.method_name
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.method_name, "ascii")),
            serializeBinaryBoolean(this.data.signature !== undefined),
            serializeBuffer(
                encodeSSHName(this.data.algorithm!, "SSH public-key signature algorithm"),
            ),
            serializeBuffer(this.data.publicKey.serialize()),
            serializeBuffer(this.data.serverHostKey),
            ...(this.data.signature ? [serializeBuffer(this.data.signature.serialize())] : []),
        ])
    }

    serializeForSignature(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.method_name, "ascii")),
            serializeBinaryBoolean(true),
            serializeBuffer(
                encodeSSHName(this.data.algorithm!, "SSH public-key signature algorithm"),
            ),
            serializeBuffer(this.data.publicKey.serialize()),
            serializeBuffer(this.data.serverHostKey),
        ])
    }

    static parse(raw: Buffer): HostboundPublicKeyAuthMethod {
        let hasSignature: boolean
        let algorithmBuffer: Buffer
        let publicKeyBlob: Buffer
        let serverHostKey: Buffer
        ;[hasSignature, raw] = readNextBinaryBoolean(raw)
        ;[algorithmBuffer, raw] = readNextBuffer(raw)
        ;[publicKeyBlob, raw] = readNextBuffer(raw)
        ;[serverHostKey, raw] = readNextBuffer(raw)

        const publicKey = PublicKey.parse(publicKeyBlob)
        const algorithm = decodeSSHName(algorithmBuffer, "SSH public-key signature algorithm")
        assert(publicKey.supportsSignatureAlgorithm(algorithm))

        let signature: Buffer | undefined
        if (hasSignature) [signature, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        const encodedSignature = signature ? EncodedSignature.parse(signature) : undefined
        assert(
            !encodedSignature ||
                encodedSignature.data.alg === publicKey.signatureAlgorithmFor(algorithm),
        )
        return new HostboundPublicKeyAuthMethod({
            publicKey,
            algorithm,
            signature: encodedSignature,
            serverHostKey,
        })
    }

    static handleAuthentication(
        client: Client,
        assertCurrent: AuthenticationGenerationGuard,
    ): Promise<boolean> {
        return PublicKeyAuthMethod.handleAuthentication(client, assertCurrent)
    }
}
