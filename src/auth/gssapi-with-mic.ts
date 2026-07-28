import assert from "node:assert"
import type Client from "../Client.js"
import {
    clientAuthenticationConfigurationFor,
    clientConfigurationFor,
} from "../ConnectionConfiguration.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import {
    buildGSSAPIUserAuthMIC,
    closeGSSAPIContext,
    GSSAPIError,
    GSSAPI_WITH_MIC,
    normalizeGSSAPIContextStep,
    normalizeGSSAPIOID,
    normalizeGSSAPIToken,
    type GSSAPIClientContext,
} from "../GSSAPI.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import {
    UserAuthGSSAPIError,
    UserAuthGSSAPIErrorToken,
    UserAuthGSSAPIExchangeComplete,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIResponse,
    UserAuthGSSAPIToken,
} from "../packets/UserAuthGSSAPI.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import Unimplemented from "../packets/Unimplemented.js"
import type Packet from "../packet.js"
import PacketEventQueue from "../utils/PacketEventQueue.js"
import {
    readNextBuffer,
    readNextUint32,
    serializeBuffer,
    serializeUint32,
} from "../utils/Buffer.js"
import AuthMethod, { type AuthenticationGenerationGuard } from "./AuthMethod.js"

export interface GSSAPIWithMICAuthMethodData {
    mechanismOIDs: readonly Buffer[]
}

export default class GSSAPIWithMICAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.GSSAPIWithMIC
    readonly method_name = GSSAPIWithMICAuthMethod.method_name
    readonly data: Readonly<GSSAPIWithMICAuthMethodData>

    constructor(data: GSSAPIWithMICAuthMethodData) {
        if (!Array.isArray(data.mechanismOIDs) || data.mechanismOIDs.length === 0) {
            throw new TypeError("GSS-API authentication requires at least one mechanism OID")
        }
        this.data = Object.freeze({
            mechanismOIDs: Object.freeze(data.mechanismOIDs.map(normalizeGSSAPIOID)),
        })
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(GSSAPI_WITH_MIC, "ascii")),
            serializeUint32(this.data.mechanismOIDs.length),
            ...this.data.mechanismOIDs.map((oid) => serializeBuffer(normalizeGSSAPIOID(oid))),
        ])
    }

    static parse(raw: Buffer): GSSAPIWithMICAuthMethod {
        let count: number
        ;[count, raw] = readNextUint32(raw)
        assert(count > 0, "GSS-API authentication requires at least one mechanism OID")
        const mechanismOIDs: Buffer[] = []
        for (let index = 0; index < count; index++) {
            let oid: Buffer
            ;[oid, raw] = readNextBuffer(raw)
            mechanismOIDs.push(oid)
        }
        assert(raw.length === 0, "Unexpected GSS-API authentication request data")
        return new GSSAPIWithMICAuthMethod({ mechanismOIDs })
    }

    static async handleAuthentication(
        client: Client,
        assertCurrent: AuthenticationGenerationGuard,
    ): Promise<boolean> {
        const mechanisms = clientConfigurationFor(client).gssapi.filter(
            (mechanism) => mechanism.createContext !== undefined,
        )
        if (mechanisms.length === 0) return false

        // Imported only when authentication starts so this method module remains safe to
        // register from UserAuthRequest without introducing an eager module cycle.
        const { default: UserAuthRequest } = await import("../packets/UserAuthRequest.js")
        assertCurrent()

        const packets = new PacketEventQueue(
            client,
            () => new Error("SSH connection closed during GSS-API authentication"),
        )
        let context: GSSAPIClientContext | undefined

        try {
            const initialSequence = client.sendPacket(
                new UserAuthRequest({
                    username: clientAuthenticationConfigurationFor(client).username,
                    service_name: SSHServiceNames.Connection,
                    method: new GSSAPIWithMICAuthMethod({
                        mechanismOIDs: mechanisms.map(({ oid }) => oid),
                    }),
                }),
            )

            const response = await waitForGSSAPIAnswer(packets, initialSequence)
            assertCurrent()
            if (response instanceof UserAuthFailure) return false
            if (!(response instanceof UserAuthGSSAPIResponse)) return false
            const mechanism = mechanisms.find(({ oid }) => oid.equals(response.oid))
            if (!mechanism?.createContext) {
                throw new Error("SSH server selected an unoffered GSS-API mechanism")
            }

            context = await mechanism.createContext(
                Object.freeze({
                    hostname: clientConfigurationFor(client).hostname,
                    username: clientAuthenticationConfigurationFor(client).username,
                    service: SSHServiceNames.Connection,
                    delegateCredentials: clientConfigurationFor(client).gssapiDelegateCredentials,
                }),
            )
            assertCurrent()
            assertClientContext(context)
            let step = normalizeGSSAPIContextStep(await context.step())
            assertCurrent()
            while (true) {
                let outboundSequence: number | undefined
                if (step.token) {
                    outboundSequence = client.sendPacket(new UserAuthGSSAPIToken(step.token))
                }
                if (step.complete) {
                    assert(client.sessionID, "SSH session identifier is unavailable")
                    if (step.integrity) {
                        const micInput = buildGSSAPIUserAuthMIC(
                            client.sessionID,
                            clientAuthenticationConfigurationFor(client).username,
                            SSHServiceNames.Connection,
                        )
                        const mic = normalizeGSSAPIToken(
                            await context.getMIC(micInput),
                            "GSS-API MIC",
                        )
                        assertCurrent()
                        outboundSequence = client.sendPacket(new UserAuthGSSAPIMIC(mic))
                    } else {
                        outboundSequence = client.sendPacket(new UserAuthGSSAPIExchangeComplete())
                    }
                    return await waitForGSSAPICompletion(
                        client,
                        packets,
                        context,
                        assertCurrent,
                        outboundSequence,
                    )
                }

                const answer = await waitForGSSAPIAnswer(packets, outboundSequence)
                assertCurrent()
                if (answer instanceof UserAuthGSSAPIToken) {
                    step = normalizeGSSAPIContextStep(await context.step(answer.token))
                    assertCurrent()
                    continue
                }
                if (answer instanceof UserAuthGSSAPIError) {
                    client.emit("gssapiError", answer.data)
                    continue
                }
                if (answer instanceof UserAuthGSSAPIErrorToken) {
                    try {
                        await context.step(answer.token)
                        assertCurrent()
                    } catch {
                        assertCurrent()
                        client.debug("GSS-API mechanism rejected the server error token")
                    }
                    return await waitForGSSAPIFailure(client, packets, assertCurrent)
                }
                return answer instanceof UserAuthSuccess
            }
        } catch (error) {
            assertCurrent()
            if (error instanceof GSSAPIError && error.token) {
                client.sendPacket(new UserAuthGSSAPIErrorToken(error.token))
            }
            client.debug("GSS-API authentication failed")
            return false
        } finally {
            packets.close()
            if (context) {
                try {
                    await closeGSSAPIContext(context)
                } catch {
                    client.debug("Could not close the GSS-API client context")
                }
            }
        }
    }
}

async function waitForGSSAPICompletion(
    client: Client,
    packets: PacketEventQueue,
    context: GSSAPIClientContext,
    assertCurrent: AuthenticationGenerationGuard,
    sequenceNumber: number,
): Promise<boolean> {
    while (true) {
        const answer = await waitForGSSAPIAnswer(packets, sequenceNumber)
        assertCurrent()
        if (answer instanceof UserAuthSuccess) return true
        if (answer instanceof UserAuthFailure) return false
        if (answer instanceof Unimplemented) return false
        if (answer instanceof UserAuthGSSAPIError) {
            client.emit("gssapiError", answer.data)
            continue
        }
        if (answer instanceof UserAuthGSSAPIErrorToken) {
            try {
                await context.step(answer.token)
                assertCurrent()
            } catch {
                assertCurrent()
                client.debug("GSS-API mechanism rejected the server error token")
            }
            return await waitForGSSAPIFailure(client, packets, assertCurrent)
        }
        throw new Error("Unexpected SSH packet after GSS-API context completion")
    }
}

async function waitForGSSAPIFailure(
    client: Client,
    packets: PacketEventQueue,
    assertCurrent: AuthenticationGenerationGuard,
    sequenceNumber?: number,
): Promise<boolean> {
    while (true) {
        const answer = await waitForGSSAPIAnswer(packets, sequenceNumber)
        assertCurrent()
        if (answer instanceof UserAuthFailure) return false
        if (answer instanceof Unimplemented) return false
        if (answer instanceof UserAuthGSSAPIError) {
            client.emit("gssapiError", answer.data)
            continue
        }
        throw new Error("Expected SSH authentication failure after a GSS-API error token")
    }
}

async function waitForGSSAPIAnswer(
    packets: PacketEventQueue,
    sequenceNumber?: number,
): Promise<Packet> {
    while (true) {
        const packet = await packets.next()
        if (
            packet instanceof UserAuthGSSAPIResponse ||
            packet instanceof UserAuthGSSAPIToken ||
            packet instanceof UserAuthGSSAPIError ||
            packet instanceof UserAuthGSSAPIErrorToken ||
            packet instanceof UserAuthFailure ||
            packet instanceof UserAuthSuccess ||
            (packet instanceof Unimplemented &&
                sequenceNumber !== undefined &&
                packet.data.sequence_number === sequenceNumber)
        ) {
            return packet
        }
    }
}

function assertClientContext(context: unknown): asserts context is GSSAPIClientContext {
    if (
        typeof context !== "object" ||
        context === null ||
        typeof (context as { step?: unknown }).step !== "function" ||
        typeof (context as { getMIC?: unknown }).getMIC !== "function"
    ) {
        throw new TypeError("Invalid SSH client GSS-API context")
    }
}
