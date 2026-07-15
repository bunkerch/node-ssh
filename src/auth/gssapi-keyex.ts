import assert from "node:assert"

import type Client from "../Client.js"
import { clientConfigurationFor } from "../ConnectionConfiguration.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import { readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import AuthMethod, { type AuthenticationGenerationGuard } from "./AuthMethod.js"

export default class GSSAPIKeyExchangeAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.GSSAPIKeyExchange
    readonly method_name = GSSAPIKeyExchangeAuthMethod.method_name
    readonly mic: Buffer

    constructor(mic: Buffer) {
        if (!Buffer.isBuffer(mic) || mic.length === 0) {
            throw new TypeError("GSS-API key-exchange authentication MIC must be non-empty")
        }
        this.mic = Buffer.from(mic)
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(this.method_name, "ascii")),
            serializeBuffer(this.mic),
        ])
    }

    static parse(raw: Buffer): GSSAPIKeyExchangeAuthMethod {
        let mic: Buffer
        ;[mic, raw] = readNextBuffer(raw)
        assert(raw.length === 0, "Unexpected gssapi-keyex authentication data")
        return new GSSAPIKeyExchangeAuthMethod(mic)
    }

    static async handleAuthentication(
        client: Client,
        assertCurrent: AuthenticationGenerationGuard,
    ): Promise<boolean> {
        const { default: UserAuthRequest } = await import("../packets/UserAuthRequest.js")
        assertCurrent()
        const mic = await client.createGSSAPIKeyExchangeAuthenticationMIC(
            clientConfigurationFor(client).username,
            SSHServiceNames.Connection,
        )
        assertCurrent()
        client.sendPacket(
            new UserAuthRequest({
                username: clientConfigurationFor(client).username,
                service_name: SSHServiceNames.Connection,
                method: new GSSAPIKeyExchangeAuthMethod(mic),
            }),
        )
        const answer = await AuthMethod.waitForAnswer(client)
        assertCurrent()
        return answer instanceof UserAuthSuccess
    }
}
