import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { serializeBuffer } from "../utils/Buffer.js"
import Client from "../Client.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"

export type NoneAuthMethodData = Record<never, never>
export default class NoneAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.None
    get method_name() {
        return NoneAuthMethod.method_name
    }

    data: NoneAuthMethodData
    constructor(data: NoneAuthMethodData) {
        this.data = data
    }

    serialize(): Buffer {
        return serializeBuffer(Buffer.from(NoneAuthMethod.method_name, "utf-8"))
    }

    static parse(raw: Buffer): AuthMethod {
        assert(raw.length === 0)
        return new NoneAuthMethod({})
    }

    static async handleAuthentication(client: Client) {
        const seqno = client.sendPacket(
            new UserAuthRequest({
                username: client.options.username,
                service_name: SSHServiceNames.Connection,
                method: new NoneAuthMethod({}),
            }),
        )

        const answer = await AuthMethod.waitForAnswer!(client, seqno)
        if (answer instanceof UserAuthSuccess) {
            return true
        }

        if (!(answer instanceof UserAuthFailure)) {
            client.debug(
                `[Authentication]`,
                `[None]`,
                `Unknown response to "UserAuthRequest" with method "none":`,
                answer,
            )
        }

        return false
    }
}
