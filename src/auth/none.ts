import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { serializeBuffer } from "../utils/Buffer.js"
import Client from "../Client.js"
import { SSHServiceNames } from "../constants.js"

export interface NoneAuthMethodData {}
export default class NoneAuthMethod implements AuthMethod {
    static method_name = "none"

    data: NoneAuthMethodData
    constructor(data: NoneAuthMethodData) {
        this.data = data
    }

    serialize(): Buffer {
        return serializeBuffer(Buffer.from(NoneAuthMethod.method_name, "utf-8"))
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        assert(raw.length === 0)
        return new NoneAuthMethod({})
    }

    static async *getPackets(client: Client): AsyncGenerator<UserAuthRequest> {
        yield new UserAuthRequest({
            username: client.options.username,
            service_name: SSHServiceNames.Connection,
            method: new NoneAuthMethod({}),
        })
    }
}
