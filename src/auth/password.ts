import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import Client, { ClientHookerPasswordAuthController } from "../Client.js"
import { SSHServiceNames } from "../constants.js"

export interface PasswordAuthMethodData {
    change_password: boolean
    password: string
}
export default class PasswordAuthMethod implements AuthMethod {
    static method_name = "password"

    data: PasswordAuthMethodData
    constructor(data: PasswordAuthMethodData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PasswordAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(this.data.change_password))
        buffers.push(serializeBuffer(Buffer.from(this.data.password, "utf-8")))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): AuthMethod {
        let change_password: boolean
        ;[change_password, raw] = readNextBinaryBoolean(raw)

        let password: Buffer
        ;[password, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return new PasswordAuthMethod({
            change_password: change_password,
            password: password.toString("utf-8"),
        })
    }

    static async *getPackets(client: Client): AsyncGenerator<UserAuthRequest> {
        if (client.clientEncryptionAlgorithm?.alg_name === "none") {
            // we do not want to send the password
            // in clear text over the network
            client.debug("Skipping password authentication because encryption is disabled")
            return
        }

        const controller: ClientHookerPasswordAuthController = {
            password: undefined,
        }
        await client.hooker.triggerHook(
            "passwordAuth",
            Object.freeze({ username: client.options.username! }),
            controller,
        )
        if (controller.password === undefined) {
            client.debug("No password provided by the user")
            // no hook, or no password was provided by the user
            return
        }

        client.debug("Trying password authentication...")

        yield new UserAuthRequest({
            username: client.options.username!,
            service_name: SSHServiceNames.Connection,
            method: new PasswordAuthMethod({
                change_password: false,
                password: controller.password,
            }),
        })
    }
}
