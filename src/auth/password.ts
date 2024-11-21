import assert from "assert"
import UserAuthRequest, { AuthMethod } from "../packets/UserAuthRequest.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import Client, { ClientHookerPasswordAuthController } from "../Client.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"

export interface PasswordAuthMethodData {
    change_password: boolean
    password: string
}
export default class PasswordAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.Password
    get method_name() {
        return PasswordAuthMethod.method_name
    }

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

    static async handleAuthentication(client: Client): Promise<boolean> {
        if (client.clientEncryptionAlgorithm?.alg_name === "none") {
            // we do not want to send the password
            // in clear text over the network
            client.debug(
                `[Authentication]`,
                `[Password]`,
                `Skipping password authentication because the channel is insecure: Encryption is disabled`,
            )
            return false
        }

        const controller: ClientHookerPasswordAuthController = {
            password: undefined,
        }
        await client.hooker.triggerHook(
            "passwordAuth",
            Object.freeze({ username: client.options.username! }),
            controller,
        )
        // no hook, or no password was provided by the user
        if (controller.password === undefined) {
            client.debug(
                `[Authentication]`,
                `[Password]`,
                `No password provided by the user; Skipping password authentication`,
            )
            return false
        }

        client.debug("Trying password authentication...")

        const seqno = client.sendPacket(
            new UserAuthRequest({
                username: client.options.username!,
                service_name: SSHServiceNames.Connection,
                method: new PasswordAuthMethod({
                    change_password: false,
                    password: controller.password,
                }),
            }),
        )
        const answer = await AuthMethod.waitForAnswer!(client, seqno)

        if (answer instanceof UserAuthSuccess) {
            return true
        }

        // TODO: We need to also support changing passwords
        // the SSH spec allows for a password change in the middle
        // of the authentication
        // not the priority and really rarely used
        // it also shares the same opcode as UserAuthPKOK
        // which is problematic, to say the least.
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
