import assert from "assert"
import UserAuthRequest from "../packets/UserAuthRequest.js"
import AuthMethod from "./AuthMethod.js"
import { readNextBinaryBoolean, readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import type Client from "../Client.js"
import type { ClientHookerPasswordAuthController } from "../Client.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthPasswordChangeRequest from "../packets/UserAuthPasswordChangeRequest.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"

export interface PasswordAuthMethodData {
    change_password: boolean
    password: string
    newPassword?: string
}
export default class PasswordAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.Password
    get method_name() {
        return PasswordAuthMethod.method_name
    }

    data: PasswordAuthMethodData
    constructor(data: PasswordAuthMethodData) {
        this.data = {
            change_password: data.change_password,
            password: data.password,
            newPassword: data.newPassword,
        }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeBuffer(Buffer.from(PasswordAuthMethod.method_name, "utf-8")))

        buffers.push(serializeBinaryBoolean(this.data.change_password))
        buffers.push(serializeBuffer(encodeSSHUTF8(this.data.password, "SSH password")))
        if (this.data.change_password) {
            assert(this.data.newPassword !== undefined, "Password change requires a new password")
            buffers.push(serializeBuffer(encodeSSHUTF8(this.data.newPassword, "SSH new password")))
        }

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): AuthMethod {
        let change_password: boolean
        ;[change_password, raw] = readNextBinaryBoolean(raw)

        let password: Buffer
        ;[password, raw] = readNextBuffer(raw)

        let newPassword: Buffer | undefined
        if (change_password) {
            ;[newPassword, raw] = readNextBuffer(raw)
        }

        assert(raw.length === 0)

        return new PasswordAuthMethod({
            change_password: change_password,
            password: decodeSSHUTF8(password, "SSH password"),
            newPassword:
                newPassword === undefined
                    ? undefined
                    : decodeSSHUTF8(newPassword, "SSH new password"),
        })
    }

    static async handleAuthentication(client: Client): Promise<boolean> {
        if (client.negotiatedAlgorithms?.cs.cipher === "none") {
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
        const policyCompleted = await client.hooker.triggerHookChecked(
            "passwordAuth",
            Object.freeze({ username: client.options.username! }),
            controller,
        )
        // no hook, or no password was provided by the user
        if (!policyCompleted || controller.password === undefined) {
            client.debug(
                `[Authentication]`,
                `[Password]`,
                `No password provided by the user; Skipping password authentication`,
            )
            return false
        }

        client.debug("Trying password authentication...")

        const method = new PasswordAuthMethod({
            change_password: false,
            password: controller.password,
        })
        while (true) {
            client.sendPacket(
                new UserAuthRequest({
                    username: client.options.username!,
                    service_name: SSHServiceNames.Connection,
                    method,
                }),
            )
            const answer = await AuthMethod.waitForAnswer!(client)
            if (answer instanceof UserAuthSuccess) return true
            if (answer instanceof UserAuthFailure) return false
            if (!(answer instanceof UserAuthPasswordChangeRequest)) return false

            const passwordChangeController = { newPassword: undefined as string | undefined }
            const policyCompleted = await client.hooker.triggerHookChecked(
                "passwordChange",
                Object.freeze({
                    username: client.options.username,
                    prompt: answer.data.prompt,
                    languageTag: answer.data.languageTag,
                }),
                passwordChangeController,
            )
            if (!policyCompleted || passwordChangeController.newPassword === undefined) return false
            method.data.change_password = true
            method.data.newPassword = passwordChangeController.newPassword
        }
    }
}
