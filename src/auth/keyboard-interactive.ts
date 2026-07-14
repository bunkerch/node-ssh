import assert from "node:assert"
import type Client from "../Client.js"
import type { ClientHookerKeyboardInteractiveController } from "../Client.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthRequest from "../packets/UserAuthRequest.js"
import AuthMethod from "./AuthMethod.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthInfoRequest from "../packets/UserAuthInfoRequest.js"
import UserAuthInfoResponse from "../packets/UserAuthInfoResponse.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import { readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import { decodeSSHLanguageTag, encodeSSHLanguageTag } from "../utils/SSHText.js"
import { decodeSSHNameList, encodeSSHNameList } from "../utils/NameList.js"
import { encodeSSHName } from "../utils/SSHName.js"

export interface KeyboardInteractiveAuthMethodData {
    languageTag: string
    submethods: string
}

export default class KeyboardInteractiveAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.KeyboardInteractive
    get method_name() {
        return KeyboardInteractiveAuthMethod.method_name
    }

    data: KeyboardInteractiveAuthMethodData

    constructor(data: KeyboardInteractiveAuthMethodData) {
        this.data = { languageTag: data.languageTag, submethods: data.submethods }
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(
                encodeSSHName(
                    KeyboardInteractiveAuthMethod.method_name,
                    "SSH authentication method name",
                ),
            ),
            serializeBuffer(encodeSSHLanguageTag(this.data.languageTag)),
            serializeBuffer(
                encodeSSHNameList(
                    this.data.submethods.length === 0 ? [] : this.data.submethods.split(","),
                ),
            ),
        ])
    }

    static parse(raw: Buffer): KeyboardInteractiveAuthMethod {
        let languageTag: Buffer
        ;[languageTag, raw] = readNextBuffer(raw)
        let submethods: Buffer
        ;[submethods, raw] = readNextBuffer(raw)
        assert(raw.length === 0)
        return new KeyboardInteractiveAuthMethod({
            languageTag: decodeSSHLanguageTag(languageTag),
            submethods: decodeSSHNameList(submethods).join(","),
        })
    }

    static async handleAuthentication(client: Client): Promise<boolean> {
        if (!client.hooker.hasHooks("keyboardInteractive")) return false

        client.sendPacket(
            new UserAuthRequest({
                username: client.options.username,
                service_name: SSHServiceNames.Connection,
                method: new KeyboardInteractiveAuthMethod({ languageTag: "", submethods: "" }),
            }),
        )

        let round = 0
        while (true) {
            const answer = await AuthMethod.waitForAnswer!(client)
            if (answer instanceof UserAuthSuccess) return true
            if (answer instanceof UserAuthFailure) return false
            if (!(answer instanceof UserAuthInfoRequest)) return false

            const controller: ClientHookerKeyboardInteractiveController = { responses: undefined }
            const policyCompleted = await client.hooker.triggerHookChecked(
                "keyboardInteractive",
                Object.freeze({
                    username: client.options.username,
                    name: answer.data.name,
                    instruction: answer.data.instruction,
                    languageTag: answer.data.languageTag,
                    prompts: Object.freeze(
                        answer.data.prompts.map((prompt) => Object.freeze(prompt)),
                    ),
                    round,
                }),
                controller,
            )
            if (!policyCompleted || !controller.responses) return false
            if (controller.responses.length !== answer.data.prompts.length) {
                throw new Error("Keyboard-interactive response count does not match prompt count")
            }
            client.sendPacket(new UserAuthInfoResponse({ responses: controller.responses }))
            round++
        }
    }
}
