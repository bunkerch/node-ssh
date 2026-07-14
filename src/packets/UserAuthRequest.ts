import assert from "assert"
import { PacketNameToType } from "../constants.js"
import type Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import NoneAuthMethod from "../auth/none.js"
import PasswordAuthMethod from "../auth/password.js"
import type Client from "../Client.js"
import PublicKeyAuthMethod, { HostboundPublicKeyAuthMethod } from "../auth/publickey.js"
import type ServerClient from "../ServerClient.js"
import KeyboardInteractiveAuthMethod from "../auth/keyboard-interactive.js"
import AuthMethod from "../auth/AuthMethod.js"
import HostbasedAuthMethod from "../auth/hostbased.js"
import GSSAPIWithMICAuthMethod from "../auth/gssapi-with-mic.js"
import GSSAPIKeyExchangeAuthMethod from "../auth/gssapi-keyex.js"
import type { AuthMethodClass } from "../auth/AuthMethod.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

export { default as AuthMethod } from "../auth/AuthMethod.js"

export interface UserAuthRequestData {
    username: string
    // should be ssh-userauth ?
    service_name: string
    method: AuthMethod
}
export class UnknownAuthMethod implements AuthMethod {
    method_name: string
    data: Buffer
    constructor(method_name: string, data: Buffer) {
        encodeSSHName(method_name, "SSH authentication method name")
        this.method_name = method_name
        this.data = Buffer.from(data)
    }

    serialize(): Buffer {
        return Buffer.concat([
            serializeBuffer(encodeSSHName(this.method_name, "SSH authentication method name")),
            this.data,
        ])
    }
}

export default class UserAuthRequest implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_REQUEST
    static auth_methods = new Map<string, AuthMethodClass>(
        [
            NoneAuthMethod,
            PublicKeyAuthMethod,
            HostboundPublicKeyAuthMethod,
            HostbasedAuthMethod,
            PasswordAuthMethod,
            KeyboardInteractiveAuthMethod,
            GSSAPIWithMICAuthMethod,
            GSSAPIKeyExchangeAuthMethod,
        ].map((method) => [method.method_name, method]),
    )

    data: UserAuthRequestData
    constructor(data: UserAuthRequestData) {
        encodeSSHUTF8(data.username, "SSH username")
        encodeSSHName(data.service_name, "SSH service name")
        encodeSSHName(data.method.method_name, "SSH authentication method name")
        this.data = { ...data }
    }

    get username() {
        return this.data.username
    }
    get publicKey() {
        return this.data.method instanceof PublicKeyAuthMethod ||
            this.data.method instanceof HostbasedAuthMethod
            ? this.data.method.data.publicKey
            : undefined
    }
    get password() {
        return this.data.method instanceof PasswordAuthMethod
            ? this.data.method.data.password
            : undefined
    }
    get method_name() {
        return this.data.method.method_name
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeUint8(UserAuthRequest.type))

        buffers.push(serializeBuffer(encodeSSHUTF8(this.data.username, "SSH username")))
        buffers.push(serializeBuffer(encodeSSHName(this.data.service_name, "SSH service name")))

        buffers.push(this.data.method.serialize())

        return Buffer.concat(buffers)
    }

    serializeForSignature(client: Client | ServerClient): Buffer {
        assert(
            this.data.method instanceof PublicKeyAuthMethod ||
                this.data.method instanceof HostbasedAuthMethod,
            "Authentication method does not support signature serialization",
        )
        assert(client.sessionID, "Client sessionID is not set")
        const buffers = []

        buffers.push(serializeBuffer(client.sessionID!))

        buffers.push(serializeUint8(UserAuthRequest.type))

        buffers.push(serializeBuffer(encodeSSHUTF8(this.data.username, "SSH username")))
        buffers.push(serializeBuffer(encodeSSHName(this.data.service_name, "SSH service name")))
        buffers.push(this.data.method.serializeForSignature())

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): UserAuthRequest {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthRequest.type)

        let username: Buffer
        ;[username, raw] = readNextBuffer(raw)

        let service_name: Buffer
        ;[service_name, raw] = readNextBuffer(raw)

        let method_name: Buffer
        ;[method_name, raw] = readNextBuffer(raw)

        const methodName = decodeSSHName(method_name, "SSH authentication method name")
        const method = UserAuthRequest.auth_methods.get(methodName)
        return new UserAuthRequest({
            username: decodeSSHUTF8(username, "SSH username"),
            service_name: decodeSSHName(service_name, "SSH service name"),
            method: method ? method.parse(raw) : new UnknownAuthMethod(methodName, raw),
        })
    }
}
