import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import NoneAuthMethod from "../auth/none.js"
import PasswordAuthMethod from "../auth/password.js"
import type Client from "../Client.js"
import PublicKeyAuthMethod, { HostboundPublicKeyAuthMethod } from "../auth/publickey.js"
import type ServerClient from "../ServerClient.js"
import KeyboardInteractiveAuthMethod from "../auth/keyboard-interactive.js"
import AuthMethod from "../auth/AuthMethod.js"
import HostbasedAuthMethod from "../auth/hostbased.js"
import type { AuthMethodClass } from "../auth/AuthMethod.js"

export { default as AuthMethod } from "../auth/AuthMethod.js"

export interface UserAuthRequestData {
    username: string
    // should be ssh-userauth ?
    service_name: string
    method: AuthMethod
}
export class UnknownAuthMethod implements AuthMethod {
    constructor(
        public method_name: string,
        public data: Buffer,
    ) {}

    serialize(): Buffer {
        return Buffer.concat([serializeBuffer(Buffer.from(this.method_name, "ascii")), this.data])
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
        ].map((method) => [method.method_name, method]),
    )

    data: UserAuthRequestData
    constructor(data: UserAuthRequestData) {
        this.data = data
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

        buffers.push(serializeBuffer(Buffer.from(this.data.username, "utf-8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))

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

        buffers.push(serializeBuffer(Buffer.from(this.data.username, "utf-8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))
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

        const methodName = method_name.toString("ascii")
        const method = UserAuthRequest.auth_methods.get(methodName)
        return new UserAuthRequest({
            username: username.toString("utf-8"),
            service_name: service_name.toString("utf-8"),
            method: method ? method.parse(raw) : new UnknownAuthMethod(methodName, raw),
        })
    }
}
