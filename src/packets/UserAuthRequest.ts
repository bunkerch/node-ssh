import assert from "assert"
import { SSHAuthenticationMethods, SSHPacketType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import NoneAuthMethod from "../auth/none.js"
import PasswordAuthMethod from "../auth/password.js"
import Client from "../Client.js"
import PublicKeyAuthMethod from "../auth/publickey.js"
import Unimplemented from "./Unimplemented.js"
import UserAuthFailure from "./UserAuthFailure.js"
import UserAuthSuccess from "./UserAuthSuccess.js"
import ServerClient from "../ServerClient.js"

export interface UserAuthRequestData {
    username: string
    // should be ssh-userauth ?
    service_name: string
    method: AuthMethod
}
export default class UserAuthRequest implements Packet {
    static type = SSHPacketType.SSH_MSG_USERAUTH_REQUEST
    static auth_methods = new Map<string, typeof AuthMethod>(
        [NoneAuthMethod, PublicKeyAuthMethod, PasswordAuthMethod].map((method) => [
            method.method_name,
            method,
        ]),
    )

    data: UserAuthRequestData
    constructor(data: UserAuthRequestData) {
        this.data = data
    }

    get username() {
        return this.data.username
    }
    get publicKey() {
        return this.data.method instanceof PublicKeyAuthMethod
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
            this.data.method instanceof PublicKeyAuthMethod,
            "Only PublicKeyAuthMethod is supported for signature serialization",
        )
        assert(client.sessionID, "Client sessionID is not set")
        const buffers = []

        buffers.push(serializeBuffer(client.sessionID!))

        buffers.push(serializeUint8(UserAuthRequest.type))

        buffers.push(serializeBuffer(Buffer.from(this.data.username, "utf-8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))
        buffers.push((this.data.method as PublicKeyAuthMethod).serializeForSignature())

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

        return new UserAuthRequest({
            username: username.toString("utf-8"),
            service_name: service_name.toString("utf-8"),
            // TODO: handle unknown auth methods
            method: UserAuthRequest.auth_methods.get(method_name.toString("utf-8"))!.parse(raw),
        })
    }
}

export abstract class AuthMethod {
    static method_name: SSHAuthenticationMethods
    method_name: SSHAuthenticationMethods

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: any) {
        throw new Error("Not implemented")
    }

    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static async handleAuthentication(client: Client): Promise<boolean> {
        throw new Error("Not implemented")
    }

    static async waitForAnswer?(
        client: Client,
        seqno: number,
    ): Promise<Unimplemented | UserAuthFailure | UserAuthSuccess> {
        const answer = await client.waitForPackets(
            {
                [SSHPacketType.SSH_MSG_UNIMPLEMENTED]: {
                    predicate: (packet: Unimplemented) => {
                        return packet.data.sequence_number === seqno
                    },
                },
                [SSHPacketType.SSH_MSG_USERAUTH_FAILURE]: {
                    predicate: () => true,
                },
                [SSHPacketType.SSH_MSG_USERAUTH_SUCCESS]: {
                    predicate: () => true,
                },
                [SSHPacketType.SSH_MSG_USERAUTH_PK_OK]: {
                    predicate: () => true,
                },
            },
            10000,
        )

        return answer
    }
}
