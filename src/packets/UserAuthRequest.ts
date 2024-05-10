import assert from "assert";
import { SSHPacketType } from "../constants.js";
import Packet from "../packet.js";
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js";
import NoneAuthMethod from "../auth/none.js";

export interface UserAuthRequestData {
    username: string,
    // should be ssh-userauth ?
    service_name: string,
    method: AuthMethod,
}
export default class UserAuthRequest implements Packet {
    static type = SSHPacketType.SSH_MSG_USERAUTH_REQUEST
    static auth_methods = new Map<string, typeof AuthMethod>(
        [
            NoneAuthMethod
        ].map(method => [method.method_name, method])
    )

    data: UserAuthRequestData
    constructor(data: UserAuthRequestData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeUint8(UserAuthRequest.type))

        buffers.push(serializeBuffer(Buffer.from(this.data.username, "utf-8")))
        buffers.push(serializeBuffer(Buffer.from(this.data.service_name, "utf-8")))
        
        buffers.push(this.data.method.serialize())

        return Buffer.concat(buffers)
    }
    
    static parse(raw: Buffer): UserAuthRequest {
        let packetType: number
        [packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthRequest.type)

        let username: Buffer
        [username, raw] = readNextBuffer(raw)

        let service_name: Buffer
        [service_name, raw] = readNextBuffer(raw)

        let method_name: Buffer
        [method_name, raw] = readNextBuffer(raw)
        
        return new UserAuthRequest({
            username: username.toString("utf-8"),
            service_name: service_name.toString("utf-8"),
            method: UserAuthRequest.auth_methods.get(method_name.toString("utf-8"))!.parse(method_name)
        })
    }
}

export abstract class AuthMethod {
    static method_name: string
    
    serialize(): Buffer {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        throw new Error("Not implemented")
    }
}