import type Client from "../Client.js"
import { SSHAuthenticationMethods } from "../constants.js"
import Packet from "../packet.js"
import Disconnect from "../packets/Disconnect.js"
import Unimplemented from "../packets/Unimplemented.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthPKOK from "../packets/UserAuthPKOK.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import { waitForMatchingPacket } from "../utils/PacketEventQueue.js"

export default abstract class AuthMethod {
    static method_name: string
    abstract method_name: string

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Not implemented")
    }

    abstract serialize(): Buffer

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static async handleAuthentication(client: Client): Promise<boolean> {
        throw new Error("Not implemented")
    }

    static async waitForAnswer(client: Client, seqno?: number): Promise<Packet> {
        return waitForMatchingPacket(
            client,
            (packet) =>
                (packet instanceof Unimplemented &&
                    (seqno === undefined || packet.data.sequence_number === seqno)) ||
                packet instanceof UserAuthFailure ||
                packet instanceof UserAuthSuccess ||
                (packet.constructor as typeof Packet).type === UserAuthPKOK.type ||
                packet instanceof Disconnect,
            10_000,
            () => new Error("SSH connection closed during authentication"),
            () => new Error("Timed out waiting for message"),
        )
    }
}

export interface AuthMethodClass {
    method_name: SSHAuthenticationMethods
    parse(raw: Buffer): AuthMethod
    handleAuthentication(client: Client): Promise<boolean>
}
