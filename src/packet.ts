import { SSHPacketType } from "./constants.js";
import KexDHInit from "./packets/KexDHInit.js";
import KexDHReply from "./packets/KexDHReply.js";
import KexInit from "./packets/KexInit.js";
import NewKeys from "./packets/NewKeys.js";

export default abstract class Packet {
    static type: SSHPacketType

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: any){
        throw new Error("Abstract class")
    }

    abstract serialize(): Buffer

    static parse(raw: Buffer): Packet {
        const type = raw.readUInt8()
        const packet = packets.get(type)
        if (!packet) {
            throw new Error(`Unknown packet type: ${type}`)
        }
        return packet.parse(raw)
    }
}

export const packets = new Map<SSHPacketType, typeof Packet>([
    [SSHPacketType.SSH_MSG_KEXINIT, KexInit],
    [SSHPacketType.SSH_MSG_NEWKEYS, NewKeys],

    [SSHPacketType.SSH_MSG_KEXDH_INIT, KexDHInit],
    [SSHPacketType.SSH_MSG_KEXDH_REPLY, KexDHReply],
])