import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextBuffer, readNextUint8, serializeBuffer, serializeUint8 } from "../utils/Buffer.js"
import PublicKey from "../utils/PublicKey.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

export interface UserAuthPKOKData {
    publicKey: PublicKey
    algorithm?: string
}
export default class UserAuthPKOK implements Packet {
    static type = PacketNameToType.SSH_MSG_USERAUTH_PK_OK

    data: UserAuthPKOKData
    constructor(data: UserAuthPKOKData) {
        const algorithm = data.algorithm ?? data.publicKey.data.alg
        encodeSSHName(algorithm, "SSH public-key acceptance algorithm")
        assert(data.publicKey.supportsSignatureAlgorithm(algorithm))
        this.data = { publicKey: data.publicKey, algorithm }
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(serializeUint8(UserAuthPKOK.type))

        buffers.push(
            serializeBuffer(
                encodeSSHName(this.data.algorithm!, "SSH public-key acceptance algorithm"),
            ),
        )
        buffers.push(serializeBuffer(this.data.publicKey.serialize()))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): UserAuthPKOK {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === UserAuthPKOK.type)

        let alg: Buffer
        ;[alg, raw] = readNextBuffer(raw)

        let data: Buffer
        ;[data, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        const publicKey = PublicKey.parse(data)
        const algorithm = decodeSSHName(alg, "SSH public-key acceptance algorithm")
        assert(publicKey.supportsSignatureAlgorithm(algorithm))

        return new UserAuthPKOK({
            publicKey: publicKey,
            algorithm,
        })
    }
}
