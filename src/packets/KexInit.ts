import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextNameList, serializeNameList } from "../utils/NameList.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import { readNextBinaryBoolean, readNextUint32, readNextUint8 } from "../utils/Buffer.js"

export interface KexInitData {
    cookie: Buffer
    kex_algorithms: string[]
    server_host_key_algorithms: string[]
    encryption_algorithms_client_to_server: string[]
    encryption_algorithms_server_to_client: string[]
    mac_algorithms_client_to_server: string[]
    mac_algorithms_server_to_client: string[]
    compression_algorithms_client_to_server: string[]
    compression_algorithms_server_to_client: string[]
    languages_client_to_server: string[]
    languages_server_to_client: string[]
    first_kex_packet_follows: boolean
}
export default class KexInit implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXINIT

    data: KexInitData
    constructor(data: KexInitData) {
        this.data = data
    }

    serialize(): Buffer {
        const buffers = []

        buffers.push(Buffer.from([KexInit.type]))

        buffers.push(this.data.cookie)

        buffers.push(serializeNameList(this.data.kex_algorithms))
        buffers.push(serializeNameList(this.data.server_host_key_algorithms))
        buffers.push(serializeNameList(this.data.encryption_algorithms_client_to_server))
        buffers.push(serializeNameList(this.data.encryption_algorithms_server_to_client))
        buffers.push(serializeNameList(this.data.mac_algorithms_client_to_server))
        buffers.push(serializeNameList(this.data.mac_algorithms_server_to_client))
        buffers.push(serializeNameList(this.data.compression_algorithms_client_to_server))
        buffers.push(serializeNameList(this.data.compression_algorithms_server_to_client))
        buffers.push(serializeNameList(this.data.languages_client_to_server))
        buffers.push(serializeNameList(this.data.languages_server_to_client))

        buffers.push(serializeBinaryBoolean(this.data.first_kex_packet_follows))
        buffers.push(Buffer.alloc(4))

        return Buffer.concat(buffers)
    }

    static parse(raw: Buffer): KexInit {
        let packetType: number
        ;[packetType, raw] = readNextUint8(raw)
        assert(packetType === KexInit.type)

        const cookie = raw.subarray(0, 16)
        assert(cookie.length === 16)
        raw = raw.subarray(16)

        let kex_algorithms: string[]
        ;[kex_algorithms, raw] = readNextNameList(raw)

        let server_host_key_algorithms: string[]
        ;[server_host_key_algorithms, raw] = readNextNameList(raw)

        let encryption_algorithms_client_to_server: string[]
        ;[encryption_algorithms_client_to_server, raw] = readNextNameList(raw)

        let encryption_algorithms_server_to_client: string[]
        ;[encryption_algorithms_server_to_client, raw] = readNextNameList(raw)

        let mac_algorithms_client_to_server: string[]
        ;[mac_algorithms_client_to_server, raw] = readNextNameList(raw)

        let mac_algorithms_server_to_client: string[]
        ;[mac_algorithms_server_to_client, raw] = readNextNameList(raw)

        let compression_algorithms_client_to_server: string[]
        ;[compression_algorithms_client_to_server, raw] = readNextNameList(raw)

        let compression_algorithms_server_to_client: string[]
        ;[compression_algorithms_server_to_client, raw] = readNextNameList(raw)

        let languages_client_to_server: string[]
        ;[languages_client_to_server, raw] = readNextNameList(raw)

        let languages_server_to_client: string[]
        ;[languages_server_to_client, raw] = readNextNameList(raw)

        let first_kex_packet_follows: boolean
        ;[first_kex_packet_follows, raw] = readNextBinaryBoolean(raw)

        // according to the RFC, it is reserved and it should
        // be 0 at all time
        let reserved_future_extensions: number
        ;[reserved_future_extensions, raw] = readNextUint32(raw)
        assert(reserved_future_extensions == 0)

        return new KexInit({
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
        })
    }
}
