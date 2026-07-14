import assert from "assert"
import { PacketNameToType } from "../constants.js"
import Packet from "../packet.js"
import { readNextNameList, serializeNameList } from "../utils/NameList.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    readNextUint8,
    serializeBuffer,
} from "../utils/Buffer.js"
import { decodeSSHLanguageTag, encodeSSHLanguageTag } from "../utils/SSHText.js"

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

function validateKexInitData(data: KexInitData): void {
    assert(data.cookie.length === 16, "SSH KEXINIT cookie must be exactly 16 bytes")
    for (const [name, algorithms] of [
        ["key exchange", data.kex_algorithms],
        ["server host key", data.server_host_key_algorithms],
        ["client-to-server encryption", data.encryption_algorithms_client_to_server],
        ["server-to-client encryption", data.encryption_algorithms_server_to_client],
        ["client-to-server MAC", data.mac_algorithms_client_to_server],
        ["server-to-client MAC", data.mac_algorithms_server_to_client],
        ["client-to-server compression", data.compression_algorithms_client_to_server],
        ["server-to-client compression", data.compression_algorithms_server_to_client],
    ] as const) {
        assert(algorithms.length > 0, `SSH KEXINIT ${name} list must not be empty`)
    }
    for (const tag of [...data.languages_client_to_server, ...data.languages_server_to_client]) {
        assert(tag.length > 0, "SSH KEXINIT language list must not contain an empty tag")
        encodeSSHLanguageTag(tag, "SSH KEXINIT language tag")
    }
}

function serializeLanguageList(tags: readonly string[]): Buffer {
    return serializeBuffer(
        Buffer.concat(
            tags.flatMap((tag, index) => [
                ...(index === 0 ? [] : [Buffer.from(",", "ascii")]),
                encodeSSHLanguageTag(tag, "SSH KEXINIT language tag"),
            ]),
        ),
    )
}

function readNextLanguageList(raw: Buffer): [string[], Buffer] {
    let encoded: Buffer
    ;[encoded, raw] = readNextBuffer(raw)
    if (encoded.length === 0) return [[], raw]
    if (encoded.some((byte) => byte > 0x7f)) {
        throw new Error("SSH KEXINIT language tag is not valid RFC 3066")
    }
    return [
        encoded
            .toString("ascii")
            .split(",")
            .map((tag) =>
                decodeSSHLanguageTag(Buffer.from(tag, "ascii"), "SSH KEXINIT language tag"),
            ),
        raw,
    ]
}

export default class KexInit implements Packet {
    static type = PacketNameToType.SSH_MSG_KEXINIT

    data: KexInitData
    constructor(data: KexInitData) {
        validateKexInitData(data)
        this.data = {
            cookie: Buffer.from(data.cookie),
            kex_algorithms: [...data.kex_algorithms],
            server_host_key_algorithms: [...data.server_host_key_algorithms],
            encryption_algorithms_client_to_server: [
                ...data.encryption_algorithms_client_to_server,
            ],
            encryption_algorithms_server_to_client: [
                ...data.encryption_algorithms_server_to_client,
            ],
            mac_algorithms_client_to_server: [...data.mac_algorithms_client_to_server],
            mac_algorithms_server_to_client: [...data.mac_algorithms_server_to_client],
            compression_algorithms_client_to_server: [
                ...data.compression_algorithms_client_to_server,
            ],
            compression_algorithms_server_to_client: [
                ...data.compression_algorithms_server_to_client,
            ],
            languages_client_to_server: [...data.languages_client_to_server],
            languages_server_to_client: [...data.languages_server_to_client],
            first_kex_packet_follows: data.first_kex_packet_follows,
        }
    }

    serialize(): Buffer {
        validateKexInitData(this.data)
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
        buffers.push(serializeLanguageList(this.data.languages_client_to_server))
        buffers.push(serializeLanguageList(this.data.languages_server_to_client))

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
        ;[languages_client_to_server, raw] = readNextLanguageList(raw)

        let languages_server_to_client: string[]
        ;[languages_server_to_client, raw] = readNextLanguageList(raw)

        let first_kex_packet_follows: boolean
        ;[first_kex_packet_follows, raw] = readNextBinaryBoolean(raw)

        // according to the RFC, it is reserved and it should
        // be 0 at all time
        let reserved_future_extensions: number
        ;[reserved_future_extensions, raw] = readNextUint32(raw)
        assert(reserved_future_extensions == 0)
        assert(raw.length === 0, "SSH KEXINIT has trailing data")

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
