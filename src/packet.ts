import { PacketName, PacketType, PacketTypeToName } from "./constants.js"
import ChannelClose from "./packets/ChannelClose.js"
import ChannelData from "./packets/ChannelData.js"
import ChannelEOF from "./packets/ChannelEOF.js"
import ChannelExtendedData from "./packets/ChannelExtendedData.js"
import ChannelFailure from "./packets/ChannelFailure.js"
import ChannelOpen from "./packets/ChannelOpen.js"
import ChannelOpenConfirmation from "./packets/ChannelOpenConfirmation.js"
import ChannelOpenFailure from "./packets/ChannelOpenFailure.js"
import ChannelRequest from "./packets/ChannelRequest.js"
import ChannelSuccess from "./packets/ChannelSuccess.js"
import ChannelWindowAdjust from "./packets/ChannelWindowAdjust.js"
import Debug from "./packets/Debug.js"
import Disconnect from "./packets/Disconnect.js"
import GlobalRequest from "./packets/GlobalRequest.js"
import Ignore from "./packets/Ignore.js"
import KexDHInit from "./packets/KexDHInit.js"
import KexDHReply from "./packets/KexDHReply.js"
import KexInit from "./packets/KexInit.js"
import NewKeys from "./packets/NewKeys.js"
import RequestFailure from "./packets/RequestFailure.js"
import RequestSuccess from "./packets/RequestSuccess.js"
import ServiceAccept from "./packets/ServiceAccept.js"
import ServiceRequest from "./packets/ServiceRequest.js"
import Unimplemented from "./packets/Unimplemented.js"
import UserAuthFailure from "./packets/UserAuthFailure.js"
import UserAuthPKOK from "./packets/UserAuthPKOK.js"
import UserAuthRequest from "./packets/UserAuthRequest.js"
import UserAuthSuccess from "./packets/UserAuthSuccess.js"
import { ValueOf } from "./utils/types.js"

export default abstract class Packet {
    static type: PacketType

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Abstract class")
    }

    abstract serialize(): Buffer

    static parse(raw: Buffer): Packet {
        const type = raw.readUInt8() as PacketType
        if (!(type in PacketTypeToName)) {
            throw new Error(`Unknown packet type: ${type}`)
        }

        const packetName = PacketTypeToName[type]
        if (!(packetName in packets)) {
            throw new Error(`Not Implemented: ${packetName}`)
        }

        const packet = packets[packetName as keyof typeof packets]

        return packet.parse(raw)
    }
}

export const packets = {
    SSH_MSG_DISCONNECT: Disconnect,
    SSH_MSG_IGNORE: Ignore,
    SSH_MSG_UNIMPLEMENTED: Unimplemented,
    SSH_MSG_DEBUG: Debug,
    SSH_MSG_SERVICE_REQUEST: ServiceRequest,
    SSH_MSG_SERVICE_ACCEPT: ServiceAccept,

    SSH_MSG_KEXINIT: KexInit,
    SSH_MSG_NEWKEYS: NewKeys,

    SSH_MSG_KEXDH_INIT: KexDHInit,
    SSH_MSG_KEXDH_REPLY: KexDHReply,

    SSH_MSG_USERAUTH_REQUEST: UserAuthRequest,
    SSH_MSG_USERAUTH_FAILURE: UserAuthFailure,
    SSH_MSG_USERAUTH_SUCCESS: UserAuthSuccess,

    SSH_MSG_USERAUTH_PK_OK: UserAuthPKOK,

    SSH_MSG_GLOBAL_REQUEST: GlobalRequest,
    SSH_MSG_REQUEST_FAILURE: RequestFailure,
    SSH_MSG_REQUEST_SUCCESS: RequestSuccess,

    SSH_MSG_CHANNEL_OPEN: ChannelOpen,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION: ChannelOpenConfirmation,
    SSH_MSG_CHANNEL_OPEN_FAILURE: ChannelOpenFailure,
    SSH_MSG_CHANNEL_WINDOW_ADJUST: ChannelWindowAdjust,
    SSH_MSG_CHANNEL_DATA: ChannelData,
    SSH_MSG_CHANNEL_EXTENDED_DATA: ChannelExtendedData,
    SSH_MSG_CHANNEL_EOF: ChannelEOF,
    SSH_MSG_CHANNEL_CLOSE: ChannelClose,
    SSH_MSG_CHANNEL_REQUEST: ChannelRequest,
    SSH_MSG_CHANNEL_SUCCESS: ChannelSuccess,
    SSH_MSG_CHANNEL_FAILURE: ChannelFailure,
} as const
;({}) as unknown as keyof typeof packets satisfies PacketName
;({}) as unknown as ValueOf<typeof packets> satisfies typeof Packet

export type Packets = {
    [k in keyof typeof packets]: InstanceType<(typeof packets)[k]>
}
