import { SSHPacketType } from "./constants.js"
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

export default abstract class Packet {
    static type: SSHPacketType

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: any) {
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
    [SSHPacketType.SSH_MSG_DISCONNECT, Disconnect],
    [SSHPacketType.SSH_MSG_IGNORE, Ignore],
    [SSHPacketType.SSH_MSG_UNIMPLEMENTED, Unimplemented],
    [SSHPacketType.SSH_MSG_DEBUG, Debug],
    [SSHPacketType.SSH_MSG_SERVICE_REQUEST, ServiceRequest],
    [SSHPacketType.SSH_MSG_SERVICE_ACCEPT, ServiceAccept],

    [SSHPacketType.SSH_MSG_KEXINIT, KexInit],
    [SSHPacketType.SSH_MSG_NEWKEYS, NewKeys],

    [SSHPacketType.SSH_MSG_KEXDH_INIT, KexDHInit],
    [SSHPacketType.SSH_MSG_KEXDH_REPLY, KexDHReply],

    [SSHPacketType.SSH_MSG_USERAUTH_REQUEST, UserAuthRequest],
    [SSHPacketType.SSH_MSG_USERAUTH_FAILURE, UserAuthFailure],
    [SSHPacketType.SSH_MSG_USERAUTH_SUCCESS, UserAuthSuccess],

    [SSHPacketType.SSH_MSG_USERAUTH_PK_OK, UserAuthPKOK],

    [SSHPacketType.SSH_MSG_GLOBAL_REQUEST, GlobalRequest],
    [SSHPacketType.SSH_MSG_REQUEST_FAILURE, RequestFailure],
    [SSHPacketType.SSH_MSG_REQUEST_SUCCESS, RequestSuccess],

    [SSHPacketType.SSH_MSG_CHANNEL_OPEN, ChannelOpen],
    [SSHPacketType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, ChannelOpenConfirmation],
    [SSHPacketType.SSH_MSG_CHANNEL_OPEN_FAILURE, ChannelOpenFailure],
    [SSHPacketType.SSH_MSG_CHANNEL_WINDOW_ADJUST, ChannelWindowAdjust],
    [SSHPacketType.SSH_MSG_CHANNEL_DATA, ChannelData],
    [SSHPacketType.SSH_MSG_CHANNEL_EXTENDED_DATA, ChannelExtendedData],
    [SSHPacketType.SSH_MSG_CHANNEL_EOF, ChannelEOF],
    [SSHPacketType.SSH_MSG_CHANNEL_CLOSE, ChannelClose],
    [SSHPacketType.SSH_MSG_CHANNEL_REQUEST, ChannelRequest],
    [SSHPacketType.SSH_MSG_CHANNEL_SUCCESS, ChannelSuccess],
    [SSHPacketType.SSH_MSG_CHANNEL_FAILURE, ChannelFailure],
])
export interface PacketTypes {
    [SSHPacketType.SSH_MSG_DISCONNECT]: Disconnect
    [SSHPacketType.SSH_MSG_IGNORE]: Ignore
    [SSHPacketType.SSH_MSG_UNIMPLEMENTED]: Unimplemented
    [SSHPacketType.SSH_MSG_DEBUG]: Debug
    [SSHPacketType.SSH_MSG_SERVICE_REQUEST]: ServiceRequest
    [SSHPacketType.SSH_MSG_SERVICE_ACCEPT]: ServiceAccept

    [SSHPacketType.SSH_MSG_KEXINIT]: KexInit
    [SSHPacketType.SSH_MSG_NEWKEYS]: NewKeys

    [SSHPacketType.SSH_MSG_KEXDH_INIT]: KexDHInit
    [SSHPacketType.SSH_MSG_KEXDH_REPLY]: KexDHReply

    [SSHPacketType.SSH_MSG_USERAUTH_REQUEST]: UserAuthRequest
    [SSHPacketType.SSH_MSG_USERAUTH_FAILURE]: UserAuthFailure
    [SSHPacketType.SSH_MSG_USERAUTH_SUCCESS]: UserAuthSuccess

    [SSHPacketType.SSH_MSG_USERAUTH_PK_OK]: UserAuthPKOK

    [SSHPacketType.SSH_MSG_GLOBAL_REQUEST]: GlobalRequest
    [SSHPacketType.SSH_MSG_REQUEST_FAILURE]: RequestFailure
    [SSHPacketType.SSH_MSG_REQUEST_SUCCESS]: RequestSuccess

    [SSHPacketType.SSH_MSG_CHANNEL_OPEN]: ChannelOpen
    [SSHPacketType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION]: ChannelOpenConfirmation
    [SSHPacketType.SSH_MSG_CHANNEL_OPEN_FAILURE]: ChannelOpenFailure
    [SSHPacketType.SSH_MSG_CHANNEL_WINDOW_ADJUST]: ChannelWindowAdjust
    [SSHPacketType.SSH_MSG_CHANNEL_DATA]: ChannelData
    [SSHPacketType.SSH_MSG_CHANNEL_EXTENDED_DATA]: ChannelExtendedData
    [SSHPacketType.SSH_MSG_CHANNEL_EOF]: ChannelEOF
    [SSHPacketType.SSH_MSG_CHANNEL_CLOSE]: ChannelClose
    [SSHPacketType.SSH_MSG_CHANNEL_REQUEST]: ChannelRequest
    [SSHPacketType.SSH_MSG_CHANNEL_SUCCESS]: ChannelSuccess
    [SSHPacketType.SSH_MSG_CHANNEL_FAILURE]: ChannelFailure
}
