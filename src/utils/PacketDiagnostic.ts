import type Packet from "../packet.js"
import ChannelData from "../packets/ChannelData.js"
import ChannelExtendedData from "../packets/ChannelExtendedData.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import GlobalRequest from "../packets/GlobalRequest.js"
import Ignore from "../packets/Ignore.js"
import RequestSuccess from "../packets/RequestSuccess.js"
import UserAuthInfoResponse from "../packets/UserAuthInfoResponse.js"
import UserAuthRequest from "../packets/UserAuthRequest.js"
import {
    UserAuthGSSAPIErrorToken,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIToken,
} from "../packets/UserAuthGSSAPI.js"
import { KexGSSAPIComplete, KexGSSAPIContinue, KexGSSAPIInit } from "../packets/KexGSSAPI.js"

const REDACTED = "<redacted>"

/** Return diagnostic metadata without exposing authentication, channel, or opaque request bytes. */
export default function packetDiagnostic(packet: Packet): unknown {
    if (packet instanceof UserAuthRequest) {
        return Object.freeze({
            type: "SSH_MSG_USERAUTH_REQUEST",
            username: packet.data.username,
            serviceName: packet.data.service_name,
            method: packet.data.method.method_name,
        })
    }
    if (packet instanceof UserAuthInfoResponse) {
        return Object.freeze({
            type: "SSH_MSG_USERAUTH_INFO_RESPONSE",
            responseCount: packet.data.responses.length,
            responses: REDACTED,
        })
    }
    if (
        packet instanceof UserAuthGSSAPIToken ||
        packet instanceof UserAuthGSSAPIErrorToken ||
        packet instanceof UserAuthGSSAPIMIC
    ) {
        return Object.freeze({ type: packet.constructor.name, token: REDACTED })
    }
    if (packet instanceof KexGSSAPIInit) {
        return Object.freeze({
            type: packet.constructor.name,
            token: REDACTED,
            publicKeyBytes: packet.publicKey.length,
        })
    }
    if (packet instanceof KexGSSAPIContinue) {
        return Object.freeze({ type: packet.constructor.name, token: REDACTED })
    }
    if (packet instanceof KexGSSAPIComplete) {
        return Object.freeze({
            type: packet.constructor.name,
            publicKeyBytes: packet.publicKey.length,
            mic: REDACTED,
            token: packet.token === undefined ? undefined : REDACTED,
        })
    }
    if (packet instanceof ChannelOpen) {
        return Object.freeze({
            type: "SSH_MSG_CHANNEL_OPEN",
            channelType: packet.data.channel_type,
            senderChannelId: packet.data.sender_channel_id,
            initialWindowSize: packet.data.initial_window_size,
            maximumPacketSize: packet.data.maximum_packet_size,
            argumentBytes: packet.data.args.length,
            args: REDACTED,
        })
    }
    if (packet instanceof ChannelRequest) {
        return Object.freeze({
            type: "SSH_MSG_CHANNEL_REQUEST",
            recipientChannelId: packet.data.recipient_channel_id,
            requestType: packet.data.request_type,
            wantReply: packet.data.want_reply,
            argumentBytes: packet.data.args.length,
            args: REDACTED,
        })
    }
    if (packet instanceof ChannelData) {
        return Object.freeze({
            type: "SSH_MSG_CHANNEL_DATA",
            recipientChannelId: packet.data.recipient_channel_id,
            dataBytes: packet.data.data.length,
            data: REDACTED,
        })
    }
    if (packet instanceof ChannelExtendedData) {
        return Object.freeze({
            type: "SSH_MSG_CHANNEL_EXTENDED_DATA",
            recipientChannelId: packet.data.recipient_channel_id,
            dataType: packet.data.data_type_code,
            dataBytes: packet.data.data.length,
            data: REDACTED,
        })
    }
    if (packet instanceof GlobalRequest) {
        return Object.freeze({
            type: "SSH_MSG_GLOBAL_REQUEST",
            requestName: packet.data.request_name,
            wantReply: packet.data.want_reply,
            argumentBytes: packet.data.args.length,
            args: REDACTED,
        })
    }
    if (packet instanceof RequestSuccess) {
        return Object.freeze({
            type: "SSH_MSG_REQUEST_SUCCESS",
            argumentBytes: packet.data.args.length,
            args: REDACTED,
        })
    }
    if (packet instanceof Ignore) {
        return Object.freeze({
            type: "SSH_MSG_IGNORE",
            dataBytes: packet.data.data.length,
            data: REDACTED,
        })
    }
    return packet
}
