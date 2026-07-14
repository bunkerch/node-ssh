import { EventEmitter } from "node:events"
import Channel, {
    DEFAULT_SERVER_CHANNEL_PACKET_SIZE,
    DEFAULT_SERVER_CHANNEL_WINDOW_SIZE,
} from "../Channel.js"
import Client from "../Client.js"
import type ServerClient from "../ServerClient.js"
import {
    decodeTunnelOpen,
    emitTunnelPayload,
    encodeTunnelPacket,
    TunnelAddressFamily,
    type TunnelEvents,
    TunnelMode,
} from "./Tunnel.js"

export default class TunnelChannel extends Channel {
    static channel_type = "tun@openssh.com"

    readonly events = new EventEmitter<TunnelEvents>()
    readonly mode: TunnelMode
    readonly unit: number

    constructor(client: Client | ServerClient, channelType: string, clientArgs = Buffer.alloc(0)) {
        if (client instanceof Client) {
            throw new Error("A client must not accept a server-initiated tunnel channel")
        }
        super(client, channelType, clientArgs)
        this.local_initial_window_size = DEFAULT_SERVER_CHANNEL_WINDOW_SIZE
        this.local_maximum_packet_size = DEFAULT_SERVER_CHANNEL_PACKET_SIZE
        const { mode, unit } = decodeTunnelOpen(clientArgs)
        this.mode = mode
        this.unit = unit
    }

    sendIPv4(packet: Buffer): Promise<void> {
        return this.sendPayload(encodeTunnelPacket(this.mode, packet, TunnelAddressFamily.IPv4))
    }

    sendIPv6(packet: Buffer): Promise<void> {
        return this.sendPayload(encodeTunnelPacket(this.mode, packet, TunnelAddressFamily.IPv6))
    }

    sendFrame(frame: Buffer): Promise<void> {
        return this.sendPayload(encodeTunnelPacket(this.mode, frame))
    }

    protected handleData(data: Buffer): boolean {
        emitTunnelPayload(this.events, this.mode, data)
        return true
    }

    private sendPayload(payload: Buffer): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.sendAtomicData(payload, (error) => (error ? reject(error) : resolve()))
        })
    }
}
