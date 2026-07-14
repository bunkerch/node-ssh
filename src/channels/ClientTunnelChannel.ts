import { EventEmitter } from "node:events"
import Client from "../Client.js"
import ChannelOpen from "../packets/ChannelOpen.js"
import ClientChannel from "./ClientChannel.js"
import {
    AUTOMATIC_TUNNEL_UNIT,
    emitTunnelPayload,
    encodeTunnelOpen,
    encodeTunnelPacket,
    TunnelAddressFamily,
    type TunnelEvents,
    TunnelMode,
} from "./Tunnel.js"

type WriteCallback = (error?: Error | null) => void

export default class ClientTunnelChannel extends ClientChannel {
    static channelType = "tun@openssh.com"

    readonly events = new EventEmitter<TunnelEvents>()
    readonly mode: TunnelMode
    readonly unit: number

    constructor(client: Client, mode: TunnelMode, unit: number = AUTOMATIC_TUNNEL_UNIT) {
        super(client, ClientTunnelChannel.channelType)
        this.mode = mode
        this.unit = unit
        encodeTunnelOpen(mode, unit)
    }

    override getOpenPacket(): ChannelOpen {
        return super.getOpenPacket(encodeTunnelOpen(this.mode, this.unit))
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

    override receiveData(data: Buffer): void {
        this.consumeLocalWindow(data)
        emitTunnelPayload(this.events, this.mode, data)
        this.adjustWindowIfNeeded()
    }

    override _write(
        data: Buffer | string,
        encoding: BufferEncoding,
        callback: WriteCallback,
    ): void {
        this.writeChannelData(
            Buffer.isBuffer(data) ? data : Buffer.from(data, encoding),
            callback,
            true,
        )
    }

    private sendPayload(payload: Buffer): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.write(payload, (error) => (error ? reject(error) : resolve()))
        })
    }
}
