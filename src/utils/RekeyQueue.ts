import type Packet from "../packet.js"

export const MAX_REKEY_QUEUED_PACKETS = 1024
export const MAX_REKEY_QUEUED_BYTES = 4 * 1024 * 1024

interface QueuedPacket {
    readonly packet: Packet
    readonly payload: Buffer
}

const pausedTransports = new WeakSet<object>()
const resumeCallbacks = new WeakMap<object, Set<() => void>>()

export class OutboundRekeyQueue {
    private readonly packets: QueuedPacket[] = []
    private bytes = 0

    enqueue(packet: Packet): void {
        const payload = packet.serialize()
        if (
            this.packets.length >= MAX_REKEY_QUEUED_PACKETS ||
            payload.length > MAX_REKEY_QUEUED_BYTES - this.bytes
        ) {
            throw new Error(
                `SSH outbound rekey queue exceeds ${MAX_REKEY_QUEUED_PACKETS} packets or ${MAX_REKEY_QUEUED_BYTES} bytes`,
            )
        }
        this.packets.push({ packet, payload })
        this.bytes += payload.length
    }

    drain(write: (packet: Packet, payload: Buffer) => void): void {
        while (this.packets.length > 0) {
            const queued = this.packets.shift()!
            this.bytes -= queued.payload.length
            write(queued.packet, queued.payload)
        }
    }

    clear(): void {
        this.packets.length = 0
        this.bytes = 0
    }
}

export function pauseApplicationTraffic(transport: object): void {
    pausedTransports.add(transport)
}

export function isApplicationTrafficPaused(transport: object): boolean {
    return pausedTransports.has(transport)
}

export function deferApplicationTraffic(transport: object, resume: () => void): boolean {
    if (!pausedTransports.has(transport)) return false
    let callbacks = resumeCallbacks.get(transport)
    if (!callbacks) {
        callbacks = new Set()
        resumeCallbacks.set(transport, callbacks)
    }
    callbacks.add(resume)
    return true
}

export function resumeApplicationTraffic(transport: object, flushQueuedPackets: () => void): void {
    pausedTransports.delete(transport)
    flushQueuedPackets()
    const callbacks = resumeCallbacks.get(transport)
    resumeCallbacks.delete(transport)
    if (!callbacks) return
    for (const resume of callbacks) resume()
}

export function discardApplicationTrafficPause(transport: object): void {
    pausedTransports.delete(transport)
    resumeCallbacks.delete(transport)
}
