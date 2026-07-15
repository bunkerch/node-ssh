import type { EventEmitter } from "node:events"
import type Packet from "../packet.js"

type PacketListener = (packet: Packet) => void

const packetListeners = new WeakMap<object, Set<PacketListener>>()

interface PacketEventSource extends EventEmitter {
    on(event: "error", listener: (error: Error) => void): this
    on(event: "close", listener: () => void): this
    off(event: "error", listener: (error: Error) => void): this
    off(event: "close", listener: () => void): this
}

export function emitPacketEvent(source: object, packet: Packet): void {
    const listeners = packetListeners.get(source)
    if (!listeners) return
    for (const listener of [...listeners]) listener(packet)
}

export function onPacketEvent(source: object, listener: PacketListener): void {
    let listeners = packetListeners.get(source)
    if (!listeners) {
        listeners = new Set()
        packetListeners.set(source, listeners)
    }
    listeners.add(listener)
}

export function offPacketEvent(source: object, listener: PacketListener): void {
    const listeners = packetListeners.get(source)
    if (!listeners) return
    listeners.delete(listener)
    if (listeners.size === 0) packetListeners.delete(source)
}

export function waitForPacketEvent(
    source: PacketEventSource,
    closedError: () => Error,
): Promise<Packet> {
    const packets = new PacketEventQueue(source, closedError)
    return packets.next().finally(() => packets.close())
}

export async function waitForMatchingPacket(
    source: PacketEventSource,
    predicate: (packet: Packet) => boolean,
    timeout: number,
    closedError: () => Error,
    timeoutError: () => Error,
): Promise<Packet> {
    const packets = new PacketEventQueue(source, closedError)
    let timer: NodeJS.Timeout | undefined
    const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(timeoutError()), timeout)
        timer.unref()
    })
    const matchingPacket = async (): Promise<Packet> => {
        while (true) {
            const packet = await packets.next()
            if (predicate(packet)) return packet
        }
    }
    try {
        return await Promise.race([matchingPacket(), deadline])
    } finally {
        if (timer !== undefined) clearTimeout(timer)
        packets.close()
    }
}

/** A scoped Promise-based queue that preserves adjacent packet events. */
export default class PacketEventQueue {
    readonly #source: PacketEventSource
    readonly #closedError: () => Error
    readonly #packets: Packet[] = []
    readonly #waiters: {
        resolve(packet: Packet): void
        reject(error: Error): void
    }[] = []
    #failure?: Error
    #closed = false

    constructor(source: PacketEventSource, closedError: () => Error) {
        this.#source = source
        this.#closedError = closedError
        onPacketEvent(source, this.#onPacket)
        source.on("error", this.#onError)
        source.on("close", this.#onClose)
    }

    next(): Promise<Packet> {
        const packet = this.#packets.shift()
        if (packet) return Promise.resolve(packet)
        if (this.#failure) return Promise.reject(this.#failure)
        if (this.#closed) return Promise.reject(this.#closedError())
        return new Promise((resolve, reject) => this.#waiters.push({ resolve, reject }))
    }

    close(): void {
        if (this.#closed) return
        this.#closed = true
        this.#removeListeners()
        const error = this.#closedError()
        for (const waiter of this.#waiters.splice(0)) waiter.reject(error)
        this.#packets.length = 0
    }

    readonly #onPacket = (packet: Packet): void => {
        const waiter = this.#waiters.shift()
        if (waiter) waiter.resolve(packet)
        else this.#packets.push(packet)
    }

    readonly #onError = (error: Error): void => {
        this.#fail(error)
    }

    readonly #onClose = (): void => {
        this.#fail(this.#closedError())
    }

    #fail(error: Error): void {
        if (this.#failure || this.#closed) return
        this.#failure = error
        this.#removeListeners()
        for (const waiter of this.#waiters.splice(0)) waiter.reject(error)
        this.#packets.length = 0
    }

    #removeListeners(): void {
        offPacketEvent(this.#source, this.#onPacket)
        this.#source.off("error", this.#onError)
        this.#source.off("close", this.#onClose)
    }
}
