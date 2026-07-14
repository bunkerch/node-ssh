import type { EventEmitter } from "node:events"
import type Packet from "../packet.js"

interface PacketEventSource extends EventEmitter {
    on(event: "packet", listener: (packet: Packet) => void): this
    on(event: "error", listener: (error: Error) => void): this
    on(event: "close", listener: () => void): this
    off(event: "packet", listener: (packet: Packet) => void): this
    off(event: "error", listener: (error: Error) => void): this
    off(event: "close", listener: () => void): this
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
        source.on("packet", this.#onPacket)
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
        this.#source.off("packet", this.#onPacket)
        this.#source.off("error", this.#onError)
        this.#source.off("close", this.#onClose)
    }
}
