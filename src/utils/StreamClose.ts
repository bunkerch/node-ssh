import { once } from "node:events"
import type { Duplex } from "node:stream"

export const DEFAULT_STREAM_CLOSE_TIMEOUT = 30_000

export function normalizeStreamCloseTimeout(
    value: number | undefined,
    description: string,
): number {
    const timeout = value === undefined ? DEFAULT_STREAM_CLOSE_TIMEOUT : value
    if (!Number.isFinite(timeout) || timeout <= 0) {
        throw new RangeError(`${description} close timeout must be a positive number`)
    }
    return timeout
}

export function closeStream(
    stream: Duplex & { close(): unknown },
    timeout: number,
    description: string,
): Promise<void> {
    if (stream.destroyed) return Promise.resolve()

    let timer: ReturnType<typeof setTimeout> | undefined
    const closed = once(stream, "close").then(() => undefined)
    const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
            const error = new Error(`Timed out waiting for ${description} to close`)
            if (!stream.destroyed) stream.destroy(error)
            reject(error)
        }, timeout)
        timer.unref()
    })

    try {
        stream.close()
    } catch (error) {
        stream.destroy(error instanceof Error ? error : new Error(String(error)))
    }

    return Promise.race([closed, deadline]).finally(() => {
        if (timer !== undefined) clearTimeout(timer)
    })
}
