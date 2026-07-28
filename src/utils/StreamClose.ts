import { once } from "node:events"
import type { Duplex } from "node:stream"
import { DEFAULT_OPERATION_TIMEOUT, normalizeTimeout } from "./Timeout.js"

export const DEFAULT_STREAM_CLOSE_TIMEOUT = DEFAULT_OPERATION_TIMEOUT

export function normalizeStreamCloseTimeout(
    value: number | undefined,
    description: string,
): number {
    return normalizeTimeout(value, DEFAULT_STREAM_CLOSE_TIMEOUT, `${description} close timeout`)
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
