export const DEFAULT_OPERATION_TIMEOUT = 30_000

export function normalizeTimeout(
    value: number | undefined,
    defaultValue: number,
    description: string,
): number {
    const timeout = value === undefined ? defaultValue : value
    if (!Number.isFinite(timeout) || timeout <= 0) {
        throw new RangeError(`${description} must be a positive number`)
    }
    return timeout
}

export function waitWithTimeout<T>(
    operation: PromiseLike<T>,
    timeout: number,
    description: string,
    onTimeout: (error: Error) => void,
): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
            const error = new Error(`Timed out waiting for ${description}`)
            try {
                onTimeout(error)
                reject(error)
            } catch (timeoutError) {
                reject(
                    timeoutError instanceof Error
                        ? timeoutError
                        : new Error(String(timeoutError), { cause: error }),
                )
            }
        }, timeout)
        timer.unref()
    })

    return Promise.race([operation, deadline]).finally(() => {
        if (timer !== undefined) clearTimeout(timer)
    })
}
