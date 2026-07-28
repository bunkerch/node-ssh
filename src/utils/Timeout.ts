export const DEFAULT_OPERATION_TIMEOUT = 30_000
export const MAXIMUM_TIMER_DELAY = 2_147_483_647

export function normalizeTimeout(
    value: number | undefined,
    defaultValue: number,
    description: string,
): number {
    const timeout = value === undefined ? defaultValue : value
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAXIMUM_TIMER_DELAY) {
        throw new RangeError(
            `${description} must be an integer between 1 and ${MAXIMUM_TIMER_DELAY}`,
        )
    }
    return timeout
}

export function normalizeOptionalTimeout(value: number, description: string): number {
    if (!Number.isInteger(value) || value < 0 || value > MAXIMUM_TIMER_DELAY) {
        throw new RangeError(
            `${description} must be an integer between 0 and ${MAXIMUM_TIMER_DELAY}`,
        )
    }
    return value
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
