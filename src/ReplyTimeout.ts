interface ReplyTimeoutRegistration {
    timeout: number
    close(): void
}

const registrations = new WeakMap<object, ReplyTimeoutRegistration>()

export function registerReplyTimeout(owner: object, timeout: number, close: () => void): void {
    if (registrations.has(owner)) throw new Error("SSH reply timeout is already registered")
    registrations.set(owner, { timeout, close })
}

/** Bound an ordered, untagged SSH reply and close the unusable transport after expiry. */
export async function waitForReply<T>(
    owner: object,
    operation: Promise<T>,
    description: string,
): Promise<T> {
    const registration = registrations.get(owner)
    if (!registration) throw new Error("SSH reply timeout is unavailable")

    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
            reject(new Error(`Timed out waiting for SSH ${description}`))
            registration.close()
        }, registration.timeout)
        timer.unref()
    })
    try {
        return await Promise.race([operation, timeout])
    } finally {
        if (timer !== undefined) clearTimeout(timer)
    }
}
