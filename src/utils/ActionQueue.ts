import { makePromise } from "./promise.js"

export interface ActionQueueLock {
    release: () => void
}

export class ActionQueue<keyType extends string = string> {
    actionQueues = new Map<
        keyType,
        {
            processing: boolean
            queue: (() => Promise<void>)[]
        }
    >()

    async queueAction<T = void>(key: keyType, nextStep: () => Promise<T>): Promise<T> {
        if (!this.actionQueues.has(key)) {
            this.actionQueues.set(key, {
                processing: false,
                queue: [],
            })
        }

        const acc = this.actionQueues.get(key)!

        const [promise, resolve, reject] = makePromise<T>()

        acc.queue.push(() => nextStep().then(resolve, reject))

        if (acc.processing) return promise
        acc.processing = true

        // start a new "thread" that will loop over the queue
        // and run it
        ;(async () => {
            while (acc.queue.length > 0) {
                const action = acc.queue.shift()!
                await action()
            }
            this.actionQueues.delete(key)
        })()

        return promise
    }

    async obtainLock(key: keyType) {
        const [lockPromise, lockResolve] = makePromise<undefined>()
        const [obtainLockPromise, obtainLockResolve] = makePromise<undefined>()

        this.queueAction(key, () => {
            obtainLockResolve(undefined)

            return lockPromise
        })

        await obtainLockPromise

        return {
            release: () => lockResolve(undefined),
        } as ActionQueueLock
    }
}
