import { makePromise } from "./promise.js"

export const MAX_QUEUED_ACTIONS = 1024

export class ActionQueueCapacityError extends Error {
    override name = "ActionQueueCapacityError"
}

export interface ActionQueueLock {
    release: () => void
}

interface QueuedAction {
    readonly run: () => Promise<void>
    readonly reject: (error: Error) => void
    readonly counted: boolean
}

interface ActionState {
    processing: boolean
    readonly queue: QueuedAction[]
}

export class ActionQueue<keyType extends string = string> {
    readonly maximumQueuedActions: number
    readonly #actionQueues = new Map<keyType, ActionState>()
    #queuedActions = 0
    #closedError?: Error

    constructor(maximumQueuedActions = MAX_QUEUED_ACTIONS) {
        if (!Number.isSafeInteger(maximumQueuedActions) || maximumQueuedActions < 0) {
            throw new RangeError("Maximum queued actions must be a non-negative safe integer")
        }
        this.maximumQueuedActions = maximumQueuedActions
    }

    get queuedActions(): number {
        return this.#queuedActions
    }

    async queueAction<T = void>(key: keyType, nextStep: () => Promise<T>): Promise<T> {
        if (this.#closedError) throw this.#closedError

        let state = this.#actionQueues.get(key)
        if (!state) {
            state = { processing: false, queue: [] }
            this.#actionQueues.set(key, state)
        }
        const counted = state.processing
        if (counted && this.#queuedActions >= this.maximumQueuedActions) {
            throw new ActionQueueCapacityError(
                `SSH action queue exceeds ${this.maximumQueuedActions} waiting operations`,
            )
        }

        const [promise, resolve, reject] = makePromise<T>()
        state.queue.push({
            counted,
            reject,
            run: async () => {
                try {
                    resolve(await nextStep())
                } catch (error) {
                    reject(error instanceof Error ? error : new Error(String(error)))
                }
            },
        })
        if (counted) {
            this.#queuedActions++
            return promise
        }

        state.processing = true
        void this.#drain(key, state)
        return promise
    }

    async obtainLock(key: keyType): Promise<ActionQueueLock> {
        const [lockPromise, lockResolve] = makePromise<void>()
        const [obtained, resolveObtained, rejectObtained] = makePromise<void>()

        void this.queueAction(key, async () => {
            resolveObtained()
            await lockPromise
        }).catch(rejectObtained)

        await obtained
        return { release: lockResolve }
    }

    close(error: Error): void {
        if (this.#closedError) return
        this.#closedError = error
        for (const [key, state] of this.#actionQueues) {
            for (const action of state.queue.splice(0)) action.reject(error)
            if (!state.processing) this.#actionQueues.delete(key)
        }
        this.#queuedActions = 0
    }

    async #drain(key: keyType, state: ActionState): Promise<void> {
        while (state.queue.length > 0) {
            const action = state.queue.shift()!
            if (action.counted) this.#queuedActions--
            await action.run()
        }
        this.#actionQueues.delete(key)
    }
}
