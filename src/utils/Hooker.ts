import EventEmitter from "node:events"

export interface HookController {
    stopPropagation(): void
}
export type Hook<values extends any[]> = (
    controller: HookController,
    ...values: values
) => void | Promise<void>
export type HookerEvents = {
    uncaughtException: [event: string, error: Error]
}

export class Hooker<types extends { [key: string]: any[] }> extends EventEmitter<HookerEvents> {
    hooks: Map<keyof types, Hook<types[keyof types]>[]> = new Map()

    hook<event extends keyof types>(event: event, hook: Hook<types[event]>) {
        if (!this.hooks.has(event)) {
            this.hooks.set(event, [])
        }

        this.hooks.get(event)!.push(hook as Hook<types[keyof types]>)
    }

    unhook<event extends keyof types>(event: event, hook: Hook<types[event]>) {
        if (!this.hooks.has(event)) {
            return
        }

        const hooks = this.hooks.get(event)!

        const index = hooks.indexOf(hook as Hook<types[keyof types]>)
        if (index === -1) {
            return
        }

        hooks.splice(index, 1)
    }

    hasHooks(event: keyof types) {
        return this.hooks.has(event)
    }

    async triggerHook<event extends keyof types>(
        event: event,
        ...values: types[event]
    ): Promise<void> {
        if (!this.hooks.has(event)) {
            return
        }

        // copy array so to prevent the loop from breaking
        // if an hook is removed or added during the loop.
        const hooks = Array.from(this.hooks.get(event)!)

        let stopPropagation = false
        const controller: HookController = {
            stopPropagation() {
                stopPropagation = true
            },
        }

        for (const hook of hooks) {
            try {
                await hook(controller, ...values)
            } catch (err) {
                if (this.listenerCount("uncaughtException") > 0) {
                    this.emit("uncaughtException", event as string, err as Error)
                } else {
                    // in node:events, they throw an uncaughtException
                    // on the process or something, this makes the process
                    // crash if you don't catch it. I'd rather log it
                    console.warn(
                        `[node-ssh] Uncaught exception in hook for event ${event.toString()}:`,
                        err,
                    )
                }
            }

            if (stopPropagation) {
                break
            }
        }
    }
}
