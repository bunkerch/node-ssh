import Channel from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import { readNextBuffer, readNextUint32 } from "../utils/Buffer.js"
import ChannelSuccess from "../packets/ChannelSuccess.js"
import assert from "assert"
import { Hooker } from "../utils/Hooker.js"
import EventEmitter from "events"

export type SessionChannelHookerExecRequestContext = {
    command: string
}
export type SessionChannelHookerExecRequestController = {
    success: boolean
}
export type SessionChannelHookerEnvRequestContext = {
    key: string
    value: string
}
export type SessionChannelHookerEnvRequestController = {
    success: boolean
}
export type SessionChannelHookerShellRequestController = {
    success: boolean
}
export type SessionChannelHooker = {
    execRequest: [
        execRequestContext: Readonly<SessionChannelHookerExecRequestContext>,
        execRequestController: SessionChannelHookerExecRequestController,
    ]
    envRequest: [
        envRequestContext: Readonly<SessionChannelHookerEnvRequestContext>,
        envRequestController: SessionChannelHookerEnvRequestController,
    ]
    shellRequest: [shellRequestController: SessionChannelHookerShellRequestController]
}

export type SessionChannelEvents = {
    shell: []
}

export default class SessionChannel extends Channel {
    static channel_type = "session"

    hooker: Hooker<SessionChannelHooker> = new Hooker()
    events: EventEmitter<SessionChannelEvents> = new EventEmitter()

    env: Map<string, string> = new Map()
    consumed: boolean = false

    constructor(client: Client | ServerClient, channel_type: string, clientArgs = Buffer.alloc(0)) {
        if (client instanceof Client) {
            // session channel not allowed on client, only on server.
            // https://datatracker.ietf.org/doc/html/rfc4254#section-6.1
            // This would technically be possible, but this is a security
            // flaw (because if a server becomes rogue, it could potentially
            // attack the clients that connect to it.)
            throw new Error("Channel type session cannot be opened on a Client.")
        }
        assert(clientArgs.length === 0, "Client Args for a SessionChannel is non-empty.")
        super(client, channel_type, clientArgs)

        // taken from OpenSSH
        this.local_initial_window_size = 2 ** 21
        this.local_maximum_packet_size = 2 ** 15
    }

    async handleChannelRequest(request: ChannelRequest) {
        assert(
            this.remoteId !== undefined,
            "handleChannelRequest was demanded, but remoteId was not set.",
        )

        switch (request.data.request_type) {
            case "pty-req": {
                this.parsePtyRequest(request.data.args)
                // TODO: Implement PTY.
                break
            }
            case "env": {
                const { key, value } = this.parseEnvRequest(request.data.args)
                this.debug(`Received environment`, key, `=`, value)

                const controller: SessionChannelHookerEnvRequestController = {
                    success: false,
                }
                const context: SessionChannelHookerEnvRequestContext = {
                    key: key,
                    value: value,
                }

                await this.hooker.triggerHook("envRequest", Object.freeze(context), controller)

                if (controller.success) {
                    this.env.set(key, value)

                    if (request.data.want_reply) {
                        this.client.sendPacket(
                            new ChannelSuccess({
                                recipient_channel_id: this.remoteId!,
                            }),
                        )
                    }

                    return
                }

                break
            }
            case "exec": {
                const { command } = this.parseExecRequest(request.data.args)
                this.debug(`Received "exec" command:`, [command])
                this.assertNotConsumed()

                const controller: SessionChannelHookerExecRequestController = {
                    success: false,
                }
                const context: SessionChannelHookerExecRequestContext = {
                    command: command,
                }
                this.hooker.triggerHook("execRequest", Object.freeze(context), controller)

                if (controller.success) {
                    this.consumed = true

                    if (request.data.want_reply) {
                        this.client.sendPacket(
                            new ChannelSuccess({
                                recipient_channel_id: this.remoteId!,
                            }),
                        )
                    }

                    return
                }

                break
            }
            case "shell": {
                // no arguments, but still need to verify args.length === 0
                this.parseShellRequest(request.data.args)
                this.assertNotConsumed()

                const controller: SessionChannelHookerShellRequestController = {
                    success: false,
                }
                await this.hooker.triggerHook("shellRequest", controller)

                if (controller.success) {
                    this.consumed = true

                    if (request.data.want_reply) {
                        this.client.sendPacket(
                            new ChannelSuccess({
                                recipient_channel_id: this.remoteId!,
                            }),
                        )
                    }

                    this.events.emit("shell")

                    return
                }
            }
            // TODO: X11 Forwarding, subsystem
        }

        await super.handleChannelRequest(request)
    }

    parsePtyRequest(raw: Buffer) {
        let term_env: Buffer
        ;[term_env, raw] = readNextBuffer(raw)

        let term_width_chars: number
        ;[term_width_chars, raw] = readNextUint32(raw)

        let term_height_rows: number
        ;[term_height_rows, raw] = readNextUint32(raw)

        let term_width_pixels: number
        ;[term_width_pixels, raw] = readNextUint32(raw)

        let term_height_pixels: number
        ;[term_height_pixels, raw] = readNextUint32(raw)

        // TODO: Also parse encoded modes
        // https://datatracker.ietf.org/doc/html/rfc4254#section-8
        let modes: Buffer
        ;[modes, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return {
            // spec doesn't mention ascii, so whatever
            term_env: term_env.toString("utf8"),
            term_width_chars: term_width_chars,
            term_height_rows: term_height_rows,
            term_width_pixels: term_width_pixels,
            term_height_pixels: term_height_pixels,
            term_modes: modes,
        }
    }

    parseEnvRequest(raw: Buffer) {
        let key: Buffer
        ;[key, raw] = readNextBuffer(raw)

        let value: Buffer
        ;[value, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return {
            key: key.toString("utf8"),
            value: value.toString("utf8"),
        }
    }

    assertNotConsumed() {
        assert(
            !this.consumed,
            "This SessionChannel has already been consumed by one shell, exec or subsystem request.",
        )
    }

    parseExecRequest(raw: Buffer) {
        let command: Buffer
        ;[command, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return {
            command: command.toString("utf8"),
        }
    }

    parseShellRequest(raw: Buffer) {
        assert(raw.length === 0)
        return {}
    }
}
