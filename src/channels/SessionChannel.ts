import Channel from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import { readNextBuffer, readNextUint32, readNextUint8 } from "../utils/Buffer.js"
import ChannelSuccess from "../packets/ChannelSuccess.js"
import assert from "assert"
import { Hooker } from "../utils/Hooker.js"
import EventEmitter from "events"
import Shell from "./Session/Shell.js"
import { normalizeSSHSignal } from "../utils/Signal.js"

export interface SessionPtyInfo {
    term: string
    columns: number
    rows: number
    width: number
    height: number
    modes: ReadonlyMap<number, number>
}

export interface SessionWindowDimensions {
    columns: number
    rows: number
    width: number
    height: number
}

export interface SessionChannelHookerExecRequestContext {
    command: string
}
export interface SessionChannelHookerExecRequestController {
    success: boolean
}
export interface SessionChannelHookerEnvRequestContext {
    key: string
    value: string
}
export interface SessionChannelHookerEnvRequestController {
    success: boolean
}
export interface SessionChannelHookerShellRequestController {
    success: boolean
}
export interface SessionChannelHookerPtyRequestController {
    success: boolean
}
export interface SessionChannelHookerSubsystemRequestContext {
    subsystem: string
}
export interface SessionChannelHookerSubsystemRequestController {
    success: boolean
}
export interface SessionChannelHookerAgentForwardRequestController {
    success: boolean
}
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SessionChannelHooker = {
    agentForwardRequest: [
        agentForwardRequestController: SessionChannelHookerAgentForwardRequestController,
    ]
    execRequest: [
        execRequestContext: Readonly<SessionChannelHookerExecRequestContext>,
        execRequestController: SessionChannelHookerExecRequestController,
    ]
    envRequest: [
        envRequestContext: Readonly<SessionChannelHookerEnvRequestContext>,
        envRequestController: SessionChannelHookerEnvRequestController,
    ]
    shellRequest: [shellRequestController: SessionChannelHookerShellRequestController]
    ptyRequest: [
        ptyRequestContext: Readonly<SessionPtyInfo>,
        ptyRequestController: SessionChannelHookerPtyRequestController,
    ]
    subsystemRequest: [
        subsystemRequestContext: Readonly<SessionChannelHookerSubsystemRequestContext>,
        subsystemRequestController: SessionChannelHookerSubsystemRequestController,
    ]
}

export interface SessionChannelEvents {
    agentForward: []
    env: [name: string, value: string]
    exec: [command: string, shell: Shell]
    pty: [pty: Readonly<SessionPtyInfo>]
    shell: [Shell]
    signal: [signal: string]
    subsystem: [name: string, shell: Shell]
    windowChange: [dimensions: Readonly<SessionWindowDimensions>]
}

export default class SessionChannel extends Channel {
    static channel_type = "session"

    hooker = new Hooker<SessionChannelHooker>()
    events = new EventEmitter<SessionChannelEvents>()

    env = new Map<string, string>()
    consumed = false

    shell: Shell | undefined
    pty: Readonly<SessionPtyInfo> | undefined
    private readonly pendingInput: Buffer[] = []
    private inputEnded = false

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
            case "auth-agent-req@openssh.com": {
                assert(request.data.args.length === 0, "Agent forwarding request has trailing data")
                this.assertNotConsumed()
                const controller: SessionChannelHookerAgentForwardRequestController = {
                    success: false,
                }
                await this.hooker.triggerHook("agentForwardRequest", controller)
                if (controller.success) {
                    ;(this.client as ServerClient).agentForwardingEnabled = true
                    this.sendRequestSuccess(request)
                    this.events.emit("agentForward")
                    return
                }
                break
            }
            case "pty-req": {
                this.assertNotConsumed()
                assert(!this.pty, "This SSH session channel already has a PTY")
                const pty = Object.freeze(this.parsePtyRequest(request.data.args))
                const controller: SessionChannelHookerPtyRequestController = { success: false }
                await this.hooker.triggerHook("ptyRequest", pty, controller)
                if (controller.success) {
                    this.pty = pty
                    this.sendRequestSuccess(request)
                    this.events.emit("pty", pty)
                    return
                }
                break
            }
            case "env": {
                this.assertNotConsumed()
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

                    this.events.emit("env", key, value)
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
                await this.hooker.triggerHook("execRequest", Object.freeze(context), controller)

                if (controller.success) {
                    this.consumed = true
                    const shell = this.activateShell()

                    if (request.data.want_reply) {
                        this.client.sendPacket(
                            new ChannelSuccess({
                                recipient_channel_id: this.remoteId!,
                            }),
                        )
                    }

                    this.events.emit("exec", command, shell)
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
                    const shell = this.activateShell()

                    if (request.data.want_reply) {
                        this.client.sendPacket(
                            new ChannelSuccess({
                                recipient_channel_id: this.remoteId!,
                            }),
                        )
                    }

                    this.events.emit("shell", shell)

                    return
                }

                break
            }
            case "subsystem": {
                const { subsystem } = this.parseSubsystemRequest(request.data.args)
                this.assertNotConsumed()
                const controller: SessionChannelHookerSubsystemRequestController = {
                    success: false,
                }
                const context: SessionChannelHookerSubsystemRequestContext = { subsystem }
                await this.hooker.triggerHook(
                    "subsystemRequest",
                    Object.freeze(context),
                    controller,
                )
                if (controller.success) {
                    this.consumed = true
                    const shell = this.activateShell()
                    this.sendRequestSuccess(request)
                    this.events.emit("subsystem", subsystem, shell)
                    return
                }
                break
            }
            case "window-change": {
                const dimensions = Object.freeze(this.parseWindowChange(request.data.args))
                this.events.emit("windowChange", dimensions)
                return
            }
            case "signal": {
                assert(this.consumed, "Cannot signal an SSH session before its program starts")
                const signal = this.parseSignalRequest(request.data.args)
                this.events.emit("signal", signal)
                return
            }
            case "xon-xoff": {
                // This notification travels from server to client, never in this direction.
                break
            }
            // TODO: X11 forwarding requests.
        }

        await super.handleChannelRequest(request)
    }

    parsePtyRequest(raw: Buffer) {
        let term: Buffer
        ;[term, raw] = readNextBuffer(raw)

        let term_width_chars: number
        ;[term_width_chars, raw] = readNextUint32(raw)

        let term_height_rows: number
        ;[term_height_rows, raw] = readNextUint32(raw)

        let term_width_pixels: number
        ;[term_width_pixels, raw] = readNextUint32(raw)

        let term_height_pixels: number
        ;[term_height_pixels, raw] = readNextUint32(raw)

        let encodedModes: Buffer
        ;[encodedModes, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return {
            term: term.toString("utf8"),
            columns: term_width_chars,
            rows: term_height_rows,
            width: term_width_pixels,
            height: term_height_pixels,
            modes: this.parseTerminalModes(encodedModes),
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

    parseSubsystemRequest(raw: Buffer) {
        let subsystem: Buffer
        ;[subsystem, raw] = readNextBuffer(raw)

        assert(raw.length === 0)

        return {
            subsystem: subsystem.toString("ascii"),
        }
    }

    parseWindowChange(raw: Buffer): SessionWindowDimensions {
        const [columns, afterColumns] = readNextUint32(raw)
        const [rows, afterRows] = readNextUint32(afterColumns)
        const [width, afterWidth] = readNextUint32(afterRows)
        const [height, remaining] = readNextUint32(afterWidth)
        assert(remaining.length === 0)
        return { columns, rows, width, height }
    }

    parseSignalRequest(raw: Buffer): string {
        const [signal, remaining] = readNextBuffer(raw)
        assert(remaining.length === 0)
        const name = signal.toString("ascii")
        const normalized = normalizeSSHSignal(name)
        assert(normalized === name, 'SSH signal requests must omit the "SIG" prefix')
        return normalized
    }

    parseTerminalModes(raw: Buffer): ReadonlyMap<number, number> {
        const modes = new Map<number, number>()
        while (raw.length > 0) {
            let opcode: number
            ;[opcode, raw] = readNextUint8(raw)
            if (opcode === 0) {
                assert(raw.length === 0, "SSH terminal modes contain data after TTY_OP_END")
                return modes
            }
            if (opcode >= 160) return modes
            let value: number
            ;[value, raw] = readNextUint32(raw)
            modes.set(opcode, value)
        }
        throw new Error("SSH terminal modes are missing TTY_OP_END")
    }

    protected handleData(data: Buffer): boolean {
        if (!this.shell) {
            this.pendingInput.push(data)
            return false
        }
        return this.shell.receive(data)
    }

    protected handleExtendedData(dataType: number, data: Buffer): boolean {
        void dataType
        void data
        return true
    }

    protected handleEOF(): void {
        this.inputEnded = true
        this.shell?.receiveEOF()
    }

    protected handleClose(): void {
        this.shell?.closeFromRemote()
    }

    private activateShell(): Shell {
        this.shell = new Shell(this)
        let hasCapacity = true
        for (const data of this.pendingInput) {
            if (!this.shell.receive(data)) hasCapacity = false
        }
        this.pendingInput.length = 0
        if (this.inputEnded) this.shell.receiveEOF()
        if (hasCapacity) this.resumeInput()
        return this.shell
    }

    private sendRequestSuccess(request: ChannelRequest): void {
        if (request.data.want_reply) {
            this.client.sendPacket(new ChannelSuccess({ recipient_channel_id: this.remoteId! }))
        }
    }
}
