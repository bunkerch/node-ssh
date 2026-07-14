import Channel from "../Channel.js"
import Client from "../Client.js"
import ServerClient from "../ServerClient.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import {
    readNextBinaryBoolean,
    readNextBuffer,
    readNextUint32,
    readNextUint8,
} from "../utils/Buffer.js"
import ChannelSuccess from "../packets/ChannelSuccess.js"
import assert from "assert"
import { Hooker } from "../utils/Hooker.js"
import EventEmitter from "events"
import Shell from "./Session/Shell.js"
import { normalizeSSHSignal } from "../utils/Signal.js"
import SFTPServer, { SFTPServerOptions } from "../sftp/SFTPServer.js"

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
    sftp?: SFTPServerOptions
}
export interface SessionChannelHookerAgentForwardRequestController {
    success: boolean
}
export interface SessionX11Request {
    single: boolean
    protocol: string
    cookie: string
    screen: number
}
export interface SessionChannelHookerX11RequestController {
    success: boolean
}
export interface SessionBreakRequestContext {
    /** Requested BREAK duration in milliseconds; zero asks for the device default. */
    duration: number
}
export interface SessionChannelHookerBreakRequestController {
    success: boolean
}
export interface SessionSignalContext {
    signal: string
}
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type SessionChannelHooker = {
    breakRequest: [
        breakRequestContext: Readonly<SessionBreakRequestContext>,
        breakRequestController: SessionChannelHookerBreakRequestController,
    ]
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
    endOfWrite: []
    shellRequest: [shellRequestController: SessionChannelHookerShellRequestController]
    signal: [signalContext: Readonly<SessionSignalContext>]
    ptyRequest: [
        ptyRequestContext: Readonly<SessionPtyInfo>,
        ptyRequestController: SessionChannelHookerPtyRequestController,
    ]
    subsystemRequest: [
        subsystemRequestContext: Readonly<SessionChannelHookerSubsystemRequestContext>,
        subsystemRequestController: SessionChannelHookerSubsystemRequestController,
    ]
    windowChange: [dimensions: Readonly<SessionWindowDimensions>]
    x11Request: [
        x11RequestContext: Readonly<SessionX11Request>,
        x11RequestController: SessionChannelHookerX11RequestController,
    ]
}

export interface SessionChannelEvents {
    agentForward: []
    break: [duration: number]
    env: [name: string, value: string]
    endOfWrite: []
    exec: [command: string, shell: Shell]
    pty: [pty: Readonly<SessionPtyInfo>]
    shell: [Shell]
    signal: [signal: string]
    sftp: [server: SFTPServer]
    subsystem: [name: string, shell: Shell]
    windowChange: [dimensions: Readonly<SessionWindowDimensions>]
    x11: [request: Readonly<SessionX11Request>]
}

export default class SessionChannel extends Channel {
    static channel_type = "session"

    hooker = new Hooker<SessionChannelHooker>()
    events = new EventEmitter<SessionChannelEvents>()

    env = new Map<string, string>()
    consumed = false

    shell: Shell | undefined
    sftp: SFTPServer | undefined
    pty: Readonly<SessionPtyInfo> | undefined
    x11: Readonly<SessionX11Request> | undefined
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

        if (request.data.request_type === "eow@openssh.com") {
            if (request.data.want_reply || request.data.args.length !== 0) {
                throw new Error("Invalid end-of-write channel request")
            }
            if (!this.hasReceivedEndOfWrite) {
                await this.hooker.triggerHook("endOfWrite")
                this.events.emit("endOfWrite")
                this.receiveEndOfWrite()
            }
            return
        }

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
            case "x11-req": {
                this.assertNotConsumed()
                assert(!this.x11, "This SSH session channel already has X11 forwarding")
                const context = Object.freeze(SessionChannel.parseX11Request(request.data.args))
                const controller: SessionChannelHookerX11RequestController = { success: false }
                await this.hooker.triggerHook("x11Request", context, controller)
                if (controller.success) {
                    this.x11 = context
                    ;(this.client as ServerClient).registerX11Forwarding(
                        this.localId,
                        context.single,
                    )
                    this.sendRequestSuccess(request)
                    this.events.emit("x11", context)
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
                    if (controller.sftp && subsystem !== "sftp") {
                        throw new Error("SFTP options require the sftp subsystem")
                    }
                    this.consumed = true
                    const shell = this.activateShell()
                    this.sendRequestSuccess(request)
                    if (subsystem === "sftp") {
                        const clientSoftware =
                            (this.client as ServerClient).clientProtocolVersion
                                ?.protocol_software ?? ""
                        this.sftp = new SFTPServer(shell, {
                            ...controller.sftp,
                            openSSHSymlinkArguments:
                                controller.sftp?.openSSHSymlinkArguments ??
                                /^(?:OpenSSH_|dropbear)/iu.test(clientSoftware),
                        })
                        this.events.emit("sftp", this.sftp)
                    } else {
                        this.events.emit("subsystem", subsystem, shell)
                    }
                    return
                }
                break
            }
            case "window-change": {
                assert(!request.data.want_reply, "SSH window-change must not request a reply")
                const dimensions = Object.freeze(this.parseWindowChange(request.data.args))
                await this.hooker.triggerHook("windowChange", dimensions)
                this.events.emit("windowChange", dimensions)
                return
            }
            case "signal": {
                assert(!request.data.want_reply, "SSH signal request must not request a reply")
                assert(this.consumed, "Cannot signal an SSH session before its program starts")
                const signal = this.parseSignalRequest(request.data.args)
                await this.hooker.triggerHook("signal", Object.freeze({ signal }))
                this.events.emit("signal", signal)
                return
            }
            case "break": {
                assert(this.consumed, "Cannot send BREAK before an SSH session program starts")
                const [duration, remaining] = readNextUint32(request.data.args)
                assert(remaining.length === 0, "SSH BREAK request has trailing data")
                const context = Object.freeze({ duration })
                const controller: SessionChannelHookerBreakRequestController = { success: false }
                await this.hooker.triggerHook("breakRequest", context, controller)
                if (controller.success) {
                    this.sendRequestSuccess(request)
                    this.events.emit("break", duration)
                    return
                }
                break
            }
            case "xon-xoff": {
                // This notification travels from server to client, never in this direction.
                break
            }
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

    static parseX11Request(raw: Buffer): SessionX11Request {
        const [single, afterSingle] = readNextBinaryBoolean(raw)
        const [protocol, afterProtocol] = readNextBuffer(afterSingle)
        const [cookie, afterCookie] = readNextBuffer(afterProtocol)
        const [screen, remaining] = readNextUint32(afterCookie)
        assert(remaining.length === 0, "X11 forwarding request has trailing data")
        assert(
            protocol.length > 0 && protocol.every((byte) => byte >= 0x21 && byte <= 0x7e),
            "X11 authentication protocol must be printable ASCII",
        )
        assert(
            cookie.length > 0 &&
                cookie.length % 2 === 0 &&
                cookie.every(
                    (byte) =>
                        (byte >= 0x30 && byte <= 0x39) ||
                        (byte >= 0x41 && byte <= 0x46) ||
                        (byte >= 0x61 && byte <= 0x66),
                ),
            "X11 authentication cookie must be hexadecimal",
        )
        const protocolName = protocol.toString("ascii")
        const cookieHex = cookie.toString("ascii")
        return { single, protocol: protocolName, cookie: cookieHex, screen }
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
        ;(this.client as ServerClient).unregisterX11Forwarding(this.localId)
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
