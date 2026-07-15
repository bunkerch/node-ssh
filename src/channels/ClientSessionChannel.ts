import { randomBytes } from "node:crypto"
import Client from "../Client.js"
import { clientConfigurationFor } from "../ConnectionConfiguration.js"
import { serializeBinaryBoolean } from "../utils/BinaryBoolean.js"
import { readNextBinaryBoolean, serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import { normalizeSSHSignal, OPENSSH_INFO_SIGNAL } from "../utils/Signal.js"
import ClientChannel from "./ClientChannel.js"
import ChannelRequest from "../packets/ChannelRequest.js"
import { encodeSSHName } from "../utils/SSHName.js"
import type { TerminalModeSettings } from "../TerminalModes.js"
import { encodeSSHUTF8 } from "../utils/SSHText.js"
import { agentRequestName, type AgentForwardingProtocol } from "../AgentForwarding.js"

export interface ClientPtyOptions {
    term?: string
    columns?: number
    cols?: number
    rows?: number
    width?: number
    height?: number
    modes?: TerminalModeSettings
}

export interface ClientWindowDimensions {
    columns: number
    rows: number
    width?: number
    height?: number
}

export interface ClientX11Options {
    single?: boolean
    protocol?: string
    cookie?: string | Buffer
    screen?: number
}
export interface ClientX11Request {
    single: boolean
    protocol: string
    cookie: string
    screen: number
}

export default class ClientSessionChannel extends ClientChannel {
    private started = false
    private ptyRequested = false
    private agentForwardingRequested = false
    private x11Requested = false

    constructor(client: Client) {
        super(client, "session")
    }

    async exec(command: string): Promise<void> {
        this.reserveProgram()
        try {
            await this.request("exec", serializeBuffer(encodeSSHUTF8(command, "SSH exec command")))
        } catch (error) {
            this.started = false
            throw error
        }
    }

    async shell(): Promise<void> {
        this.reserveProgram()
        try {
            await this.request("shell")
        } catch (error) {
            this.started = false
            throw error
        }
    }

    async requestPty(options: ClientPtyOptions = {}): Promise<void> {
        this.ensureNotStarted("request a PTY")
        if (this.ptyRequested) throw new Error(`SSH session channel ${this.localId} has a PTY`)
        this.ptyRequested = true
        const columns = options.columns ?? options.cols ?? 80
        const rows = options.rows ?? 24
        const width = options.width ?? 640
        const height = options.height ?? 480
        try {
            await this.request(
                "pty-req",
                Buffer.concat([
                    serializeBuffer(
                        encodeSSHUTF8(options.term ?? "vt100", "SSH PTY terminal type"),
                    ),
                    serializeUint32(this.uint32(columns, "PTY columns")),
                    serializeUint32(this.uint32(rows, "PTY rows")),
                    serializeUint32(this.uint32(width, "PTY pixel width")),
                    serializeUint32(this.uint32(height, "PTY pixel height")),
                    serializeBuffer(this.serializeTerminalModes(options.modes)),
                ]),
            )
        } catch (error) {
            this.ptyRequested = false
            throw error
        }
    }

    async setEnv(name: string, value: string, wantReply = true): Promise<void> {
        this.ensureNotStarted("set environment variables")
        await this.request(
            "env",
            Buffer.concat([
                serializeBuffer(encodeSSHUTF8(name, "SSH environment variable name")),
                serializeBuffer(encodeSSHUTF8(value, "SSH environment variable value")),
            ]),
            wantReply,
        )
    }

    async openssh_forwardAgent(): Promise<void> {
        this.client.assertOpenSSHVendor()
        await this.requestAgentForwarding("legacy")
    }

    /** Request RFC 9987 agent forwarding, with the pre-standardization compatibility fallback. */
    async forwardAgent(): Promise<void> {
        const protocol: AgentForwardingProtocol = this.client.rfc9987AgentForwarding
            ? "rfc9987"
            : "legacy"
        if (protocol === "legacy") this.client.assertOpenSSHVendor()
        await this.requestAgentForwarding(protocol)
    }

    private async requestAgentForwarding(protocol: AgentForwardingProtocol): Promise<void> {
        this.ensureNotStarted("request agent forwarding")
        if (this.agentForwardingRequested) return
        if (!clientConfigurationFor(this.client).agent.getStream) {
            throw new Error("The configured authentication agent cannot be forwarded")
        }
        await this.request(agentRequestName(protocol))
        this.agentForwardingRequested = true
        this.client.agentForwardingEnabled = true
    }

    async requestX11(options: ClientX11Options = {}): Promise<Readonly<ClientX11Request>> {
        this.ensureNotStarted("request X11 forwarding")
        if (this.x11Requested) throw new Error(`SSH session channel ${this.localId} has X11`)
        const single = options.single ?? false
        const protocol = options.protocol ?? "MIT-MAGIC-COOKIE-1"
        if (!/^[\x21-\x7e]+$/u.test(protocol)) {
            throw new Error("X11 authentication protocol must be non-empty printable ASCII")
        }
        const cookie = Buffer.isBuffer(options.cookie)
            ? options.cookie.toString("hex")
            : (options.cookie ?? randomBytes(16).toString("hex"))
        if (!/^(?:[0-9a-fA-F]{2})+$/u.test(cookie)) {
            throw new Error("X11 authentication cookie must be non-empty hexadecimal data")
        }
        const screen = this.uint32(options.screen ?? 0, "X11 screen number")
        const normalizedCookie = cookie.toLowerCase()
        await this.request(
            "x11-req",
            Buffer.concat([
                serializeBinaryBoolean(single),
                serializeBuffer(Buffer.from(protocol, "ascii")),
                serializeBuffer(Buffer.from(normalizedCookie, "ascii")),
                serializeUint32(screen),
            ]),
        )
        this.x11Requested = true
        this.client.registerX11Forwarding(this.localId, single)
        this.once("close", () => this.client.unregisterX11Forwarding(this.localId))
        return Object.freeze({ single, protocol, cookie: normalizedCookie, screen })
    }

    async subsystem(name: string): Promise<void> {
        this.reserveProgram()
        try {
            await this.request(
                "subsystem",
                serializeBuffer(encodeSSHName(name, "SSH subsystem name")),
            )
        } catch (error) {
            this.started = false
            throw error
        }
    }

    setWindow(dimensions: ClientWindowDimensions): Promise<void> {
        this.ensureStarted("change terminal dimensions")
        return this.request(
            "window-change",
            Buffer.concat([
                serializeUint32(this.uint32(dimensions.columns, "window columns")),
                serializeUint32(this.uint32(dimensions.rows, "window rows")),
                serializeUint32(this.uint32(dimensions.width ?? 0, "window pixel width")),
                serializeUint32(this.uint32(dimensions.height ?? 0, "window pixel height")),
            ]),
            false,
        )
    }

    signal(name: string): Promise<void> {
        this.ensureStarted("send a signal")
        return this.request(
            "signal",
            serializeBuffer(Buffer.from(normalizeSSHSignal(name), "ascii")),
            false,
        )
    }

    /** Request SIGINFO on an OpenSSH-compatible BSD-derived server. */
    async sendInfoSignal(): Promise<void> {
        this.client.assertOpenSSHVendor()
        await this.signal(OPENSSH_INFO_SIGNAL)
    }

    sendBreak(duration = 0): Promise<void> {
        this.ensureStarted("send a terminal BREAK")
        return this.request("break", serializeUint32(this.uint32(duration, "BREAK duration")))
    }

    break(duration = 0): Promise<void> {
        return this.sendBreak(duration)
    }

    override async receiveRequest(packet: ChannelRequest): Promise<void> {
        if (packet.data.request_type === "xon-xoff") {
            if (packet.data.want_reply) {
                throw new Error("SSH xon-xoff notification must not request a reply")
            }
            const [clientCanDo, remaining] = readNextBinaryBoolean(packet.data.args)
            if (remaining.length !== 0) {
                throw new Error("SSH xon-xoff notification has trailing data")
            }
            this.emit("xonXoff", clientCanDo)
            return
        }
        await super.receiveRequest(packet)
    }

    private reserveProgram(): void {
        if (this.started) {
            throw new Error(`SSH session channel ${this.localId} has already started a program`)
        }
        this.started = true
    }

    private ensureNotStarted(action: string): void {
        if (this.started) {
            throw new Error(`Cannot ${action} after starting an SSH session program`)
        }
    }

    private ensureStarted(action: string): void {
        if (!this.started) {
            throw new Error(`Cannot ${action} before starting an SSH session program`)
        }
    }

    private serializeTerminalModes(modes?: TerminalModeSettings): Buffer {
        const entries = modes instanceof Map ? [...modes.entries()] : Object.entries(modes ?? {})
        const encoded: Buffer[] = []
        for (const [rawOpcode, rawValue] of entries) {
            const opcode = typeof rawOpcode === "number" ? rawOpcode : Number(rawOpcode)
            if (!Number.isInteger(opcode) || opcode < 1 || opcode > 159) {
                throw new RangeError(`SSH terminal mode opcode must be between 1 and 159`)
            }
            encoded.push(
                Buffer.from([opcode]),
                serializeUint32(this.uint32(rawValue, `terminal mode ${opcode}`)),
            )
        }
        encoded.push(Buffer.from([0]))
        return Buffer.concat(encoded)
    }

    private uint32(value: number, name: string): number {
        if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
            throw new RangeError(`${name} must be a uint32`)
        }
        return value
    }
}
