import Client from "../Client.js"
import { serializeBuffer, serializeUint32 } from "../utils/Buffer.js"
import { normalizeSSHSignal } from "../utils/Signal.js"
import ClientChannel from "./ClientChannel.js"

export interface ClientPtyOptions {
    term?: string
    columns?: number
    rows?: number
    width?: number
    height?: number
    modes?: Readonly<Record<number, number>> | ReadonlyMap<number, number>
}

export interface ClientWindowDimensions {
    columns: number
    rows: number
    width?: number
    height?: number
}

export default class ClientSessionChannel extends ClientChannel {
    private started = false
    private ptyRequested = false
    private agentForwardingRequested = false

    constructor(client: Client) {
        super(client, "session")
    }

    async exec(command: string): Promise<void> {
        this.reserveProgram()
        try {
            await this.request("exec", this.serializeString(command))
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
        const columns = options.columns ?? 80
        const rows = options.rows ?? 24
        const width = options.width ?? 640
        const height = options.height ?? 480
        try {
            await this.request(
                "pty-req",
                Buffer.concat([
                    serializeBuffer(Buffer.from(options.term ?? "vt100", "utf8")),
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

    setEnv(name: string, value: string): Promise<void> {
        this.ensureNotStarted("set environment variables")
        return this.request(
            "env",
            Buffer.concat([
                serializeBuffer(Buffer.from(name, "utf8")),
                serializeBuffer(Buffer.from(value, "utf8")),
            ]),
        )
    }

    async openssh_forwardAgent(): Promise<void> {
        this.ensureNotStarted("request agent forwarding")
        if (this.agentForwardingRequested) return
        if (!this.client.options.agent.getStream) {
            throw new Error("The configured authentication agent cannot be forwarded")
        }
        await this.request("auth-agent-req@openssh.com")
        this.agentForwardingRequested = true
        this.client.agentForwardingEnabled = true
    }

    async subsystem(name: string): Promise<void> {
        this.reserveProgram()
        try {
            await this.request("subsystem", serializeBuffer(Buffer.from(name, "ascii")))
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

    private serializeTerminalModes(
        modes?: Readonly<Record<number, number>> | ReadonlyMap<number, number>,
    ): Buffer {
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
