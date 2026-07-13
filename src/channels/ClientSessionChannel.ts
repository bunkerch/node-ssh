import Client from "../Client.js"
import ClientChannel from "./ClientChannel.js"

export default class ClientSessionChannel extends ClientChannel {
    private started = false

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

    private reserveProgram(): void {
        if (this.started) {
            throw new Error(`SSH session channel ${this.localId} has already started a program`)
        }
        this.started = true
    }
}
