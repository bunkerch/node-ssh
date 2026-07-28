import { Duplex } from "node:stream"
import Server from "../../src/Server.js"
import ServerClient from "../../src/ServerClient.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

describe("server connection lifecycle", () => {
    test("reports a transport failure only after close cleanup", async () => {
        class FailingCloseTransport extends Duplex {
            readonly writes: Buffer[] = []

            _read(): void {
                void this.readableLength
            }

            _write(
                _chunk: Buffer,
                _encoding: BufferEncoding,
                callback: (error?: Error | null) => void,
            ): void {
                this.writes.push(Buffer.from(_chunk))
                callback()
            }

            _final(callback: (error?: Error | null) => void): void {
                callback(new Error("server transport close failed"))
            }
        }

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey] })
        const transport = new FailingCloseTransport()
        const connection = new ServerClient(transport, server)
        const observations: string[] = []
        connection.on("close", () => observations.push("close"))

        await expect(connection.close()).rejects.toThrow("server transport close failed")
        expect(observations).toEqual(["close"])
        expect(connection.isConnected).toBe(false)
        expect(transport.writes).toEqual([])
        await connection[Symbol.asyncDispose]()
    })

    test("bounds graceful shutdown when the transport never finishes", async () => {
        class StalledCloseTransport extends Duplex {
            _read(): void {
                void this.readableLength
            }

            _write(
                _chunk: Buffer,
                _encoding: BufferEncoding,
                callback: (error?: Error | null) => void,
            ): void {
                callback()
            }

            _final(callback: (error?: Error | null) => void): void {
                // Deliberately never completes the graceful stream shutdown.
                void callback
            }
        }

        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const server = new Server({ hostKeys: [hostKey], replyTimeout: 20 })
        const transport = new StalledCloseTransport()
        const connection = new ServerClient(transport, server)
        const observations: string[] = []
        connection.on("close", () => observations.push("close"))

        await expect(connection.close()).rejects.toThrow(
            "Timed out while closing SSH server connection",
        )
        expect(observations).toEqual(["close"])
        expect(transport.destroyed).toBe(true)
        expect(connection.isConnected).toBe(false)
        await connection[Symbol.asyncDispose]()
    })
})
