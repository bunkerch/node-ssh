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
})
