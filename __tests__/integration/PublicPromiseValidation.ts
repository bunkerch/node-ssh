import Client from "../../src/Client.js"

function invokePromise(operation: () => Promise<unknown>): Promise<unknown> {
    let result: Promise<unknown> | undefined
    expect(() => {
        result = operation()
    }).not.toThrow()
    expect(result).toBeInstanceOf(Promise)
    return result!
}

describe("public Promise operation validation", () => {
    test("rejects invalid channel metadata before allocating an identifier", async () => {
        const client = new Client({ username: "test", strictVendor: false })
        const operations: readonly [() => Promise<unknown>, string][] = [
            [() => client.exec("invalid\ud800command"), "SSH exec command is not valid UTF-8 text"],
            [
                () => client.subsystem(""),
                "SSH subsystem name must be 1 to 64 printable US-ASCII characters",
            ],
            [
                () => client.forwardOut("source.example", 0, "target.example", -1),
                "SSH destination port must be between 0 and 65535",
            ],
            [
                () => client.forwardOut("source.example", 0, "invalid\ud800target", 22),
                "direct-tcpip destination address is not valid UTF-8 text",
            ],
            [
                () => client.forwardOutStreamLocal(""),
                "SSH stream-local socket path must be non-empty and contain no NUL",
            ],
        ]

        for (const [operation, message] of operations) {
            await expect(invokePromise(operation)).rejects.toThrow(message)
        }
        expect(client.localChannelIndex).toBe(0)
        expect(client.channels.size).toBe(0)
    })
})
