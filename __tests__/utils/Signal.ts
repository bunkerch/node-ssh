import { normalizeSSHSignal } from "../../src/utils/Signal.js"

describe("SSH signal names", () => {
    test("normalizes the optional SIG prefix for RFC 4254 standard signals", () => {
        expect(normalizeSSHSignal("SIGTERM")).toBe("TERM")
        expect(normalizeSSHSignal("USR1")).toBe("USR1")
    })

    test("accepts extension signal names without rewriting them", () => {
        expect(normalizeSSHSignal("SIG@example.com")).toBe("SIG@example.com")
        expect(normalizeSSHSignal("custom-signal@example.com")).toBe("custom-signal@example.com")
    })

    test("rejects unknown, non-extension and non-ASCII names", () => {
        expect(() => normalizeSSHSignal("SIGFAKE")).toThrow("Invalid SSH signal name")
        expect(() => normalizeSSHSignal("TERM@@example.com")).toThrow("Invalid SSH signal name")
        expect(() => normalizeSSHSignal("térm@example.com")).toThrow("Invalid SSH signal name")
    })
})
