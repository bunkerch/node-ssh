import { execFile } from "node:child_process"
import { promisify } from "node:util"

import {
    compression_algorithms,
    encryption_algorithms,
    kex_algorithms,
    mac_algorithm_names,
    public_key_signature_algorithms,
} from "../../src/algorithms.js"

const execFileAsync = promisify(execFile)

const catalogs = [
    {
        query: "cipher",
        supported: () => encryption_algorithms.keys(),
    },
    {
        query: "cipher-auth",
        supported: () => encryption_algorithms.keys(),
    },
    {
        query: "compression",
        supported: () => compression_algorithms.keys(),
    },
    {
        query: "kex",
        supported: () => kex_algorithms.keys(),
    },
    {
        query: "key",
        supported: () => public_key_signature_algorithms,
    },
    {
        query: "key-sig",
        supported: () => public_key_signature_algorithms,
    },
    {
        query: "mac",
        supported: () => mac_algorithm_names,
    },
    {
        query: "sig",
        supported: () => public_key_signature_algorithms,
    },
] as const

describe("system OpenSSH algorithm catalog", () => {
    test.each(catalogs)("supports every $query algorithm exposed by ssh -Q", async (catalog) => {
        const { stdout } = await execFileAsync("ssh", ["-Q", catalog.query])
        const systemAlgorithms = stdout.trim().split("\n").filter(Boolean)
        const supported = new Set(catalog.supported())

        expect(systemAlgorithms.length).toBeGreaterThan(0)
        expect(systemAlgorithms.filter((algorithm) => !supported.has(algorithm))).toEqual([])
    })
})
