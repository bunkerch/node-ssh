import { createHash } from "node:crypto"
import { createRequire } from "node:module"
import type koffi from "koffi"
import { SSHAgentError } from "./SSHAgent.js"

const require = createRequire(import.meta.url)
const PAGEANT_PIPE_INPUT = Buffer.from("Pageant\0", "ascii")
const CRYPTPROTECTMEMORY_BLOCK_SIZE = 16
const CRYPTPROTECTMEMORY_CROSS_PROCESS = 1
const NAME_USER_PRINCIPAL = 8
const CP_ACP = 0
const PAGEANT_PIPE_HASH_PREFIX = Buffer.from([0, 0, 0, CRYPTPROTECTMEMORY_BLOCK_SIZE])

type Koffi = typeof koffi
type NativeFunction = (...args: unknown[]) => unknown

function loadKoffi(): Koffi {
    // Keep the native FFI binding out of non-Windows import and startup paths.
    try {
        return require("koffi") as Koffi
    } catch (cause) {
        throw new PageantAgentError(
            'Automatic Pageant discovery requires the optional "koffi" package',
            { cause },
        )
    }
}

function readWindowsName(
    getName: NativeFunction,
    prefixArguments: readonly unknown[] = [],
): Buffer | undefined {
    const length = [0]
    getName(...prefixArguments, null, length)
    if (!Number.isSafeInteger(length[0]) || length[0] <= 1 || length[0] > 32_768) return undefined

    const raw = Buffer.alloc(length[0])
    if (!getName(...prefixArguments, raw, length)) return undefined
    const nul = raw.indexOf(0)
    return raw.subarray(0, nul === -1 ? raw.length : nul)
}

function decodeWindowsAnsi(koffiModule: Koffi, value: Buffer): string {
    const kernel32 = koffiModule.load("kernel32.dll")
    try {
        const multiByteToWideChar = kernel32.func(
            "int __stdcall MultiByteToWideChar(uint32_t, uint32_t, const void *, int, _Out_ void *, int)",
        ) as NativeFunction
        const wideLength = multiByteToWideChar(CP_ACP, 0, value, value.length, null, 0)
        if (typeof wideLength !== "number" || wideLength <= 0 || wideLength > 32_768) {
            throw new Error("Windows could not decode the Pageant user name")
        }
        const wide = Buffer.alloc(wideLength * 2)
        const converted = multiByteToWideChar(CP_ACP, 0, value, value.length, wide, wideLength)
        if (converted !== wideLength)
            throw new Error("Windows could not decode the Pageant user name")
        return wide.toString("utf16le")
    } finally {
        kernel32.unload()
    }
}

function readPageantUserName(koffiModule: Koffi): string {
    const secur32 = koffiModule.load("secur32.dll")
    let raw: Buffer | undefined
    try {
        const getUserNameEx = secur32.func(
            "int __stdcall GetUserNameExA(int, _Out_ void *, _Inout_ uint32_t *)",
        ) as NativeFunction
        raw = readWindowsName(getUserNameEx, [NAME_USER_PRINCIPAL])
        const at = raw?.indexOf(0x40) ?? -1
        if (raw && at !== -1) raw = raw.subarray(0, at)
    } finally {
        secur32.unload()
    }

    if (!raw) {
        const advapi32 = koffiModule.load("advapi32.dll")
        try {
            const getUserName = advapi32.func(
                "int __stdcall GetUserNameA(_Out_ void *, _Inout_ uint32_t *)",
            ) as NativeFunction
            raw = readWindowsName(getUserName)
        } finally {
            advapi32.unload()
        }
    }
    if (!raw || raw.length === 0)
        throw new Error("Windows could not determine the Pageant user name")
    return decodeWindowsAnsi(koffiModule, raw)
}

function pageantPipeSuffix(koffiModule: Koffi): string {
    const protectedMemory = Buffer.alloc(CRYPTPROTECTMEMORY_BLOCK_SIZE)
    PAGEANT_PIPE_INPUT.copy(protectedMemory)
    const crypt32 = koffiModule.load("crypt32.dll")
    try {
        const cryptProtectMemory = crypt32.func(
            "int __stdcall CryptProtectMemory(_Inout_ void *, uint32_t, uint32_t)",
        ) as NativeFunction
        if (
            !cryptProtectMemory(
                protectedMemory,
                protectedMemory.length,
                CRYPTPROTECTMEMORY_CROSS_PROCESS,
            )
        ) {
            throw new Error("Windows could not derive the Pageant pipe name")
        }
    } finally {
        crypt32.unload()
    }
    return createHash("sha256")
        .update(PAGEANT_PIPE_HASH_PREFIX)
        .update(protectedMemory)
        .digest("hex")
}

/** Discover the named pipe used by Pageant 0.75 and newer for the current Windows user. */
export function discoverPageantAgentSocket(): string {
    if (process.platform !== "win32") {
        throw new PageantAgentError("Automatic Pageant discovery is only available on Windows")
    }
    try {
        const koffiModule = loadKoffi()
        const username = readPageantUserName(koffiModule)
        return String.raw`\\.\pipe\pageant.${username}.${pageantPipeSuffix(koffiModule)}`
    } catch (cause) {
        if (cause instanceof PageantAgentError) throw cause
        throw new PageantAgentError("Could not discover the Pageant named pipe", { cause })
    }
}

export class PageantAgentError extends SSHAgentError {
    override name = "PageantAgentError"
}
