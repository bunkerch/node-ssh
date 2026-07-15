const STANDARD_SIGNALS = new Set([
    "ABRT",
    "ALRM",
    "FPE",
    "HUP",
    "ILL",
    "INT",
    "KILL",
    "PIPE",
    "QUIT",
    "SEGV",
    "TERM",
    "USR1",
    "USR2",
])

/** OpenSSH extension that requests SIGINFO on BSD-derived systems. */
export const OPENSSH_INFO_SIGNAL = "INFO@openssh.com"

export function normalizeSSHSignal(value: string): string {
    const withoutPrefix = value.startsWith("SIG") ? value.slice(3) : value
    const signal = STANDARD_SIGNALS.has(withoutPrefix) ? withoutPrefix : value
    if (STANDARD_SIGNALS.has(signal)) return signal
    if (/^[\x21-\x3f\x41-\x7e]+@[\x21-\x3f\x41-\x7e]+$/u.test(signal)) return signal
    throw new Error(`Invalid SSH signal name: ${value}`)
}
