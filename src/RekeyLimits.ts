export const DEFAULT_REKEY_BYTES = 1_073_741_824
export const DEFAULT_REKEY_INTERVAL = 3_600_000

const MAXIMUM_TIMER_INTERVAL = 2_147_483_647

export function validateRekeyBytes(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError("SSH rekey byte limit must be a non-negative safe integer")
    }
}

export function validateRekeyInterval(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > MAXIMUM_TIMER_INTERVAL) {
        throw new RangeError(
            `SSH rekey interval must be an integer between 0 and ${MAXIMUM_TIMER_INTERVAL}`,
        )
    }
}
