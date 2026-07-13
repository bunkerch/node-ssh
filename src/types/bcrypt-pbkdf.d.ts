declare module "bcrypt-pbkdf" {
    export function pbkdf(
        passphrase: Uint8Array,
        passphraseLength: number,
        salt: Uint8Array,
        saltLength: number,
        key: Uint8Array,
        keyLength: number,
        rounds: number,
    ): number
}
