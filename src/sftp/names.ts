import { SFTPProtocolError } from "./codec.js"

export function validateSFTPDirectoryEntryName(filename: Buffer): void {
    if (filename.length === 0) {
        throw new SFTPProtocolError("SFTP READDIR filename must not be empty")
    }
    if (filename.includes(0x2f)) {
        throw new SFTPProtocolError("SFTP READDIR filename must not contain path separators")
    }
}

export function validateSFTPRealPath(filename: Buffer): void {
    if (filename[0] !== 0x2f) {
        throw new SFTPProtocolError("SFTP REALPATH response must be absolute")
    }
}
