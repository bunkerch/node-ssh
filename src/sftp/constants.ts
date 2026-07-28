export const SFTP_VERSION = 3
export const MAX_SFTP_PACKET_LENGTH = 256 * 1024
export const MAX_SFTP_HANDLE_LENGTH = 256

export enum SFTPPacketType {
    Init = 1,
    Version = 2,
    Open = 3,
    Close = 4,
    Read = 5,
    Write = 6,
    LStat = 7,
    FStat = 8,
    SetStat = 9,
    FSetStat = 10,
    OpenDir = 11,
    ReadDir = 12,
    Remove = 13,
    MkDir = 14,
    RmDir = 15,
    RealPath = 16,
    Stat = 17,
    Rename = 18,
    ReadLink = 19,
    SymLink = 20,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
    Extended = 200,
    ExtendedReply = 201,
}

export enum SFTPStatusCode {
    Ok = 0,
    EOF = 1,
    NoSuchFile = 2,
    PermissionDenied = 3,
    Failure = 4,
    BadMessage = 5,
    NoConnection = 6,
    ConnectionLost = 7,
    OperationUnsupported = 8,
    /** Registered extension status used by copy-data version 1. */
    InvalidParameter = 23,
}

export enum SFTPOpenFlags {
    Read = 0x0000_0001,
    Write = 0x0000_0002,
    Append = 0x0000_0004,
    Create = 0x0000_0008,
    Truncate = 0x0000_0010,
    Exclusive = 0x0000_0020,
}

const SFTP_OPEN_FLAGS_MASK =
    SFTPOpenFlags.Read |
    SFTPOpenFlags.Write |
    SFTPOpenFlags.Append |
    SFTPOpenFlags.Create |
    SFTPOpenFlags.Truncate |
    SFTPOpenFlags.Exclusive

export function validateSFTPOpenFlags(flags: number): void {
    if (!Number.isSafeInteger(flags) || flags < 0 || flags > 0xffff_ffff) {
        throw new RangeError("SFTP open flags must be a uint32")
    }
    if ((flags & ~SFTP_OPEN_FLAGS_MASK) !== 0) {
        throw new Error("SFTP open flags contain unknown bits")
    }
    if ((flags & SFTPOpenFlags.Exclusive) !== 0 && (flags & SFTPOpenFlags.Create) === 0) {
        throw new Error("SFTP exclusive flag requires create")
    }
}

export enum SFTPAttributeFlags {
    Size = 0x0000_0001,
    UIDGID = 0x0000_0002,
    Permissions = 0x0000_0004,
    AccessModificationTime = 0x0000_0008,
    Extended = 0x8000_0000,
}

export const SFTP_ATTRIBUTE_FLAGS_MASK =
    SFTPAttributeFlags.Size |
    SFTPAttributeFlags.UIDGID |
    SFTPAttributeFlags.Permissions |
    SFTPAttributeFlags.AccessModificationTime |
    SFTPAttributeFlags.Extended
