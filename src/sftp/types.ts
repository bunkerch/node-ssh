import { SFTPPacketType } from "./constants.js"

export interface SFTPExtension {
    name: string
    data: Buffer
}

export interface SFTPExtendedAttribute {
    type: Buffer
    data: Buffer
}

export interface SFTPAttributes {
    size?: bigint
    uid?: number
    gid?: number
    permissions?: number
    accessTime?: number
    modificationTime?: number
    extended?: readonly SFTPExtendedAttribute[]
}

export interface SFTPNameEntry {
    filename: Buffer
    longname: Buffer
    attributes: SFTPAttributes
}

export interface SFTPInitPacket {
    type: SFTPPacketType.Init
    version: number
    extensions: readonly SFTPExtension[]
}

export interface SFTPVersionPacket {
    type: SFTPPacketType.Version
    version: number
    extensions: readonly SFTPExtension[]
}

export interface SFTPRequestPacketBase {
    requestId: number
}

export interface SFTPOpenPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Open
    filename: Buffer
    flags: number
    attributes: SFTPAttributes
}

export interface SFTPHandleRequestPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Close | SFTPPacketType.FStat | SFTPPacketType.ReadDir
    handle: Buffer
}

export interface SFTPReadPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Read
    handle: Buffer
    offset: bigint
    length: number
}

export interface SFTPWritePacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Write
    handle: Buffer
    offset: bigint
    data: Buffer
}

export interface SFTPPathPacket extends SFTPRequestPacketBase {
    type:
        | SFTPPacketType.LStat
        | SFTPPacketType.OpenDir
        | SFTPPacketType.Remove
        | SFTPPacketType.RmDir
        | SFTPPacketType.RealPath
        | SFTPPacketType.Stat
        | SFTPPacketType.ReadLink
    path: Buffer
}

export interface SFTPSetStatPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.SetStat
    path: Buffer
    attributes: SFTPAttributes
}

export interface SFTPFSetStatPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.FSetStat
    handle: Buffer
    attributes: SFTPAttributes
}

export interface SFTPMkDirPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.MkDir
    path: Buffer
    attributes: SFTPAttributes
}

export interface SFTPTwoPathPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Rename | SFTPPacketType.SymLink
    firstPath: Buffer
    secondPath: Buffer
}

export interface SFTPStatusPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Status
    code: number
    message: string
    languageTag: string
}

export interface SFTPHandlePacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Handle
    handle: Buffer
}

export interface SFTPDataPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Data
    data: Buffer
}

export interface SFTPNamePacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Name
    names: readonly SFTPNameEntry[]
}

export interface SFTPAttrsPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Attrs
    attributes: SFTPAttributes
}

export interface SFTPExtendedPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.Extended
    request: string
    data: Buffer
}

export interface SFTPExtendedReplyPacket extends SFTPRequestPacketBase {
    type: SFTPPacketType.ExtendedReply
    data: Buffer
}

export type SFTPRequestPacket =
    | SFTPOpenPacket
    | SFTPHandleRequestPacket
    | SFTPReadPacket
    | SFTPWritePacket
    | SFTPPathPacket
    | SFTPSetStatPacket
    | SFTPFSetStatPacket
    | SFTPMkDirPacket
    | SFTPTwoPathPacket
    | SFTPExtendedPacket

export type SFTPPacket =
    | SFTPInitPacket
    | SFTPVersionPacket
    | SFTPOpenPacket
    | SFTPHandleRequestPacket
    | SFTPReadPacket
    | SFTPWritePacket
    | SFTPPathPacket
    | SFTPSetStatPacket
    | SFTPFSetStatPacket
    | SFTPMkDirPacket
    | SFTPTwoPathPacket
    | SFTPStatusPacket
    | SFTPHandlePacket
    | SFTPDataPacket
    | SFTPNamePacket
    | SFTPAttrsPacket
    | SFTPExtendedPacket
    | SFTPExtendedReplyPacket
