export const defaultProtocolVersionExchange = "SSH-2.0-modernssh_1.0.1\r\n"

export enum SocketState {
    Connecting,
    Connected,
    Closed,
    Disconnected,
}

export const PacketNameToType = {
    SSH_MSG_DISCONNECT: 1,
    SSH_MSG_IGNORE: 2,
    SSH_MSG_UNIMPLEMENTED: 3,
    SSH_MSG_DEBUG: 4,
    SSH_MSG_SERVICE_REQUEST: 5,
    SSH_MSG_SERVICE_ACCEPT: 6,
    SSH_MSG_EXT_INFO: 7,
    SSH_MSG_NEWCOMPRESS: 8,

    SSH_MSG_KEXINIT: 20,
    SSH_MSG_NEWKEYS: 21,

    SSH_MSG_KEXDH_INIT: 30,
    SSH_MSG_KEXDH_REPLY: 31,
    SSH_MSG_KEX_DH_GEX_INIT: 32,
    SSH_MSG_KEX_DH_GEX_REPLY: 33,
    SSH_MSG_KEX_DH_GEX_REQUEST: 34,

    SSH_MSG_USERAUTH_REQUEST: 50,
    SSH_MSG_USERAUTH_FAILURE: 51,
    SSH_MSG_USERAUTH_SUCCESS: 52,
    SSH_MSG_USERAUTH_BANNER: 53,

    // This is messed up in the spec
    // not my fault
    SSH_MSG_USERAUTH_PK_OK: 60,
    SSH_MSG_USERAUTH_INFO_RESPONSE: 61,
    SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: 63,
    SSH_MSG_USERAUTH_GSSAPI_ERROR: 64,
    SSH_MSG_USERAUTH_GSSAPI_ERRTOK: 65,
    SSH_MSG_USERAUTH_GSSAPI_MIC: 66,

    SSH_MSG_GLOBAL_REQUEST: 80,
    SSH_MSG_REQUEST_SUCCESS: 81,
    SSH_MSG_REQUEST_FAILURE: 82,

    SSH_MSG_CHANNEL_OPEN: 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION: 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE: 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST: 93,
    SSH_MSG_CHANNEL_DATA: 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA: 95,
    SSH_MSG_CHANNEL_EOF: 96,
    SSH_MSG_CHANNEL_CLOSE: 97,
    SSH_MSG_CHANNEL_REQUEST: 98,
    SSH_MSG_CHANNEL_SUCCESS: 99,
    SSH_MSG_CHANNEL_FAILURE: 100,

    SSH_MSG_PING: 192,
    SSH_MSG_PONG: 193,
} as const
export const PacketTypeToName = Object.fromEntries(
    Object.entries(PacketNameToType).map(([key, value]) => [value, key]),
) as {
    readonly [Type in PacketName as (typeof PacketNameToType)[Type]]: Type
}
export type PacketName = keyof typeof PacketNameToType
export type PacketType = keyof typeof PacketTypeToName

export const SEQUENCE_NUMBER_MODULO = 2 ** 32

export enum SSHServiceNames {
    UserAuth = "ssh-userauth",
    Connection = "ssh-connection",
}

export enum SSHAuthenticationMethods {
    None = "none",
    PublicKey = "publickey",
    Hostbased = "hostbased",
    Password = "password",
    KeyboardInteractive = "keyboard-interactive",
    GSSAPIWithMIC = "gssapi-with-mic",
    GSSAPIKeyExchange = "gssapi-keyex",
    HostboundPublicKey = "publickey-hostbound-v00@openssh.com",
}

// https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
export const MAXIMUM_CHANNEL_WINDOW_SIZE = 2 ** 32 - 1

export enum SSHExtendedDataTypes {
    SSH_EXTENDED_DATA_STDERR = 1,
}
