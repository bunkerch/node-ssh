import type Client from "../Client.js"
import { SSHAuthenticationMethods } from "../constants.js"

export default abstract class AuthMethod {
    static method_name: string
    abstract method_name: string

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    constructor(data: unknown) {
        throw new Error("Not implemented")
    }

    abstract serialize(): Buffer

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        throw new Error("Not implemented")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static async handleAuthentication(client: Client): Promise<boolean> {
        throw new Error("Not implemented")
    }

    static async waitForAnswer(client: Client, seqno?: number) {
        return client.waitForPackets(
            {
                SSH_MSG_UNIMPLEMENTED: {
                    predicate: (packet) =>
                        seqno === undefined || packet.data.sequence_number === seqno,
                },
                SSH_MSG_USERAUTH_FAILURE: {
                    predicate: () => true,
                },
                SSH_MSG_USERAUTH_SUCCESS: {
                    predicate: () => true,
                },
                SSH_MSG_USERAUTH_PK_OK: {
                    predicate: () => true,
                },
            },
            10_000,
        )
    }
}

export interface AuthMethodClass {
    method_name: SSHAuthenticationMethods
    parse(raw: Buffer): AuthMethod
    handleAuthentication(client: Client): Promise<boolean>
}
