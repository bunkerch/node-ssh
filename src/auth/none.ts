import { AuthMethod } from "../packets/UserAuthRequest.js";

export default class NoneAuthMethod implements AuthMethod {
    static method_name = "none"

    serialize(): Buffer {
        return Buffer.from(NoneAuthMethod.method_name, "utf-8")
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        return new NoneAuthMethod()
    }
}