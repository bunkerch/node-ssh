import { AuthMethod } from "../packets/UserAuthRequest.js";
import { serializeBuffer } from "../utils/Buffer.js";

export default class NoneAuthMethod implements AuthMethod {
    static method_name = "none"

    serialize(): Buffer {
        return serializeBuffer(
            Buffer.from(NoneAuthMethod.method_name, "utf-8")
        )
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    static parse(raw: Buffer): AuthMethod {
        return new NoneAuthMethod()
    }
}