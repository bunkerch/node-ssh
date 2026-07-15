import assert from "node:assert"
import type Client from "../Client.js"
import { clientConfigurationFor } from "../ConnectionConfiguration.js"
import { SSHAuthenticationMethods, SSHServiceNames } from "../constants.js"
import UserAuthFailure from "../packets/UserAuthFailure.js"
import UserAuthRequest from "../packets/UserAuthRequest.js"
import UserAuthSuccess from "../packets/UserAuthSuccess.js"
import { readNextBuffer, serializeBuffer } from "../utils/Buffer.js"
import PublicKey from "../utils/PublicKey.js"
import EncodedSignature from "../utils/Signature.js"
import AuthMethod from "./AuthMethod.js"
import { decodeSSHUTF8, encodeSSHUTF8 } from "../utils/SSHText.js"
import { decodeSSHName, encodeSSHName } from "../utils/SSHName.js"

export interface HostbasedAuthMethodData {
    publicKey: PublicKey
    algorithm: string
    clientHostname: string
    clientUsername: string
    signature: EncodedSignature
}

export default class HostbasedAuthMethod implements AuthMethod {
    static method_name = SSHAuthenticationMethods.Hostbased
    readonly data: HostbasedAuthMethodData

    get method_name(): SSHAuthenticationMethods {
        return HostbasedAuthMethod.method_name
    }

    constructor(data: HostbasedAuthMethodData) {
        encodeSSHName(data.algorithm, "SSH hostbased signature algorithm")
        assert(
            data.publicKey.supportsSignatureAlgorithm(data.algorithm),
            `Signature algorithm ${data.algorithm} is incompatible with ${data.publicKey.data.alg}`,
        )
        validateClientHostname(data.clientHostname)
        validateClientUsername(data.clientUsername)
        assert(
            data.signature.data.alg === data.publicKey.signatureAlgorithmFor(data.algorithm),
            "Hostbased signature algorithm mismatch",
        )
        this.data = { ...data }
    }

    serialize(): Buffer {
        return Buffer.concat([
            this.serializeForSignature(),
            serializeBuffer(this.data.signature.serialize()),
        ])
    }

    serializeForSignature(): Buffer {
        return Buffer.concat([
            serializeBuffer(Buffer.from(HostbasedAuthMethod.method_name, "ascii")),
            serializeBuffer(
                encodeSSHName(this.data.algorithm, "SSH hostbased signature algorithm"),
            ),
            serializeBuffer(this.data.publicKey.serialize()),
            serializeBuffer(Buffer.from(this.data.clientHostname, "ascii")),
            serializeBuffer(encodeSSHUTF8(this.data.clientUsername, "SSH hostbased client user")),
        ])
    }

    static parse(raw: Buffer): HostbasedAuthMethod {
        let algorithm: Buffer
        let publicKeyBlob: Buffer
        let clientHostname: Buffer
        let clientUsername: Buffer
        let signature: Buffer
        ;[algorithm, raw] = readNextBuffer(raw)
        ;[publicKeyBlob, raw] = readNextBuffer(raw)
        ;[clientHostname, raw] = readNextBuffer(raw)
        ;[clientUsername, raw] = readNextBuffer(raw)
        ;[signature, raw] = readNextBuffer(raw)
        assert(raw.length === 0)

        const algorithmName = decodeSSHName(algorithm, "SSH hostbased signature algorithm")
        const publicKey = PublicKey.parse(publicKeyBlob)
        const encodedSignature = EncodedSignature.parse(signature)
        return new HostbasedAuthMethod({
            publicKey,
            algorithm: algorithmName,
            clientHostname: clientHostname.toString("ascii"),
            clientUsername: decodeSSHUTF8(clientUsername, "SSH hostbased client user"),
            signature: encodedSignature,
        })
    }

    static async handleAuthentication(client: Client): Promise<boolean> {
        const options = clientConfigurationFor(client).hostbased
        if (!options) return false

        const publicKey = options.key.data.publicKey
        const algorithm = options.algorithm ?? publicKey.signatureAlgorithms[0]
        assert(
            publicKey.supportsSignatureAlgorithm(algorithm),
            `Signature algorithm ${algorithm} is incompatible with ${publicKey.data.alg}`,
        )
        const placeholder = new EncodedSignature({
            alg: publicKey.signatureAlgorithmFor(algorithm),
            data: Buffer.alloc(0),
        })
        const method = new HostbasedAuthMethod({
            publicKey,
            algorithm,
            clientHostname: options.localHostname,
            clientUsername: options.localUsername,
            signature: placeholder,
        })
        const request = new UserAuthRequest({
            username: clientConfigurationFor(client).username,
            service_name: SSHServiceNames.Connection,
            method,
        })
        method.data.signature = options.key.sign(request.serializeForSignature(client), algorithm)
        client.sendPacket(request)

        const answer = await AuthMethod.waitForAnswer(client)
        if (answer instanceof UserAuthSuccess) return true
        if (answer instanceof UserAuthFailure) return false
        return false
    }
}

function validateClientHostname(hostname: string): void {
    assert(hostname.length > 0 && Buffer.byteLength(hostname, "ascii") <= 255)
    assert(Buffer.from(hostname, "ascii").toString("ascii") === hostname)
    const labels = (hostname.endsWith(".") ? hostname.slice(0, -1) : hostname).split(".")
    assert(
        labels.every(
            (label) =>
                label.length > 0 &&
                label.length <= 63 &&
                /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label),
        ),
        "Hostbased client hostname must be a valid ASCII FQDN",
    )
}

function validateClientUsername(username: string): void {
    assert(username.length > 0 && !username.includes("\0"), "Hostbased client username is invalid")
    assert(Buffer.from(username, "utf8").toString("utf8") === username)
}
