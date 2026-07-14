import assert from "node:assert"
import { createHash } from "node:crypto"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import Agent, { AgentType } from "../../src/publickey/Agent.js"
import Server from "../../src/Server.js"
import { serializeUint32 } from "../../src/utils/Buffer.js"
import PrivateKey, { SSHECDSAPrivateKey } from "../../src/utils/PrivateKey.js"
import PublicKey, { ECDSA_CURVES } from "../../src/utils/PublicKey.js"
import EncodedSignature, { SSH_ECDSA_SECURITY_KEY_ALGORITHM } from "../../src/utils/Signature.js"

const application = "ssh:test"
const publicPoint = Buffer.from(
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    "hex",
)
const privateScalar = Buffer.from(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "hex",
)
const publicKeyBlob = Buffer.from(
    "00000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d" +
        "000000086e69737470323536" +
        "00000041" +
        publicPoint.toString("hex") +
        "000000087373683a74657374",
    "hex",
)

class SecurityKeyAgent extends Agent<string> {
    type = AgentType.NonInteractive
    private readonly publicKey = PublicKey.parse(publicKeyBlob)
    private readonly signer = new SSHECDSAPrivateKey(ECDSA_CURVES[0], {
        publicKey: publicPoint,
        privateKey: privateScalar,
    })

    async sign(id: string, data: Buffer, algorithm?: string): Promise<EncodedSignature> {
        assert(id === "security-key")
        assert(algorithm === SSH_ECDSA_SECURITY_KEY_ALGORITHM)
        const flags = 1
        const counter = 7
        const signedData = Buffer.concat([
            createHash("sha256").update(application).digest(),
            Buffer.from([flags]),
            serializeUint32(counter),
            createHash("sha256").update(data).digest(),
        ])
        const signature = this.signer.sign(signedData)
        return new EncodedSignature({
            alg: SSH_ECDSA_SECURITY_KEY_ALGORITHM,
            data: signature.data.data,
            securityKey: { flags, counter },
        })
    }

    async getPublicKeys(): Promise<[string, PublicKey][]> {
        return [["security-key", this.publicKey]]
    }

    async getPublicKey(id: string): Promise<PublicKey> {
        assert(id === "security-key")
        return this.publicKey
    }
}

describe("security-key authentication", () => {
    test("authenticates through an agent and awaited server policy", async () => {
        const hostKey = await PrivateKey.generate("ssh-ed25519")
        const agent = new SecurityKeyAgent()
        const expectedKey = await agent.getPublicKey("security-key")
        const server = new Server({ hostKeys: [hostKey], sendAllHostKeys: false })
        const contexts: unknown[] = []
        const errors: Error[] = []
        server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
            await Promise.resolve()
            contexts.push(context)
            decision.allowLogin =
                context.username === "security-key-user" &&
                context.publicKey.equals(expectedKey) &&
                context.signature !== undefined &&
                context.publicKey.verifySignature(context.signatureMessage, context.signature)
        })
        server.on("connection", (connection) => {
            connection.on("error", (error) => errors.push(error))
        })
        server.listen({ host: "127.0.0.1", port: 0 })
        await once(server.server, "listening")

        const client = new Client({
            hostname: "127.0.0.1",
            port: (server.address() as AddressInfo).port,
            username: "security-key-user",
            agent,
            authenticationMethodsOrder: [SSHAuthenticationMethods.PublicKey],
        })
        client.on("error", (error) => errors.push(error))
        client.hooker.hook("hostKey", (_hook, decision) => {
            decision.allowHostKey = true
        })

        try {
            await client.connect()
            expect(client.isConnected).toBeTrue()
            expect(client.serverSignatureAlgorithms).toContain(SSH_ECDSA_SECURITY_KEY_ALGORITHM)
            expect(contexts).toHaveLength(1)
            expect(errors).toEqual([])
        } finally {
            client.destroy()
            for (const connection of server.clients) connection.terminate()
            await server.close()
        }
    }, 15_000)
})
