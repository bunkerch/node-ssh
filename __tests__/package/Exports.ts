import { execFile } from "node:child_process"
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import {
    Agent,
    Channel,
    Client,
    ClientAgentChannel,
    ClientDirectStreamLocalChannel,
    ClientForwardedStreamLocalChannel,
    ClientForwardedTCPIPChannel,
    ClientTCPIPChannel,
    ClientX11Channel,
    DirectTCPIPChannel,
    DirectStreamLocalChannel,
    decodeSFTPLimits,
    DiskAgent,
    EncodedSignature,
    encodeSFTPPacket,
    flagsToString,
    ForwardedTCPIPChannel,
    ForwardedAgentChannel,
    ForwardedStreamLocalChannel,
    ForwardedX11Channel,
    generateKeyPair,
    generateKeyPairSync,
    GSSAPIError,
    HTTPAgent,
    HTTPSAgent,
    KERBEROS_V5_GSSAPI_OID,
    OnePasswordAgent,
    OPEN_MODE,
    parseKey,
    parseKeys,
    PrivateKey,
    PrivateKeyAgent,
    ProtocolVersionExchange,
    PublicKey,
    PublicKeyAlgorithm,
    Server,
    ServerClient,
    SessionChannel,
    Shell,
    SFTPPacketParser,
    SFTPPacketType,
    SFTPClient,
    SFTPReadStream,
    SFTPServer,
    SFTPStats,
    SFTPWriteStream,
    STATUS_CODE,
    stringToFlags,
    SSHAgent,
    SSHHTTPAgent,
    SSHHTTPSAgent,
    SSHAuthenticationMethods,
    TerminalMode,
    TerminalModes,
    type ClientOptions,
    type ClientSessionOptions,
    type ServerOptions,
} from "../../src/index.js"

const execFileAsync = promisify(execFile)

describe("package exports", () => {
    test("exposes the supported source API without executing a demo", () => {
        const clientOptions: ClientOptions = { hostname: "example.test" }
        const sessionOptions: ClientSessionOptions = { env: { LANG: "C" }, pty: true }
        const serverOptions: ServerOptions = { sendAllHostKeys: false }

        expect(clientOptions.hostname).toBe("example.test")
        expect(sessionOptions.pty).toBe(true)
        expect(serverOptions.sendAllHostKeys).toBe(false)
        expect([
            Agent,
            Channel,
            Client,
            ClientAgentChannel,
            ClientDirectStreamLocalChannel,
            ClientForwardedStreamLocalChannel,
            ClientForwardedTCPIPChannel,
            ClientTCPIPChannel,
            ClientX11Channel,
            DirectTCPIPChannel,
            DirectStreamLocalChannel,
            DiskAgent,
            EncodedSignature,
            ForwardedTCPIPChannel,
            ForwardedAgentChannel,
            ForwardedStreamLocalChannel,
            ForwardedX11Channel,
            generateKeyPair,
            generateKeyPairSync,
            GSSAPIError,
            HTTPAgent,
            HTTPSAgent,
            KERBEROS_V5_GSSAPI_OID,
            OnePasswordAgent,
            parseKey,
            parseKeys,
            PrivateKey,
            PrivateKeyAgent,
            ProtocolVersionExchange,
            PublicKey,
            PublicKeyAlgorithm,
            Server,
            ServerClient,
            SessionChannel,
            Shell,
            SSHAgent,
            SSHHTTPAgent,
            SSHHTTPSAgent,
        ]).toHaveLength(38)
        expect(SSHAuthenticationMethods.PublicKey).toBe("publickey")
        expect(SSHAuthenticationMethods.KeyboardInteractive).toBe("keyboard-interactive")
        expect(SSHAuthenticationMethods.GSSAPIWithMIC).toBe("gssapi-with-mic")
        expect(KERBEROS_V5_GSSAPI_OID.toString("hex")).toBe("06092a864886f712010202")
        expect(TerminalMode.ECHO).toBe(53)
        expect(TerminalModes).toBe(TerminalMode)
        expect(encodeSFTPPacket).toBeFunction()
        expect(decodeSFTPLimits).toBeFunction()
        expect(SFTPPacketParser).toBeFunction()
        expect(SFTPPacketType.Init).toBe(1)
        expect(SFTPClient).toBeFunction()
        expect(SFTPReadStream).toBeFunction()
        expect(SFTPServer).toBeFunction()
        expect(SFTPStats).toBeFunction()
        expect(SFTPWriteStream).toBeFunction()
        expect(stringToFlags("r")).toBe(OPEN_MODE.READ)
        expect(flagsToString(OPEN_MODE.READ)).toBe("r")
        expect(STATUS_CODE.OK).toBe(0)
    })

    test("compiled entry point provides the same side-effect-free API", async () => {
        const entry = await import("../../dist/index.js")

        expect(entry.Client).toBeDefined()
        expect(entry.ClientAgentChannel).toBeDefined()
        expect(entry.ClientDirectStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ClientForwardedTCPIPChannel).toBeDefined()
        expect(entry.ClientTCPIPChannel).toBeDefined()
        expect(entry.ClientX11Channel).toBeDefined()
        expect(entry.SSHHTTPAgent).toBeDefined()
        expect(entry.SSHHTTPSAgent).toBeDefined()
        expect(entry.HTTPAgent).toBe(entry.SSHHTTPAgent)
        expect(entry.HTTPSAgent).toBe(entry.SSHHTTPSAgent)
        expect(entry.generateKeyPair).toBeFunction()
        expect(entry.generateKeyPairSync).toBeFunction()
        expect(entry.GSSAPIError).toBeFunction()
        expect(entry.KERBEROS_V5_GSSAPI_OID).toBeInstanceOf(Buffer)
        expect(entry.parseKeys).toBeFunction()
        expect(entry.DirectTCPIPChannel).toBeDefined()
        expect(entry.DirectStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedTCPIPChannel).toBeDefined()
        expect(entry.ForwardedAgentChannel).toBeDefined()
        expect(entry.ForwardedStreamLocalChannel).toBeDefined()
        expect(entry.ForwardedX11Channel).toBeDefined()
        expect(entry.Server).toBeDefined()
        expect(entry.PrivateKey).toBeDefined()
        expect(entry.ProtocolVersionExchange).toBeDefined()
        expect(entry.SSHAgent).toBeDefined()
        expect(entry.OnePasswordAgent).toBeDefined()
        expect(entry.SFTPPacketParser).toBeDefined()
        expect(entry.SFTPPacketType.Status).toBe(101)
        expect(entry.SFTPClient).toBeDefined()
        expect(entry.SFTPReadStream).toBeDefined()
        expect(entry.SFTPServer).toBeDefined()
        expect(entry.SFTPStats).toBeDefined()
        expect(entry.SFTPWriteStream).toBeDefined()
        expect(entry.OPEN_MODE.READ).toBe(1)
        expect(entry.STATUS_CODE.OK).toBe(0)
        expect(entry.decodeSFTPLimits).toBeDefined()
        expect(entry.TerminalMode.TTY_OP_OSPEED).toBe(129)
        expect(entry.TerminalModes).toBe(entry.TerminalMode)
    })

    test("compiled declarations expose Promise-only completion APIs", async () => {
        const client = await readFile("dist/Client.d.ts", "utf8")
        const clientChannel = await readFile("dist/channels/ClientChannel.d.ts", "utf8")
        const clientSession = await readFile("dist/channels/ClientSessionChannel.d.ts", "utf8")
        const channel = await readFile("dist/Channel.d.ts", "utf8")
        const serverClient = await readFile("dist/ServerClient.d.ts", "utf8")
        const server = await readFile("dist/Server.d.ts", "utf8")
        const streams = await readFile("dist/sftp/streams.d.ts", "utf8")
        const shell = await readFile("dist/channels/Session/Shell.d.ts", "utf8")
        const privateKey = await readFile("dist/utils/PrivateKey.d.ts", "utf8")

        expect(client).not.toContain("ClientSessionCallback")
        expect(client).not.toContain("ClientGlobalRequestCallback")
        expect(client).toContain("globalRequest(name: string, args?: Buffer): Promise<Buffer>")
        expect(client).toContain("exec(command: string, options?: ClientSessionOptions)")
        expect(clientChannel).toContain("sendData(data: Buffer | string")
        expect(clientSession).toContain("forwardAgent(): Promise<void>")
        expect(channel).toContain("sendData(data: Buffer): Promise<void>")
        expect(channel).toContain("sendExtendedData(dataType: number, data: Buffer): Promise<void>")
        expect(serverClient).not.toContain("ServerGlobalRequestCallback")
        expect(serverClient).toContain("rekey(): Promise<void>")
        expect(serverClient).toContain("forwardAgent(): Promise<ForwardedAgentChannel>")
        expect(server).toContain("getConnections(): Promise<number>")
        expect(server).toContain("close(): Promise<void>")
        expect(streams.match(/close\(\): Promise<void>/gu)).toHaveLength(2)
        expect(shell).toContain("writeStdout(data: Buffer | string")
        expect(shell).toContain("writeStderr(data: Buffer | string")
        expect(privateKey).toContain(
            "fromPuTTY(data: string | Buffer, passphrase?: string | Buffer): PrivateKey",
        )
    })

    test("package archive exposes working ESM key generation", async () => {
        const directory = await mkdtemp(join(tmpdir(), "modernssh-package-"))
        try {
            await execFileAsync("pnpm", ["pack", "--pack-destination", directory])
            const archive = (await readdir(directory)).find((name) => name.endsWith(".tgz"))
            expect(archive).toBeDefined()
            const consumer = join(directory, "consumer")
            await mkdir(consumer)
            await execFileAsync("pnpm", ["add", "--dir", consumer, join(directory, archive!)])
            const { stdout, stderr } = await execFileAsync(
                "node",
                [
                    "--input-type=module",
                    "--eval",
                    `
                    const { Client, generateKeyPair, generateKeyPairSync, parseKey, PrivateKey, PrivateKeyAgent } = await import("modernssh")
                    const { privateKey, publicKey } = await generateKeyPair("ed25519", {
                        comment: "packed@example.test",
                    })
                    const message = Buffer.from("packed-key-generation")
                    if (!publicKey.verifySignature(message, privateKey.sign(message))) process.exit(2)
                    const encrypted = privateKey.toString({ passphrase: "packed-secret", rounds: 1 })
                    const parsed = PrivateKey.fromString(encrypted, "packed-secret")
                    if (!parsed.data.publicKey.equals(publicKey)) process.exit(3)
                    if (!parseKey(publicKey.toString()).equals(publicKey)) process.exit(4)
                    const configured = new Client({ privateKey: encrypted, passphrase: "packed-secret" })
                    if (!(configured.options.agent instanceof PrivateKeyAgent)) process.exit(5)
                    const legacy = generateKeyPairSync("dsa")
                    const legacySignature = legacy.privateKey.sign(message)
                    if (!legacy.publicKey.verifySignature(message, legacySignature)) process.exit(6)
                    if (new Client({}).algorithmOffer.serverHostKey.includes("ssh-dss")) process.exit(7)
                    const explicitLegacy = new Client({ algorithms: { serverHostKey: ["ssh-dss"] } })
                    if (explicitLegacy.algorithmOffer.serverHostKey[0] !== "ssh-dss") process.exit(8)
                    const synchronous = generateKeyPairSync("ecdsa", { bits: 256 })
                    if (!synchronous.publicKey.verifySignature(message, synchronous.privateKey.sign(message))) process.exit(9)
                    const rfc4716 = "---- BEGIN SSH" + "2 PUBLIC KEY ----\\n" + publicKey.serialize().toString("base64") + "\\n---- END SSH" + "2 PUBLIC KEY ----\\n"
                    if (!parseKey(rfc4716).equals(publicKey)) process.exit(10)
                    const ppk = Buffer.from("UHVUVFktVXNlci1LZXktRmlsZS0zOiBzc2gtZWQyNTUxOQpFbmNyeXB0aW9uOiBub25lCkNvbW1lbnQ6IFJGQyA4MDMyIHRlc3QgdmVjdG9yIDEKUHVibGljLUxpbmVzOiAyCkFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlOZGFtQUdDc1FxMzFVdiswOGxrQnpvTzRYTHoycVlqSmE4Q0dtajMKQjFFYQpQcml2YXRlLUxpbmVzOiAxCkFBQUFJSjFoc1ozdi9WcGd1b1JLOUpMc0xNUkVTY1ZwZXpKcEdYQTdyQU1jcm45ZwpQcml2YXRlLU1BQzogOWUxNzE1ZjEwNzM2ZWY1NTdiMDI0OWJkNjAxOWVjYTgyOTBhNjQ4ZDk3YjFmZjc1MmVlNmJlMDhkMDNiNzcxOQo=", "base64")
                    const importedPPK = parseKey(ppk)
                    if (!(importedPPK instanceof PrivateKey)) process.exit(11)
                    if (importedPPK.data.comment !== "RFC 8032 test vector 1") process.exit(12)
                    if (!importedPPK.data.publicKey.verifySignature(Buffer.alloc(0), importedPPK.sign(Buffer.alloc(0)))) process.exit(13)
                    const curve448Client = new Client({ algorithms: { kex: ["curve448-sha512"] } })
                    if (curve448Client.algorithmOffer.kex[0] !== "curve448-sha512") process.exit(14)
                    process.stdout.write(publicKey.toString())
                `,
                ],
                { cwd: consumer },
            )
            expect(stdout).toStartWith("ssh-ed25519 ")
            expect(stdout).toEndWith(" packed@example.test")
            expect(stderr).toBe("")
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    }, 30_000)
})
