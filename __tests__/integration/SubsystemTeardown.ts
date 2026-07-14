import { expect, test } from "bun:test"
import { once } from "node:events"
import type { AddressInfo } from "node:net"
import Client from "../../src/Client.js"
import Server from "../../src/Server.js"
import type ServerClient from "../../src/ServerClient.js"
import SessionChannel from "../../src/channels/SessionChannel.js"
import type PublicKeySubsystemServer from "../../src/publickey/PublicKeySubsystemServer.js"
import type SFTPServer from "../../src/sftp/SFTPServer.js"
import { SFTPPacketType } from "../../src/sftp/constants.js"
import { SSHAuthenticationMethods } from "../../src/constants.js"
import PrivateKey from "../../src/utils/PrivateKey.js"

function within<T>(promise: Promise<T>, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), 250)
        timer.unref()
        promise.then(
            (value) => {
                clearTimeout(timer)
                resolve(value)
            },
            (error: unknown) => {
                clearTimeout(timer)
                reject(error as Error)
            },
        )
    })
}

test("truncated SFTP input closes the subsystem channel", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
            })
            channel.events.on("sftp", (sftp) => {
                sftp.on("error", () => undefined)
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "subsystem-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        const clientClosed = once(sftp.channel, "close")

        await sftp.channel.sendData(Buffer.from([0, 0, 0, 5, SFTPPacketType.Stat]))
        sftp.channel.eof()
        await within(clientClosed, "SFTP channel close")

        expect(sftp.channel.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("truncated public-key input closes the subsystem channel", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    let peer: ServerClient | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "publickey") return
                controller.success = true
            })
            channel.events.on("publicKey", (publicKeys) => {
                publicKeys.on("error", () => undefined)
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "subsystem-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const publicKeys = await client.publicKeySubsystem()
        const clientClosed = once(publicKeys.channel, "close")

        await publicKeys.channel.sendData(Buffer.from([0, 0, 0, 5, 0]))
        publicKeys.channel.eof()
        await within(clientClosed, "public-key subsystem channel close")

        expect(publicKeys.channel.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("truncated SFTP output closes the client channel", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    let peer: ServerClient | undefined
    let serverSFTP: SFTPServer | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "sftp") return
                controller.success = true
            })
            channel.events.on("sftp", (sftp) => {
                serverSFTP = sftp
                sftp.on("error", () => undefined)
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "subsystem-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const sftp = await client.sftp()
        const channelError = once(sftp.channel, "error")

        await serverSFTP!.stream.writeStdout(Buffer.from([0, 0, 0, 5, SFTPPacketType.Status]))
        serverSFTP!.stream.eof()
        await within(channelError, "SFTP client channel error")

        expect(sftp.channel.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})

test("truncated public-key output closes the client channel", async () => {
    const server = new Server({
        hostKeys: [await PrivateKey.generate("ssh-ed25519")],
        sendAllHostKeys: false,
    })
    server.hooker.hook("noneAuthentication", (_hook, _context, controller) => {
        controller.allowLogin = true
    })
    server.hooker.hook("channelOpenRequest", (_hook, channel, controller) => {
        controller.allowOpen = channel instanceof SessionChannel
    })

    let peer: ServerClient | undefined
    let serverPublicKeys: PublicKeySubsystemServer | undefined
    server.on("connection", (connection) => {
        peer = connection
        connection.on("channel", (channel) => {
            if (!(channel instanceof SessionChannel)) return
            channel.hooker.hook("subsystemRequest", (_hook, context, controller) => {
                if (context.subsystem !== "publickey") return
                controller.success = true
            })
            channel.events.on("publicKey", (publicKeys) => {
                serverPublicKeys = publicKeys
                publicKeys.on("error", () => undefined)
            })
        })
    })
    server.listen({ host: "127.0.0.1", port: 0 })
    await once(server, "listening")

    const client = new Client({
        hostname: "127.0.0.1",
        port: (server.address() as AddressInfo).port,
        username: "subsystem-teardown-test",
        authenticationMethodsOrder: [SSHAuthenticationMethods.None],
    })
    client.hooker.hook("hostKey", (_hook, controller) => {
        controller.allowHostKey = true
    })

    try {
        await client.connect()
        const publicKeys = await client.publicKeySubsystem()
        const channelError = once(publicKeys.channel, "error")

        await serverPublicKeys!.stream.writeStdout(Buffer.from([0, 0, 0, 5, 0]))
        serverPublicKeys!.stream.eof()
        await within(channelError, "public-key client channel error")

        expect(publicKeys.channel.destroyed).toBe(true)
        expect(client.isConnected).toBe(true)
    } finally {
        client.destroy()
        peer?.terminate()
        await server.close()
    }
})
