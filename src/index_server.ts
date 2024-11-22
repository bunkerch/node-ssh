import "modernlog/patch.js"
import Server from "./Server.js"
import PublicKey from "./utils/PublicKey.js"
import PrivateKey from "./utils/PrivateKey.js"
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import SessionChannel from "./channels/SessionChannel.js"
import ChannelData from "./packets/ChannelData.js"

const server = new Server({
    hostKeys: [
        PrivateKey.fromString(readFileSync(homedir() + "/.ssh/id_ed25519", "utf8")),
        // big day for annoying people
        await PrivateKey.generate("ssh-ed25519"),
    ],
})

server.listen(3022, () => {
    server.debug("Server listening on port", 3022)
})

server.on("connection", (client) => {
    client.on("error", console.error)

    client.on("connect", () => {
        console.log(
            `User ${client.credentials!.username} logged in with ${client.credentials!.method_name}`,
        )
    })

    client.on("channel", (channel) => {
        if (!(channel instanceof SessionChannel)) return

        channel.hooker.hook("envRequest", (_, context, controller) => {
            if (!["LANG"].includes(context.key)) return

            controller.success = true
        })

        channel.hooker.hook("shellRequest", (_, controller) => {
            controller.success = true
        })

        channel.events.on("shell", (shell) => {
            process.stdin.resume()
            process.stdin.setRawMode(true)
            process.stdin.setEncoding("utf8")
            process.stdin.pipe(shell.stdout)

            client.sendPacket(
                new ChannelData({
                    recipient_channel_id: channel.remoteId!,
                    data: Buffer.from("Hello World !\n\nEnvironment Variables:\n", "utf8"),
                }),
            )

            for (const [key, value] of channel.env.entries()) {
                client.sendPacket(
                    new ChannelData({
                        recipient_channel_id: channel.remoteId!,
                        data: Buffer.from(`${key}=${value}\n`, "utf8"),
                    }),
                )
            }

            // channel.close()
        })
    })
})

const allowedUser = "manaf"
const allowedPublicKeys = PublicKey.parseAuthorizedKeysFile(`
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICcSFk1WeyZZyOV/W5oFXldpVvLssFZNZVyURUsSz6tU thomiz@vitc.org
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJS6a664HMOKoLXZU0NTI/v9psSjaYye6GUsab62uvg3 manafralli@gmail.com
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1QB7MrCW2ZmvlGgADPkm61EBkds4AI8kpXo7vvNDTl manaf@2221.ch
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKNMME9pqRzPV2Gn6LB3erVXpvkzi1OtYLGkjTRSupQg9sN+17iTQIx3dCEudWRWLXBOtlL1lg1UH9TbnnCYjY+ns7KlFa8ibLeAy9D8NPTZ/4yMapDhZM8ThQseqKMbr9D9XfSryCpj9bPNCg2+OY2FPhArVyOBRcT9byHXPJYPES82pH8EepCDnr/D7NSM1TsrIzXc0d8JLZJxr+f6OMdrf8646cLmM0iJuEelyt+2sBxrJZRsu0Y0pHMwVoN+2U1xOjshxLCAZrIJGK7LOLCDR/AFljNzQlTFkQOSFDghBkz/R4CDtsoT6D0/GA8ZMDb7hgrCgu93C7ZFDfzOZKDzN4l80nuxdUbcEdtMVc36Aj2IzMoFxWauGGmnOBu1zujnSvU2azK/f1RT1UNKqMfwq8hn5T7OC9CGX6cTKGOnHwIzv1igMDi2Wghgarj79jH4xdcF//wAkyaipPZSW9LAX4CRauLW3hKZ/Afeq15Bm6H39zLH4cdtonX0rDPvk= manaf@cooper.home
`)

server.hooker.hook("publicKeyAuthentication", (_, context, controller) => {
    // only allow user "manaf"
    if (context.username != allowedUser) return

    const publicKey = allowedPublicKeys.find((key) => key.equals(context.publicKey))
    // public key is not in the keys file
    if (!publicKey) return

    // when using password managers or keychains,
    // the server needs to explicitely tell the
    // client to sign the auth request.
    if (!context.signature) {
        controller.requestSignature = true
        return
    }

    // If the signature is not valid, do not allow login.
    if (!context.publicKey.verifySignature(context.signatureMessage, context.signature)) return

    controller.allowLogin = true
})

server.hooker.hook("channelOpenRequest", (_, channel, controller) => {
    if (!(channel instanceof SessionChannel)) return

    controller.allowOpen = true
})
