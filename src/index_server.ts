import "modernlog/patch.js"
import Server from "./Server.js"
import PublicKey from "./utils/PublicKey.js"

const server = new Server()
//server.on("debug", console.debug)

server.listen(1023, () => {
    server.debug("Server listening on port", 1023)
})

server.on("connection", (client) => {
    client.on("error", console.error)
})

const allowedUser = "manaf"
const allowedPublicKeys = [
    PublicKey.parseString(
        `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICcSFk1WeyZZyOV/W5oFXldpVvLssFZNZVyURUsSz6tU thomiz@vitc.org`,
    ),
    PublicKey.parseString(
        `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJS6a664HMOKoLXZU0NTI/v9psSjaYye6GUsab62uvg3 manafralli@gmail.com`,
    ),
]

server.hooker.hook("publicKeyAuthentication", async (_, context, controller) => {
    if (context.username != allowedUser) {
        // deny request
        return
    }

    for (const publicKey of allowedPublicKeys) {
        if (publicKey.equals(context.publicKey)) {
            // this is a valid public key

            if (!context.signature) {
                controller.requestSignature = true
                return
            }

            if (context.publicKey.verifySignature(context.signatureMessage, context.signature)) {
                controller.allowLogin = true
            }

            return
        }
    }

    // if none match, deny request
})
