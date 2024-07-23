import "modernlog/patch.js"
import Server from "./Server.js"
import PublicKey from "./utils/PublicKey.js"

const server = new Server()
server.on("debug", console.debug)

server.listen(1023, () => {
    server.debug("Server listening on port", 1023)
})

server.on("connection", (client) => {
    client.on("error", console.error)
})

const allowedUser = "manaf"
const allowedPublicKeys = PublicKey.parseAuthorizedKeysFile(`
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICcSFk1WeyZZyOV/W5oFXldpVvLssFZNZVyURUsSz6tU thomiz@vitc.org
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJS6a664HMOKoLXZU0NTI/v9psSjaYye6GUsab62uvg3 manafralli@gmail.com
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
