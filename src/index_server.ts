import "modernlog/patch.js"
import Server from "./Server.js"

const server = new Server()
server.on("debug", console.debug)

server.listen(1023, () => {
    server.debug("Server listening on port", 1023)
})

server.on("connection", (client) => {
    client.on("error", console.error)
})
