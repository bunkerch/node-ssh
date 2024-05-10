import "modernlog/patch.js"
import Client from "./Client.js"

const client = new Client({
    hostname: "127.0.0.1",
    port: 1022,
    username: "debian",
})
client.on("debug", (...args) => console.debug(...args))
client.on("error", console.error)
client.on("close", () => {
    console.log("Connection closed")
})
await client.connect()
