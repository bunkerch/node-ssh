import "modernlog/patch.js"
import Client from "./Client.js"
import DiskAgent from "./publickey/DiskAgent.js"

const client = new Client({
    hostname: "127.0.0.1",
    port: 1022,
    username: "debian",
    password: "debian",
    agent: new DiskAgent(),
})
client.on("debug", (...args) => console.debug(...args))
client.on("error", console.error)
client.on("close", () => {
    console.log("Connection closed")
})

await client.connect()
console.log("Connected with ssh!")
