import "modernlog/patch.js"
import Client from "./Client.js"
import DiskAgent from "./publickey/DiskAgent.js"

const client = new Client({
    hostname: "VPS1",
    port: 22,
    username: "debian",
    agent: new DiskAgent(),
})
client.on("debug", (...args) => console.debug(...args))
client.on("error", console.error)
client.on("close", () => {
    console.log("Connection closed")
})

await client.connect()
console.log("Connected with ssh!")
