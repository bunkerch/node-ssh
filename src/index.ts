import "modernlog/patch.js"
import Client from "./Client.js"
import DiskAgent from "./publickey/DiskAgent.js"

const client = new Client({
    hostname: "kiji",
    port: 22,
    username: "ubuntu",
    agent: new DiskAgent(),
})
client.on("error", console.error)
client.on("close", () => {
    console.log("Connection closed")
})
client.on("debug", console.debug)

await client.connect()
console.log("Connected with ssh!")
