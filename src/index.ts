import "modernlog/patch.js"
import Client from "./Client.js";

const client = new Client({
    hostname: "VPS1",
    port: 22,
    username: "debian"
})
client.hooker.hook("hostKey", (controller, result) => {
    // example. you could have a more complex logic here
    result.allowHostKey = true
})
client.on("debug", (...args) => console.debug(...args))
client.on("error", console.error)
client.on("close", () => {
    console.log("Connection closed")
})
await client.connect()