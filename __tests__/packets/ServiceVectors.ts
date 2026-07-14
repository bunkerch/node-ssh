import ServiceAccept from "../../src/packets/ServiceAccept.js"
import ServiceRequest from "../../src/packets/ServiceRequest.js"

const request = Buffer.from("050000000c7373682d7573657261757468", "hex")
const acceptance = Buffer.from("060000000c7373682d7573657261757468", "hex")

describe("RFC 4253 service negotiation vectors", () => {
    test("parses and serializes an independently written service request", () => {
        const packet = ServiceRequest.parse(request)
        expect(packet.data.service_name).toBe("ssh-userauth")
        expect(packet.serialize()).toEqual(request)
    })

    test("parses and serializes an independently written service acceptance", () => {
        const packet = ServiceAccept.parse(acceptance)
        expect(packet.data.service_name).toBe("ssh-userauth")
        expect(packet.serialize()).toEqual(acceptance)
    })
})
