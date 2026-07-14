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

    test("service packets snapshot caller metadata", () => {
        const requestInput = { service_name: "ssh-userauth" }
        const requestPacket = new ServiceRequest(requestInput)
        requestInput.service_name = "changed@example.com"
        expect(requestPacket.serialize()).toEqual(request)

        const acceptanceInput = { service_name: "ssh-userauth" }
        const acceptancePacket = new ServiceAccept(acceptanceInput)
        acceptanceInput.service_name = "changed@example.com"
        expect(acceptancePacket.serialize()).toEqual(acceptance)
    })
})
