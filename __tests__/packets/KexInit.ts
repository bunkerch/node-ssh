// TODO: Jest does not allow ESM imports ? figure it out
import { SSHPacketType } from "../../src/constants";
import KexInit from "../../src/packets/KexInit";

test("Packet Type should be SSH_MSG_KEXINIT", () => {
    expect(KexInit.type).toBe(SSHPacketType.SSH_MSG_KEXINIT)
})

const sample = Buffer.from(
    "141356fc33611b65c6301d0c2fae1acdcd00000102637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d73686131000000417273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d00000000000000000000000000",
    "hex"
)
test("Should parse", () => {
    const packet = KexInit.parse(sample)

    expect(packet.data.cookie.toString("hex")).toBe("1356fc33611b65c6301d0c2fae1acdcd")

    expect(packet.data.kex_algorithms).toEqual([
        "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1"
    ])
    expect(packet.data.server_host_key_algorithms).toEqual([
        "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ecdsa-sha2-nistp256",
        "ssh-ed25519"
    ])
    expect(packet.data.encryption_algorithms_client_to_server).toEqual([
        "chacha20-poly1305@openssh.com", "aes128-ctr",
        "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"
    ])
    expect(packet.data.encryption_algorithms_server_to_client).toEqual([
        "chacha20-poly1305@openssh.com", "aes128-ctr",
        "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"
    ])
    expect(packet.data.mac_algorithms_client_to_server).toEqual([
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"
    ])
    expect(packet.data.mac_algorithms_server_to_client).toEqual([
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"
    ])
    expect(packet.data.compression_algorithms_client_to_server).toEqual([
        "none", "zlib@openssh.com"
    ])
    expect(packet.data.compression_algorithms_server_to_client).toEqual([
        "none", "zlib@openssh.com"
    ])
})

test("Should serialize correctly", () => {
    const packet = KexInit.parse(sample)
    const serialized = packet.serialize()
    expect(serialized).toEqual(sample)
})