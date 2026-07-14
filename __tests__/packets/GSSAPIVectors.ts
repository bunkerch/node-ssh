import GSSAPIWithMICAuthMethod from "../../src/auth/gssapi-with-mic.js"
import GSSAPIKeyExchangeAuthMethod from "../../src/auth/gssapi-keyex.js"
import {
    buildGSSAPIKeyExchangeUserAuthMIC,
    buildGSSAPIUserAuthMIC,
    KERBEROS_V5_GSSAPI_OID,
    normalizeGSSAPIClientMechanisms,
    normalizeGSSAPIOID,
    type GSSAPIClientMechanism,
} from "../../src/GSSAPI.js"
import Packet from "../../src/packet.js"
import {
    UserAuthGSSAPIError,
    UserAuthGSSAPIErrorToken,
    UserAuthGSSAPIExchangeComplete,
    UserAuthGSSAPIMIC,
    UserAuthGSSAPIResponse,
    UserAuthGSSAPIToken,
} from "../../src/packets/UserAuthGSSAPI.js"
import UserAuthRequest from "../../src/packets/UserAuthRequest.js"

const kerberosOID = "06092a864886f712010202"
const spnegoOID = "06062b0601050502"

describe("RFC 4462 GSS-API authentication vectors", () => {
    test("parses and serializes a fixed mechanism negotiation request", () => {
        const frame = Buffer.from(
            "32" +
                "00000005616c696365" +
                "0000000e7373682d636f6e6e656374696f6e" +
                "0000000f6773736170692d776974682d6d6963" +
                "00000002" +
                `0000000b${kerberosOID}` +
                `00000008${spnegoOID}`,
            "hex",
        )
        const request = UserAuthRequest.parse(frame)

        expect(request.data.method).toBeInstanceOf(GSSAPIWithMICAuthMethod)
        expect(
            (request.data.method as GSSAPIWithMICAuthMethod).data.mechanismOIDs.map((oid) =>
                oid.toString("hex"),
            ),
        ).toEqual([kerberosOID, spnegoOID])
        expect(request.serialize()).toEqual(frame)
    })

    test("parses and serializes every context-exchange message", () => {
        const vectors: readonly [Buffer, { parse(raw: Buffer): Packet }][] = [
            [Buffer.from(`3c0000000b${kerberosOID}`, "hex"), UserAuthGSSAPIResponse],
            [Buffer.from("3d00000003aabbcc", "hex"), UserAuthGSSAPIToken],
            [Buffer.from("3f", "hex"), UserAuthGSSAPIExchangeComplete],
            [
                Buffer.from("400000000100000002000000046f6f707300000005656e2d5553", "hex"),
                UserAuthGSSAPIError,
            ],
            [Buffer.from("4100000002dead", "hex"), UserAuthGSSAPIErrorToken],
            [Buffer.from("4200000003010203", "hex"), UserAuthGSSAPIMIC],
        ]

        for (const [frame, packet] of vectors) {
            expect(packet.parse(frame).serialize()).toEqual(frame)
        }
        for (const [frame] of vectors.slice(2)) {
            expect(Packet.parse(frame).serialize()).toEqual(frame)
        }
    })

    test("builds the exact session-bound MIC input", () => {
        const expected = Buffer.from(
            "0000000401020304" +
                "32" +
                "00000005616c696365" +
                "0000000e7373682d636f6e6e656374696f6e" +
                "0000000f6773736170692d776974682d6d6963",
            "hex",
        )
        expect(
            buildGSSAPIUserAuthMIC(Buffer.from("01020304", "hex"), "alice", "ssh-connection"),
        ).toEqual(expected)
    })

    test("matches the gssapi-keyex request and session-bound MIC input", () => {
        const micInput = Buffer.from(
            "0000000401020304" +
                "32" +
                "00000005616c696365" +
                "0000000e7373682d636f6e6e656374696f6e" +
                "0000000c6773736170692d6b65796578",
            "hex",
        )
        expect(
            buildGSSAPIKeyExchangeUserAuthMIC(
                Buffer.from("01020304", "hex"),
                "alice",
                "ssh-connection",
            ),
        ).toEqual(micInput)

        const frame = Buffer.from(
            "32" +
                "00000005616c696365" +
                "0000000e7373682d636f6e6e656374696f6e" +
                "0000000c6773736170692d6b65796578" +
                "00000004deadbeef",
            "hex",
        )
        const request = UserAuthRequest.parse(frame)
        expect(request.data.method).toBeInstanceOf(GSSAPIKeyExchangeAuthMethod)
        expect((request.data.method as GSSAPIKeyExchangeAuthMethod).mic).toEqual(
            Buffer.from("deadbeef", "hex"),
        )
        expect(request.serialize()).toEqual(frame)
    })

    test("requires canonical DER OIDs, complete framing, and owned token bytes", () => {
        expect(KERBEROS_V5_GSSAPI_OID.toString("hex")).toBe(kerberosOID)
        expect(() => normalizeGSSAPIOID(Buffer.from("0500", "hex"))).toThrow("object identifier")
        expect(() => normalizeGSSAPIOID(Buffer.from("0681092a864886f712010202", "hex"))).toThrow(
            "Non-canonical",
        )
        expect(() => normalizeGSSAPIOID(Buffer.from("06028081", "hex"))).toThrow("Non-canonical")
        expect(() => UserAuthGSSAPIToken.parse(Buffer.from("3d000000010001", "hex"))).toThrow(
            "Unexpected",
        )

        const source = Buffer.from("aabb", "hex")
        const token = new UserAuthGSSAPIToken(source)
        source.fill(0)
        expect(token.token).toEqual(Buffer.from("aabb", "hex"))
    })

    test("normalizes class-based mechanism adapters without losing their receiver", async () => {
        class Mechanism implements GSSAPIClientMechanism {
            readonly oid = KERBEROS_V5_GSSAPI_OID
            readonly identity = "class-adapter"

            createContext() {
                expect(this.identity).toBe("class-adapter")
                return {
                    step: () => ({ complete: true, integrity: true }),
                    getMIC: () => Buffer.from([1]),
                }
            }

            createKeyExchangeContext() {
                expect(this.identity).toBe("class-adapter")
                return {
                    step: () => ({
                        complete: true,
                        integrity: true,
                        mutualAuthentication: true,
                    }),
                    verifyMIC: () => true,
                }
            }
        }
        const mechanism = new Mechanism()
        const [normalized] = normalizeGSSAPIClientMechanisms([mechanism])
        const context = await normalized.createContext({
            hostname: "example.test",
            username: "alice",
            service: "ssh-connection",
            delegateCredentials: false,
        })

        expect(context.step).toBeFunction()
        expect(normalized.createKeyExchangeContext).toBeFunction()
        await normalized.createKeyExchangeContext!({
            hostname: "example.test",
            service: "host",
            delegateCredentials: false,
            anonymous: true,
            mutualAuthentication: true,
            integrity: true,
            replayDetection: false,
            sequenceDetection: false,
        })
    })
})
