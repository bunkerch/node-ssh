#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import struct
import sys
from hashlib import sha256, sha384
from typing import Callable, Mapping

import asyncssh
from asyncssh.compression import get_compressor, get_decompressor
from asyncssh.constants import MSG_EXT_INFO
from asyncssh.encryption import GCMEncryption, register_encryption_alg
from asyncssh.kex import register_kex_alg
from asyncssh.kex_dh import _KexDHBase
from asyncssh.mac import MAC, register_mac_alg
from asyncssh.misc import ProtocolError
from asyncssh.packet import Boolean, MPInt, NameList, SSHPacket, String
from kyber_py.ml_kem import ML_KEM_1024, ML_KEM_512, ML_KEM_768

if os.environ.get("MODERNSSH_PEER_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_debug_level(2)


USERNAME = "interop"
PASSWORD = "correct-horse-battery-staple"
PUBLIC_KEY_SUBSYSTEM_VERSION = 3
MSG_NEWCOMPRESS = 8
DELAY_COMPRESSION_VALUE = NameList((b"zlib", b"none")) * 2
PUBLIC_KEY = bytes.fromhex(
    "0000000b7373682d6564323535313900000020"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)


class RegisteredAEADMAC(MAC):
    """Negotiation placeholder for RFC 5647's paired MAC registry names."""

    def sign(self, _seq: int, _packet: bytes) -> bytes:
        raise RuntimeError("RFC 5647 authenticates through its encryption algorithm")

    def verify(self, _seq: int, _packet: bytes, _signature: bytes) -> bool:
        raise RuntimeError("RFC 5647 authenticates through its encryption algorithm")


for algorithm, cipher in (
    (b"AEAD_AES_128_GCM", "aes128-gcm"),
    (b"AEAD_AES_256_GCM", "aes256-gcm"),
):
    register_encryption_alg(algorithm, GCMEncryption, cipher, False)
    register_mac_alg(algorithm, 0, 16, True, RegisteredAEADMAC, (), False)


class StandaloneMLKEMKeyExchange(_KexDHBase):
    """FIPS 203 key exchange framing from the standalone SSH ML-KEM draft."""

    _init_type = 30
    _reply_type = 31

    def __init__(
        self,
        alg: bytes,
        conn: asyncssh.SSHConnection,
        hash_alg: Callable,
        kem: object,
        public_key_bytes: int,
        ciphertext_bytes: int,
    ):
        super().__init__(alg, conn, hash_alg)
        self._kem = kem
        self._public_key_bytes = public_key_bytes
        self._ciphertext_bytes = ciphertext_bytes
        self._client_public_key = b""
        self._server_ciphertext = b""
        self._secret_key = b""
        self._shared_secret = b""

        if conn.is_client():
            self._client_public_key, self._secret_key = self._kem.keygen()

    def _parse_client_key(self, packet: SSHPacket) -> None:
        self._client_public_key = packet.get_string()

    def _parse_server_key(self, packet: SSHPacket) -> None:
        self._server_ciphertext = packet.get_string()

    def _format_client_key(self) -> bytes:
        return String(self._client_public_key)

    def _format_server_key(self) -> bytes:
        return String(self._server_ciphertext)

    def _compute_hash(self, host_key_data: bytes, _key: bytes) -> bytes:
        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(self._format_client_key())
        hash_obj.update(self._format_server_key())
        hash_obj.update(String(self._shared_secret))
        return hash_obj.digest()

    def _compute_client_shared(self) -> bytes:
        if len(self._server_ciphertext) != self._ciphertext_bytes:
            raise ProtocolError("Invalid ML-KEM server ciphertext length")

        try:
            self._shared_secret = self._kem.decaps(
                self._secret_key,
                self._server_ciphertext,
            )
        except ValueError:
            raise ProtocolError("Invalid ML-KEM server ciphertext") from None

        return MPInt(int.from_bytes(self._shared_secret, "big"))

    def _compute_server_shared(self) -> bytes:
        if len(self._client_public_key) != self._public_key_bytes:
            raise ProtocolError("Invalid ML-KEM client public key length")

        try:
            self._shared_secret, self._server_ciphertext = self._kem.encaps(
                self._client_public_key
            )
        except ValueError:
            raise ProtocolError("Invalid ML-KEM client public key") from None

        return MPInt(int.from_bytes(self._shared_secret, "big"))

    async def start(self) -> None:
        if self._conn.is_client():
            self._send_init()

    _packet_handlers: Mapping[int, Callable] = {
        30: _KexDHBase._process_init,
        31: _KexDHBase._process_reply,
    }


for algorithm, hash_alg, kem, public_key_bytes, ciphertext_bytes in (
    (b"mlkem512-sha256", sha256, ML_KEM_512, 800, 768),
    (b"mlkem768-sha256", sha256, ML_KEM_768, 1184, 1088),
    (b"mlkem1024-sha384", sha384, ML_KEM_1024, 1568, 1568),
):
    register_kex_alg(
        algorithm,
        StandaloneMLKEMKeyExchange,
        hash_alg,
        (kem, public_key_bytes, ciphertext_bytes),
        False,
    )


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def public_key_packet(name: str, payload: bytes = b"") -> bytes:
    body = ssh_string(name.encode("ascii")) + payload
    return struct.pack(">I", len(body)) + body


class PacketReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def uint32(self) -> int:
        if self.offset + 4 > len(self.data):
            raise ValueError("truncated uint32")
        value = struct.unpack_from(">I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def boolean(self) -> bool:
        if self.offset >= len(self.data):
            raise ValueError("truncated boolean")
        value = self.data[self.offset] != 0
        self.offset += 1
        return value

    def string(self) -> bytes:
        length = self.uint32()
        if self.offset + length > len(self.data):
            raise ValueError("truncated string")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ValueError("trailing packet data")


async def read_public_key_packet(reader: asyncssh.SSHReader[bytes]) -> tuple[str, PacketReader]:
    length = struct.unpack(">I", await reader.readexactly(4))[0]
    if length > 256 * 1024:
        raise ValueError("oversized public-key subsystem packet")
    packet = PacketReader(await reader.readexactly(length))
    name = packet.string().decode("ascii")
    return name, packet


async def write_fragmented(writer: asyncssh.SSHWriter[bytes], data: bytes) -> None:
    split = min(7, len(data))
    writer.write(data[:split])
    await writer.drain()
    await asyncio.sleep(0)
    writer.write(data[split:])
    await writer.drain()


def version_packet() -> bytes:
    return public_key_packet("version", struct.pack(">I", PUBLIC_KEY_SUBSYSTEM_VERSION))


def status_packet(code: int = 0, description: str = "") -> bytes:
    return public_key_packet(
        "status",
        struct.pack(">I", code)
        + ssh_string(description.encode("utf-8"))
        + ssh_string(b""),
    )


def attribute_packet(name: str, compulsory: bool) -> bytes:
    return public_key_packet(
        "attribute",
        ssh_string(name.encode("ascii")) + bytes([int(compulsory)]),
    )


def request_attributes(attributes: list[tuple[bytes, bytes, bool]]) -> bytes:
    return struct.pack(">I", len(attributes)) + b"".join(
        ssh_string(name) + ssh_string(value) + bytes([int(critical)])
        for name, value, critical in attributes
    )


def listed_attributes(attributes: list[tuple[bytes, bytes]]) -> bytes:
    return struct.pack(">I", len(attributes)) + b"".join(
        ssh_string(name) + ssh_string(value) for name, value in attributes
    )


def listed_key_packet(
    key: bytes, attributes: list[tuple[bytes, bytes]]
) -> bytes:
    return public_key_packet(
        "publickey",
        ssh_string(b"ssh-ed25519")
        + ssh_string(key)
        + listed_attributes(attributes),
    )


def listed_certificate_packet(
    certificate: bytes, namespace: bytes
) -> bytes:
    return public_key_packet(
        "certificate",
        ssh_string(b"X509")
        + ssh_string(certificate)
        + listed_attributes([(b"namespace", namespace)]),
    )


async def expect_status(reader: asyncssh.SSHReader[bytes]) -> None:
    name, packet = await read_public_key_packet(reader)
    if name != "status" or packet.uint32() != 0:
        raise ValueError("public-key subsystem request failed")
    packet.string().decode("utf-8")
    packet.string().decode("ascii")
    packet.finish()


async def exchange_version(
    reader: asyncssh.SSHReader[bytes],
    writer: asyncssh.SSHWriter[bytes],
) -> None:
    await write_fragmented(writer, version_packet())
    name, packet = await read_public_key_packet(reader)
    if name != "version" or packet.uint32() < PUBLIC_KEY_SUBSYSTEM_VERSION:
        raise ValueError("unexpected public-key subsystem version")
    packet.finish()


class ServerPolicy(asyncssh.SSHServer):
    connection: asyncssh.SSHServerConnection
    client_delay_compression = False
    client_elevation: bytes | None = None

    def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
        self.connection = connection
        connection._extensions_to_send[b"no-flow-control"] = b"s"
        connection._extensions_to_send[b"delay-compression"] = DELAY_COMPRESSION_VALUE
        handlers = dict(connection._packet_handlers)
        process_ext_info = handlers[MSG_EXT_INFO]

        def capture_ext_info(
            target: asyncssh.SSHServerConnection,
            packet_type: int,
            packet_id: int,
            packet: SSHPacket,
        ) -> None:
            extensions = SSHPacket(packet.get_remaining_payload())
            extension_count = extensions.get_uint32()
            for _ in range(extension_count):
                name = extensions.get_string()
                value = extensions.get_string()
                if name == b"delay-compression":
                    self.client_delay_compression = value == DELAY_COMPRESSION_VALUE
                elif name == b"elevation":
                    self.client_elevation = value
            extensions.check_end()
            process_ext_info(target, packet_type, packet_id, packet)

        handlers[MSG_EXT_INFO] = capture_ext_info

        def process_newcompress(
            target: asyncssh.SSHServerConnection,
            _packet_type: int,
            _packet_id: int,
            packet: SSHPacket,
        ) -> None:
            packet.check_end()
            if not self.client_delay_compression:
                raise ProtocolError("Unexpected SSH_MSG_NEWCOMPRESS")
            target._decompressor = get_decompressor(b"zlib")
            target._decompress_after_auth = False

        handlers[MSG_NEWCOMPRESS] = process_newcompress
        connection._packet_handlers = handlers

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USERNAME and password == PASSWORD

    def auth_completed(self) -> None:
        if self.client_delay_compression:
            self.connection._compressor = get_compressor(b"zlib")
            self.connection._compress_after_auth = False
        if self.client_elevation == b"n":
            self.connection._send_global_request(
                b"elevation",
                Boolean(False),
                want_reply=False,
            )


class ClientPolicy(asyncssh.SSHClient):
    connection: asyncssh.SSHClientConnection
    elevated: bool | None = None
    server_delay_compression = False

    def connection_made(self, connection: asyncssh.SSHClientConnection) -> None:
        self.connection = connection
        connection._extensions_to_send[b"no-flow-control"] = b"p"
        connection._extensions_to_send[b"elevation"] = b"n"
        connection._extensions_to_send[b"delay-compression"] = DELAY_COMPRESSION_VALUE

        handlers = dict(connection._packet_handlers)
        process_ext_info = handlers[MSG_EXT_INFO]

        def capture_ext_info(
            target: asyncssh.SSHClientConnection,
            packet_type: int,
            packet_id: int,
            packet: SSHPacket,
        ) -> None:
            extensions = SSHPacket(packet.get_remaining_payload())
            extension_count = extensions.get_uint32()
            for _ in range(extension_count):
                name = extensions.get_string()
                value = extensions.get_string()
                if name == b"delay-compression":
                    self.server_delay_compression = value == DELAY_COMPRESSION_VALUE
            extensions.check_end()
            process_ext_info(target, packet_type, packet_id, packet)

        handlers[MSG_EXT_INFO] = capture_ext_info
        connection._packet_handlers = handlers

        def process_elevation(packet: SSHPacket) -> None:
            self.elevated = packet.get_boolean()
            packet.check_end()
            connection._report_global_response(True)

        connection._process_elevation_global_request = process_elevation

    def auth_completed(self) -> None:
        if self.server_delay_compression:
            self.connection._decompressor = get_decompressor(b"zlib")
            self.connection._decompress_after_auth = False
            self.connection.send_packet(MSG_NEWCOMPRESS)
            self.connection._compressor = get_compressor(b"zlib")
            self.connection._compress_after_auth = False


async def handle_command_process(process: asyncssh.SSHServerProcess[bytes]) -> None:
    contents = await process.stdin.read()
    process.stdout.write((process.command or "").encode() + b"\0" + contents)
    process.stderr.write(b"independent-peer-stderr")
    process.exit(23)


async def handle_public_key_process(process: asyncssh.SSHServerProcess[bytes]) -> None:
    await exchange_version(process.stdin, process.stdout)
    stored_key: bytes | None = None
    stored_comment = b""
    stored_certificate: bytes | None = None

    while True:
        name, packet = await read_public_key_packet(process.stdin)
        if name == "listattributes":
            packet.finish()
            process.stdout.write(
                attribute_packet("comment", False)
                + attribute_packet("shell", True)
                + attribute_packet("namespace", False)
                + status_packet()
            )
        elif name == "add":
            algorithm = packet.string()
            key = packet.string()
            overwrite = packet.boolean()
            count = packet.uint32()
            attributes: list[tuple[bytes, bytes, bool]] = []
            for _ in range(count):
                attributes.append((packet.string(), packet.string(), packet.boolean()))
            packet.finish()
            if algorithm != b"ssh-ed25519" or key != PUBLIC_KEY or not overwrite:
                raise ValueError("unexpected public-key subsystem add request")
            if attributes != [
                (b"namespace", b"ssh", True),
                (b"comment", b"library-client", False),
            ]:
                raise ValueError("unexpected public-key subsystem attributes")
            stored_key = key
            stored_comment = attributes[1][1]
            process.stdout.write(status_packet())
        elif name == "list":
            attributes = [
                (packet.string(), packet.string(), packet.boolean())
                for _ in range(packet.uint32())
            ]
            packet.finish()
            if attributes != [(b"namespace", b"ssh", True)]:
                raise ValueError("unexpected public-key subsystem list namespace")
            response = b""
            if stored_key is not None:
                response += listed_key_packet(
                    stored_key,
                    [(b"namespace", b"ssh"), (b"comment", stored_comment)],
                )
            process.stdout.write(response + status_packet())
        elif name == "remove":
            algorithm = packet.string()
            key = packet.string()
            attributes = [
                (packet.string(), packet.string(), packet.boolean())
                for _ in range(packet.uint32())
            ]
            packet.finish()
            if (
                algorithm != b"ssh-ed25519"
                or key != stored_key
                or attributes != [(b"namespace", b"ssh", True)]
            ):
                raise ValueError("unexpected public-key subsystem remove request")
            stored_key = None
            process.stdout.write(status_packet())
        elif name == "add-certificate":
            certificate_format = packet.string()
            certificate = packet.string()
            overwrite = packet.boolean()
            attributes = [
                (packet.string(), packet.string(), packet.boolean())
                for _ in range(packet.uint32())
            ]
            packet.finish()
            if (
                certificate_format != b"X509"
                or certificate != b"\x01\x02\x03"
                or overwrite
                or attributes != [(b"namespace", b"ssh", True)]
            ):
                raise ValueError("unexpected public-key subsystem certificate add")
            stored_certificate = certificate
            process.stdout.write(status_packet())
        elif name == "list-certificates":
            packet.finish()
            response = (
                b""
                if stored_certificate is None
                else listed_certificate_packet(stored_certificate, b"ssh")
            )
            process.stdout.write(response + status_packet())
        elif name == "remove-certificate":
            certificate_format = packet.string()
            certificate = packet.string()
            attributes = [
                (packet.string(), packet.string()) for _ in range(packet.uint32())
            ]
            packet.finish()
            if (
                certificate_format != b"X509"
                or certificate != stored_certificate
                or attributes != [(b"namespace", b"ssh")]
            ):
                raise ValueError("unexpected public-key subsystem certificate remove")
            stored_certificate = None
            process.stdout.write(status_packet())
        elif name == "list-namespaces":
            packet.finish()
            process.stdout.write(
                public_key_packet("namespace", ssh_string(b"ssh"))
                + public_key_packet("namespace", ssh_string(b"ssl"))
                + status_packet()
            )
        else:
            packet.finish()
            process.stdout.write(status_packet(8, "unsupported request"))
        await process.stdout.drain()


async def handle_process(process: asyncssh.SSHServerProcess[bytes]) -> None:
    if process.subsystem == "publickey":
        await handle_public_key_process(process)
    else:
        await handle_command_process(process)


async def serve(
    key_exchange: str, cipher: str = "aes128-ctr", mac: str = "hmac-sha2-256"
) -> None:
    host_key = asyncssh.generate_private_key("ssh-ed448")
    listener = await asyncssh.create_server(
        ServerPolicy,
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        kex_algs=[key_exchange],
        encryption_algs=[cipher],
        mac_algs=[mac],
        encoding=None,
        process_factory=handle_process,
    )
    print(json.dumps({"port": listener.get_port()}), flush=True)
    await listener.wait_closed()


async def connect_command(
    port: int,
    key_exchange: str,
    cipher: str = "aes128-ctr",
    mac: str = "hmac-sha2-256",
) -> None:
    policy = ClientPolicy()
    async with asyncssh.connect(
        "127.0.0.1",
        port,
        client_factory=lambda: policy,
        username=USERNAME,
        password=PASSWORD,
        known_hosts=None,
        kex_algs=[key_exchange],
        server_host_key_algs=["ssh-ed448"],
        encryption_algs=[cipher],
        mac_algs=[mac],
    ) as connection:
        result = await connection.run("independent-client-command", input="client-input")
        print(
            json.dumps(
                {
                    "elevated": policy.elevated,
                    "exitStatus": result.exit_status,
                    "stdout": base64.b64encode(result.stdout.encode()).decode(),
                    "stderr": base64.b64encode(result.stderr.encode()).decode(),
                }
            )
        )


async def connect_public_key(port: int, key_exchange: str) -> None:
    async with asyncssh.connect(
        "127.0.0.1",
        port,
        username=USERNAME,
        password=PASSWORD,
        known_hosts=None,
        kex_algs=[key_exchange],
        server_host_key_algs=["ssh-ed448"],
        encryption_algs=["aes128-ctr"],
        mac_algs=["hmac-sha2-256"],
    ) as connection:
        writer, reader, _stderr = await connection.open_session(
            subsystem="publickey",
            encoding=None,
        )
        await exchange_version(reader, writer)

        writer.write(public_key_packet("listattributes"))
        capabilities: list[tuple[str, bool]] = []
        while True:
            name, packet = await read_public_key_packet(reader)
            if name == "status":
                if packet.uint32() != 0:
                    raise ValueError("public-key subsystem capability request failed")
                packet.string()
                packet.string()
                packet.finish()
                break
            if name != "attribute":
                raise ValueError("unexpected public-key subsystem capability response")
            capabilities.append((packet.string().decode("ascii"), packet.boolean()))
            packet.finish()

        add = (
            ssh_string(b"ssh-ed25519")
            + ssh_string(PUBLIC_KEY)
            + b"\x01"
            + request_attributes(
                [
                    (b"namespace", b"ssh", True),
                    (b"comment", b"independent-client", False),
                ]
            )
        )
        writer.write(public_key_packet("add", add))
        await expect_status(reader)

        namespace_filter = request_attributes([(b"namespace", b"ssh", True)])
        writer.write(public_key_packet("list", namespace_filter))
        name, packet = await read_public_key_packet(reader)
        if name != "publickey":
            raise ValueError("unexpected public-key subsystem list response")
        algorithm = packet.string().decode("ascii")
        listed_key = packet.string()
        count = packet.uint32()
        attributes = [(packet.string(), packet.string()) for _ in range(count)]
        packet.finish()
        await expect_status(reader)
        if (
            algorithm != "ssh-ed25519"
            or listed_key != PUBLIC_KEY
            or attributes
            != [(b"namespace", b"ssh"), (b"comment", b"independent-client")]
        ):
            raise ValueError("unexpected listed public key")

        writer.write(
            public_key_packet(
                "remove",
                ssh_string(b"ssh-ed25519")
                + ssh_string(PUBLIC_KEY)
                + namespace_filter,
            )
        )
        await expect_status(reader)
        writer.write(public_key_packet("list", namespace_filter))
        await expect_status(reader)

        certificate = b"\x01\x02\x03"
        writer.write(
            public_key_packet(
                "add-certificate",
                ssh_string(b"X509")
                + ssh_string(certificate)
                + b"\x00"
                + request_attributes([(b"namespace", b"ssh", True)]),
            )
        )
        await expect_status(reader)
        writer.write(public_key_packet("list-certificates"))
        name, packet = await read_public_key_packet(reader)
        if name != "certificate":
            raise ValueError("unexpected public-key subsystem certificate response")
        certificate_format = packet.string()
        listed_certificate = packet.string()
        certificate_attributes = [
            (packet.string(), packet.string()) for _ in range(packet.uint32())
        ]
        packet.finish()
        await expect_status(reader)
        if (
            certificate_format != b"X509"
            or listed_certificate != certificate
            or certificate_attributes != [(b"namespace", b"ssh")]
        ):
            raise ValueError("unexpected listed certificate")
        writer.write(
            public_key_packet(
                "remove-certificate",
                ssh_string(b"X509")
                + ssh_string(certificate)
                + listed_attributes([(b"namespace", b"ssh")]),
            )
        )
        await expect_status(reader)

        writer.write(public_key_packet("list-namespaces"))
        namespaces: list[str] = []
        while True:
            name, packet = await read_public_key_packet(reader)
            if name == "status":
                if packet.uint32() != 0:
                    raise ValueError("public-key subsystem namespace request failed")
                packet.string()
                packet.string()
                packet.finish()
                break
            if name != "namespace":
                raise ValueError("unexpected public-key subsystem namespace response")
            namespaces.append(packet.string().decode("utf-8"))
            packet.finish()
        writer.close()
        await writer.wait_closed()

        print(
            json.dumps(
                {
                    "algorithm": algorithm,
                    "capabilities": capabilities,
                    "comment": attributes[1][1].decode("utf-8"),
                    "certificate": listed_certificate.hex(),
                    "namespaces": namespaces,
                    "removed": True,
                }
            )
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="mode", required=True)
    server = subcommands.add_parser("server")
    server.add_argument("key_exchange")
    server.add_argument("cipher", nargs="?", default="aes128-ctr")
    server.add_argument("mac", nargs="?", default="hmac-sha2-256")
    client = subcommands.add_parser("client")
    client.add_argument("port", type=int)
    client.add_argument("key_exchange")
    client.add_argument("cipher", nargs="?", default="aes128-ctr")
    client.add_argument("mac", nargs="?", default="hmac-sha2-256")
    public_key_client = subcommands.add_parser("publickey-client")
    public_key_client.add_argument("port", type=int)
    public_key_client.add_argument("key_exchange")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    if args.mode == "server":
        await serve(args.key_exchange, args.cipher, args.mac)
    elif args.mode == "publickey-client":
        await connect_public_key(args.port, args.key_exchange)
    else:
        await connect_command(args.port, args.key_exchange, args.cipher, args.mac)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except (OSError, asyncssh.Error) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
