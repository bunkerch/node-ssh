#!/usr/bin/env python3

import argparse
import asyncio
import base64
import json
import logging
import os
import struct
import sys

import asyncssh
from asyncssh.encryption import GCMEncryption, register_encryption_alg
from asyncssh.mac import MAC, register_mac_alg

if os.environ.get("MODERNSSH_PEER_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_debug_level(2)


USERNAME = "interop"
PASSWORD = "correct-horse-battery-staple"
PUBLIC_KEY_SUBSYSTEM_VERSION = 2
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


def listed_key_packet(key: bytes, comment: bytes) -> bytes:
    return public_key_packet(
        "publickey",
        ssh_string(b"ssh-ed25519")
        + ssh_string(key)
        + struct.pack(">I", 1)
        + ssh_string(b"comment")
        + ssh_string(comment),
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
    if name != "version" or packet.uint32() != PUBLIC_KEY_SUBSYSTEM_VERSION:
        raise ValueError("unexpected public-key subsystem version")
    packet.finish()


class ServerPolicy(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USERNAME and password == PASSWORD


async def handle_command_process(process: asyncssh.SSHServerProcess[bytes]) -> None:
    contents = await process.stdin.read()
    process.stdout.write((process.command or "").encode() + b"\0" + contents)
    process.stderr.write(b"independent-peer-stderr")
    process.exit(23)


async def handle_public_key_process(process: asyncssh.SSHServerProcess[bytes]) -> None:
    await exchange_version(process.stdin, process.stdout)
    stored_key: bytes | None = None
    stored_comment = b""

    while True:
        name, packet = await read_public_key_packet(process.stdin)
        if name == "listattributes":
            packet.finish()
            process.stdout.write(
                attribute_packet("comment", False)
                + attribute_packet("shell", True)
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
            if attributes != [(b"comment", b"library-client", False)]:
                raise ValueError("unexpected public-key subsystem attributes")
            stored_key = key
            stored_comment = attributes[0][1]
            process.stdout.write(status_packet())
        elif name == "list":
            packet.finish()
            response = b""
            if stored_key is not None:
                response += listed_key_packet(stored_key, stored_comment)
            process.stdout.write(response + status_packet())
        elif name == "remove":
            algorithm = packet.string()
            key = packet.string()
            packet.finish()
            if algorithm != b"ssh-ed25519" or key != stored_key:
                raise ValueError("unexpected public-key subsystem remove request")
            stored_key = None
            process.stdout.write(status_packet())
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
    async with asyncssh.connect(
        "127.0.0.1",
        port,
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
            + struct.pack(">I", 1)
            + ssh_string(b"comment")
            + ssh_string(b"independent-client")
            + b"\x00"
        )
        writer.write(public_key_packet("add", add))
        await expect_status(reader)

        writer.write(public_key_packet("list"))
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
            or attributes != [(b"comment", b"independent-client")]
        ):
            raise ValueError("unexpected listed public key")

        writer.write(
            public_key_packet(
                "remove",
                ssh_string(b"ssh-ed25519") + ssh_string(PUBLIC_KEY),
            )
        )
        await expect_status(reader)
        writer.write(public_key_packet("list"))
        await expect_status(reader)
        writer.close()
        await writer.wait_closed()

        print(
            json.dumps(
                {
                    "algorithm": algorithm,
                    "capabilities": capabilities,
                    "comment": attributes[0][1].decode("utf-8"),
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
