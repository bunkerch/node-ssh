#!/usr/bin/env python3

import argparse
import asyncio
import base64
import json
import logging
import os
import sys

import asyncssh

if os.environ.get("MODERNSSH_PEER_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_debug_level(2)


USERNAME = "interop"
PASSWORD = "correct-horse-battery-staple"


class ServerPolicy(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USERNAME and password == PASSWORD


async def handle_process(process: asyncssh.SSHServerProcess[str]) -> None:
    contents = await process.stdin.read()
    process.stdout.write(f"{process.command}\0{contents}")
    process.stderr.write("independent-peer-stderr")
    process.exit(23)


async def serve(key_exchange: str) -> None:
    host_key = asyncssh.generate_private_key("ssh-ed448")
    listener = await asyncssh.create_server(
        ServerPolicy,
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        kex_algs=[key_exchange],
        encryption_algs=["aes128-ctr"],
        mac_algs=["hmac-sha2-256"],
        process_factory=handle_process,
    )
    print(json.dumps({"port": listener.get_port()}), flush=True)
    await listener.wait_closed()


async def connect(port: int, key_exchange: str) -> None:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="mode", required=True)
    server = subcommands.add_parser("server")
    server.add_argument("key_exchange")
    client = subcommands.add_parser("client")
    client.add_argument("port", type=int)
    client.add_argument("key_exchange")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    if args.mode == "server":
        await serve(args.key_exchange)
    else:
        await connect(args.port, args.key_exchange)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except (OSError, asyncssh.Error) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
