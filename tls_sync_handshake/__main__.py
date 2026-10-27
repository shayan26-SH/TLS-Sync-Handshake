from __future__ import annotations

import argparse
import sys
import threading

from .client import TLSClient
from .server import TLSServer
from .session_cache import SessionCache
from .webapp import create_web_server


def _client_command(args: argparse.Namespace) -> int:
    client = TLSClient(args.cafile)
    result = client.request(args.host, args.port, args.message.encode("utf-8"))
    print(f"response: {result.response.decode('utf-8')}")
    print(f"protocol: {result.protocol}; cipher: {result.cipher}")
    print(f"resumed: {result.resumed}; session ticket cached: {result.ticket_cached}")
    return 0


def _server_command(args: argparse.Namespace) -> int:
    server = TLSServer(args.cert, args.key, args.host, args.port)
    address = server.start()
    print(f"TLS 1.3 server listening on {address[0]}:{address[1]}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.close()
    return 0


def _demo_command(args: argparse.Namespace) -> int:
    server = TLSServer(args.cert, args.key, host="127.0.0.1", port=0)
    host, port = server.start()
    try:
        client = TLSClient(args.cafile, cache=SessionCache())
        for number in (1, 2):
            result = client.request(host, port, f"hello {number}".encode("utf-8"))
            print(
                f"demo {number}: response={result.response.decode('utf-8')!r}, "
                f"resumed={result.resumed}, ticket_cached={result.ticket_cached}"
            )
        return 0
    finally:
        server.close()


def _web_command(args: argparse.Namespace) -> int:
    server = create_web_server(args.cert, args.key, args.cafile, args.host, args.port)
    address = server.server_address
    print(f"TLS handshake demo available at http://{address[0]}:{address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo app")
    finally:
        server.server_close()
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-sync-handshake",
        description="TLS 1.3 session lifecycle and resumption demonstration",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("server", help="run a TLS 1.3 echo server")
    server.add_argument("--cert", required=True, help="server certificate PEM file")
    server.add_argument("--key", required=True, help="server private key PEM file")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8443)
    server.set_defaults(handler=_server_command)

    client = commands.add_parser("client", help="send one message to a TLS server")
    client.add_argument("--cafile", required=True, help="trusted CA/certificate PEM file")
    client.add_argument("--host", default="127.0.0.1")
    client.add_argument("--port", type=int, default=8443)
    client.add_argument("--message", default="hello TLS 1.3")
    client.set_defaults(handler=_client_command)

    demo = commands.add_parser("demo", help="connect twice and attempt TLS resumption")
    demo.add_argument("--cert", required=True, help="server certificate PEM file")
    demo.add_argument("--key", required=True, help="server private key PEM file")
    demo.add_argument("--cafile", required=True, help="trusted CA/certificate PEM file")
    demo.set_defaults(handler=_demo_command)

    web = commands.add_parser("web", help="run the interactive browser demo app")
    web.add_argument("--cert", required=True, help="server certificate PEM file")
    web.add_argument("--key", required=True, help="server private key PEM file")
    web.add_argument("--cafile", required=True, help="trusted CA/certificate PEM file")
    web.add_argument("--host", default="127.0.0.1", help="local web UI bind address")
    web.add_argument("--port", type=int, default=8000, help="local web UI port")
    web.set_defaults(handler=_web_command)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
