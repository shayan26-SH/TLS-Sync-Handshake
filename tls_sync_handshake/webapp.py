from __future__ import annotations

import json
import ipaddress
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .client import TLSClient
from .protocol import MAX_REQUEST_BYTES
from .server import TLSServer
from .session_cache import SessionCache

_STATIC_DIR = Path(__file__).with_name("static")
_MAX_BODY_BYTES = 8192


class DemoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        certfile: str,
        keyfile: str,
        cafile: str,
    ) -> None:
        self.tls_server = TLSServer(
            certfile, keyfile, host="127.0.0.1", port=0, logger=None
        )
        self.tls_host, self.tls_port = self.tls_server.start()
        self.cache = SessionCache()
        self.client = TLSClient(cafile, cache=self.cache, logger=None)
        self.request_lock = threading.Lock()
        self.request_count = 0
        self.resumed_count = 0
        try:
            super().__init__(address, _make_handler())
        except Exception:
            self.tls_server.close()
            raise

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.tls_server.close()


def _make_handler() -> type[BaseHTTPRequestHandler]:
    class DemoRequestHandler(BaseHTTPRequestHandler):
        server: DemoHTTPServer

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                self._send_bytes(
                    200,
                    (_STATIC_DIR / "index.html").read_bytes(),
                    "text/html; charset=utf-8",
                )
            elif path == "/api/status":
                self._send_json(
                    200,
                    {
                        "ready": True,
                        "protocol": "TLS 1.3",
                        "requests": self.server.request_count,
                        "resumed": self.server.resumed_count,
                    },
                )
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if path not in {"/api/connect", "/api/reset"}:
                self._send_json(404, {"error": "Not found"})
                return

            if path == "/api/reset":
                with self.server.request_lock:
                    self.server.cache.clear(
                        self.server.tls_host, self.server.tls_port
                    )
                    self.server.request_count = 0
                    self.server.resumed_count = 0
                self._send_json(200, {"cleared": True})
                return

            try:
                length = int(self.headers.get("Content-Length", ""))
                if length < 0 or length > _MAX_BODY_BYTES:
                    raise ValueError("Request body is too large")
                payload = json.loads(self.rfile.read(length))
                message = payload.get("message") if isinstance(payload, dict) else None
                if not isinstance(message, str) or not message.strip():
                    raise ValueError("Enter a non-empty message")
                encoded_message = message.encode("utf-8")
                if len(encoded_message) > MAX_REQUEST_BYTES:
                    raise ValueError(
                        f"Message must be at most {MAX_REQUEST_BYTES} UTF-8 bytes"
                    )
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
                self._send_json(400, {"error": str(error) or "Invalid request"})
                return

            events: list[str] = []
            with self.server.request_lock:
                try:
                    self.server.client.logger = events.append
                    result = self.server.client.request(
                        self.server.tls_host,
                        self.server.tls_port,
                        encoded_message,
                    )
                    self.server.request_count += 1
                    if result.resumed:
                        self.server.resumed_count += 1
                except (OSError, ssl.SSLError, ValueError, RuntimeError) as error:
                    self._send_json(502, {"error": str(error)})
                    return
                finally:
                    self.server.client.logger = None

            self._send_json(
                200,
                {
                    "response": result.response.decode("utf-8", errors="replace"),
                    "protocol": result.protocol,
                    "cipher": result.cipher,
                    "resumed": result.resumed,
                    "ticket_cached": result.ticket_cached,
                    "events": events,
                },
            )

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self._send_bytes(status, body, "application/json; charset=utf-8")

        def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    return DemoRequestHandler


def create_web_server(
    certfile: str,
    keyfile: str,
    cafile: str,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> DemoHTTPServer:
    address = socket.getaddrinfo(
        host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
    )[0][4]
    if not ipaddress.ip_address(address[0]).is_loopback:
        raise ValueError("The browser demo can only bind to a loopback address")
    return DemoHTTPServer((str(address[0]), int(address[1])), certfile, keyfile, cafile)
