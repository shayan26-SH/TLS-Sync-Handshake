from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Callable

from .lifecycle import SessionLifecycle, SessionState
from .protocol import MAX_REQUEST_BYTES, encode_line, receive_line
from .session_cache import SessionCache


@dataclass(frozen=True)
class ClientResult:
    response: bytes
    resumed: bool
    protocol: str
    cipher: str
    ticket_cached: bool


class TLSClient:
    def __init__(
        self,
        cafile: str,
        cache: SessionCache | None = None,
        logger: Callable[[str], None] | None = print,
        timeout: float = 5.0,
    ) -> None:
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.cache = cache if cache is not None else SessionCache()
        self.logger = logger
        self.timeout = timeout

    def request(self, host: str, port: int, message: bytes) -> ClientResult:
        request = encode_line(message, limit=MAX_REQUEST_BYTES)
        lifecycle = SessionLifecycle(self.logger)
        raw_socket: socket.socket | None = None
        tls_socket: ssl.SSLSocket | None = None
        try:
            lifecycle.transition(SessionState.HANDSHAKING)
            raw_socket = socket.create_connection((host, port), timeout=self.timeout)
            tls_socket = self.context.wrap_socket(
                raw_socket,
                server_hostname=host,
                session=self.cache.get(host, port),
            )
            tls_socket.settimeout(self.timeout)
            resumed = tls_socket.session_reused
            lifecycle.transition(
                SessionState.RESUMED if resumed else SessionState.ESTABLISHED
            )

            tls_socket.sendall(request)
            response = receive_line(tls_socket)
            session = tls_socket.session
            ticket_cached = self.cache.put(host, port, session)
            protocol = tls_socket.version() or "unknown"
            cipher_info = tls_socket.cipher()
            cipher = cipher_info[0] if cipher_info else "unknown"

            raw_socket = tls_socket.unwrap()
            tls_socket = None
            raw_socket.close()
            raw_socket = None
            lifecycle.terminate()
            return ClientResult(response, resumed, protocol, cipher, ticket_cached)
        finally:
            if tls_socket is not None:
                tls_socket.close()
            if raw_socket is not None:
                raw_socket.close()
            lifecycle.terminate()
