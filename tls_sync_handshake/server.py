from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable

from .lifecycle import SessionLifecycle, SessionState
from .protocol import MAX_REQUEST_BYTES, RESPONSE_PREFIX, encode_line, receive_line


class TLSServer:
    def __init__(
        self,
        certfile: str,
        keyfile: str,
        host: str = "127.0.0.1",
        port: int = 8443,
        logger: Callable[[str], None] | None = print,
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.logger = logger
        self.timeout = timeout
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    @property
    def address(self) -> tuple[str, int]:
        if self._listener is None:
            raise RuntimeError("Server has not been started")
        address = self._listener.getsockname()
        return str(address[0]), int(address[1])

    def start(self) -> tuple[str, int]:
        if self._thread is not None:
            raise RuntimeError("Server has already been started")
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen()
        self._listener.settimeout(0.25)
        self._thread = threading.Thread(target=self._serve, name="tls-demo-server")
        self._thread.start()
        return self.address

    def close(self) -> None:
        self._stopping.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout + 1)
            if self._thread.is_alive():
                raise TimeoutError("TLS server did not stop in time")

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stopping.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stopping.is_set():
                    return
                raise
            self._handle(connection)

    def _handle(self, connection: socket.socket) -> None:
        lifecycle = SessionLifecycle(self.logger)
        tls_socket: ssl.SSLSocket | None = None
        try:
            connection.settimeout(self.timeout)
            lifecycle.transition(SessionState.HANDSHAKING)
            tls_socket = self.context.wrap_socket(connection, server_side=True)
            tls_socket.settimeout(self.timeout)
            lifecycle.transition(
                SessionState.RESUMED
                if tls_socket.session_reused
                else SessionState.ESTABLISHED
            )

            message = receive_line(tls_socket, limit=MAX_REQUEST_BYTES)
            tls_socket.sendall(encode_line(RESPONSE_PREFIX + message))
            connection = tls_socket.unwrap()
            tls_socket = None
            connection.close()
            lifecycle.terminate()
        except (OSError, ssl.SSLError, ValueError, ConnectionError) as error:
            if tls_socket is not None:
                tls_socket.close()
            else:
                connection.close()
            lifecycle.terminate()
            if self.logger is not None:
                self.logger(f"[{lifecycle.session_id}] connection failed: {error}")
