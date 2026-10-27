from __future__ import annotations

import socket


MAX_MESSAGE_BYTES = 4096
RESPONSE_PREFIX = b"echo: "
MAX_REQUEST_BYTES = MAX_MESSAGE_BYTES - len(RESPONSE_PREFIX)


def receive_line(sock: socket.socket, limit: int = MAX_MESSAGE_BYTES) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = sock.recv(min(1024, limit + 1 - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed before a complete message arrived")
        newline = chunk.find(b"\n")
        if newline >= 0:
            data.extend(chunk[:newline])
            return bytes(data)
        data.extend(chunk)
    raise ValueError(f"Message exceeds the {limit}-byte limit")


def encode_line(message: bytes, limit: int = MAX_MESSAGE_BYTES) -> bytes:
    if b"\n" in message or b"\r" in message:
        raise ValueError("Messages must not contain newline characters")
    if len(message) > limit:
        raise ValueError(f"Message exceeds the {limit}-byte limit")
    return message + b"\n"
