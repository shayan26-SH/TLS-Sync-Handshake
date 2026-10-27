import socket

import pytest

from tls_sync_handshake.protocol import encode_line, receive_line


def test_receive_line_handles_split_chunks() -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(b"hello ")
        writer.sendall(b"TLS\nignored")
        assert receive_line(reader) == b"hello TLS"
    finally:
        reader.close()
        writer.close()


def test_receive_line_rejects_oversized_message() -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(b"12345\n")
        with pytest.raises(ValueError, match="limit"):
            receive_line(reader, limit=4)
    finally:
        reader.close()
        writer.close()


def test_encode_line_rejects_newlines() -> None:
    with pytest.raises(ValueError, match="newline"):
        encode_line(b"first\nsecond")
