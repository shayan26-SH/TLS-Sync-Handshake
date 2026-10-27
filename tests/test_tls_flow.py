from __future__ import annotations

import datetime
import http.client
import ipaddress
import json
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_sync_handshake.client import TLSClient
from tls_sync_handshake.server import TLSServer
from tls_sync_handshake.session_cache import SessionCache
from tls_sync_handshake.webapp import create_web_server


def _write_certificate_files(directory: Path) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    cert_path = directory / "test-cert.pem"
    key_path = directory / "test-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_tls13_echo_and_session_resumption(tmp_path: Path) -> None:
    cert_path, key_path = _write_certificate_files(tmp_path)
    events: list[str] = []
    event_lock = threading.Lock()

    def log(event: str) -> None:
        with event_lock:
            events.append(event)

    server = TLSServer(
        str(cert_path),
        str(key_path),
        host="127.0.0.1",
        port=0,
        logger=log,
    )
    host, port = server.start()
    try:
        cache = SessionCache()
        client = TLSClient(str(cert_path), cache=cache, logger=log)
        first = client.request(host, port, b"first")
        second = client.request(host, port, b"second")

        assert first.response == b"echo: first"
        assert first.protocol == "TLSv1.3"
        assert first.ticket_cached
        assert second.response == b"echo: second"
        assert second.resumed
    finally:
        server.close()

    assert any("-> RESUMED" in event for event in events)


def test_browser_demo_api_shows_real_resumption_and_reset(tmp_path: Path) -> None:
    cert_path, key_path = _write_certificate_files(tmp_path)
    server = create_web_server(
        str(cert_path),
        str(key_path),
        str(cert_path),
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def request(method: str, path: str, payload: dict[str, str] | None = None):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        body = json.dumps(payload) if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        status = response.status
        connection.close()
        return status, data, response.getheader("Content-Type")

    try:
        status, page, content_type = request("GET", "/")
        assert status == 200
        assert content_type.startswith("text/html")
        assert b"Run full demo" in page

        status, first_bytes, _ = request(
            "POST", "/api/connect", {"message": "first web message"}
        )
        first = json.loads(first_bytes)
        assert status == 200
        assert first["response"] == "echo: first web message"
        assert first["protocol"] == "TLSv1.3"
        assert first["resumed"] is False

        status, second_bytes, _ = request(
            "POST", "/api/connect", {"message": "second web message"}
        )
        second = json.loads(second_bytes)
        assert status == 200
        assert second["resumed"] is True

        status, _, _ = request("POST", "/api/reset")
        assert status == 200
        status, third_bytes, _ = request(
            "POST", "/api/connect", {"message": "after reset"}
        )
        third = json.loads(third_bytes)
        assert status == 200
        assert third["resumed"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_browser_demo_refuses_non_loopback_bind(tmp_path: Path) -> None:
    cert_path, key_path = _write_certificate_files(tmp_path)

    try:
        create_web_server(
            str(cert_path),
            str(key_path),
            str(cert_path),
            host="192.0.2.1",
            port=0,
        )
    except ValueError as error:
        assert "loopback" in str(error)
    else:
        raise AssertionError("The demo must not bind to a non-loopback address")
