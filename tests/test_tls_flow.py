from __future__ import annotations

import datetime
import ipaddress
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_sync_handshake.client import TLSClient
from tls_sync_handshake.server import TLSServer
from tls_sync_handshake.session_cache import SessionCache


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
