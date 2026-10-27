# TLS Sync Handshake

A small Python demonstration of TLS 1.3 connection lifecycle and session resumption. It runs a local TLS echo server and client, logs high-level state transitions, and attempts to reuse a TLS session ticket on a second connection.

Python's `ssl` module and its OpenSSL backend implement the TLS protocol and cryptographic operations. This project does **not** implement TLS records, handshake messages, key exchange, certificate verification, or traffic-key derivation itself.

## Security scope

This is an educational prototype, not a production server or a custom TLS implementation. Use a maintained TLS stack such as Python's `ssl` for real applications. Do not log, export, or persist private keys, session tickets, traffic secrets, or other credentials.

The demo intentionally:

- Requires TLS 1.3 and normal certificate verification.
- Uses a process-local client session cache; session objects are opaque and are not serialized.
- Leaves ticket creation, cryptographic resumption, and server-side ticket handling to OpenSSL.
- Does not implement 0-RTT, replay handling, a distributed session store, custom key updates, or application authentication.
- Uses a simple bounded newline-delimited echo protocol over TLS. The server handles connections sequentially.

## Requirements

- Python 3.10 or newer
- An OpenSSL build with TLS 1.3 support (the Python `ssl` module reports its OpenSSL version)
- `cryptography` and `pytest` only for generating local development certificates and running tests

Install the development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

## Generate a local development certificate

The helper creates a self-signed certificate and private key in `dev-certs`. These are for local testing only; do not use them in a deployed service.

```powershell
python scripts\generate_dev_cert.py
```

## Run the resumption demo

```powershell
python -m tls_sync_handshake demo `
  --cert dev-certs\localhost-cert.pem `
  --key dev-certs\localhost-key.pem `
  --cafile dev-certs\localhost-cert.pem
```

The demo makes two connections. It should report a full handshake on the first and a resumed handshake on the second when the platform's OpenSSL build issues and accepts a session ticket. The client prints whether it cached a ticket and whether the second connection actually resumed; resumption is never reported as successful unless OpenSSL confirms it.

## Run server and client separately

Start the server:

```powershell
python -m tls_sync_handshake server `
  --cert dev-certs\localhost-cert.pem `
  --key dev-certs\localhost-key.pem `
  --host 127.0.0.1 `
  --port 8443
```

In another terminal, send a message:

```powershell
python -m tls_sync_handshake client `
  --cafile dev-certs\localhost-cert.pem `
  --host 127.0.0.1 `
  --port 8443 `
  --message "hello TLS 1.3"
```

The standalone client makes one request per process. Session resumption is demonstrated by the `demo` command, which retains the opaque client session in memory between connections.

## State and session behavior

Each connection logs transitions from `CLOSED` to `HANDSHAKING`, then to `ESTABLISHED` or `RESUMED`, and finally to `TERMINATED`. Failed connections are terminated and report an error. The lifecycle class rejects invalid transitions.

The client cache keys sessions by host and port and checks the `SSLSession` ticket and timeout properties. Actual ticket validity and resumption are determined by OpenSSL. A cache entry is not a custom session ticket store and cannot be shared across processes.

## Tests

Run the unit and local TLS integration tests:

```powershell
python -m pytest -q
```

The integration test creates a short-lived self-signed test certificate in a temporary directory, starts a loopback-only server, verifies TLS 1.3, and checks session resumption. It does not contact external hosts.

## Project layout

```text
tls_sync_handshake/
  client.py          TLS client and in-memory resumption attempt
  lifecycle.py       Validated session lifecycle transitions
  protocol.py        Bounded demo message framing
  server.py          Sequential TLS 1.3 echo server
  session_cache.py   Process-local opaque SSLSession cache
scripts/
  generate_dev_cert.py
tests/
  test_lifecycle.py
  test_protocol.py
  test_tls_flow.py
```

## References

- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [Python `ssl` module documentation](https://docs.python.org/3/library/ssl.html)
