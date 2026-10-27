from __future__ import annotations

import time
from dataclasses import dataclass
from ssl import SSLSession


@dataclass(frozen=True)
class CachedSession:
    session: SSLSession
    expires_at: float


class SessionCache:
    """Process-local cache of opaque TLS sessions; never serializes ticket material."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, int], CachedSession] = {}

    def get(self, host: str, port: int) -> SSLSession | None:
        key = (host, port)
        cached = self._sessions.get(key)
        if cached is None:
            return None
        if cached.expires_at <= time.time() or not cached.session.has_ticket:
            self._sessions.pop(key, None)
            return None
        return cached.session

    def put(self, host: str, port: int, session: SSLSession) -> bool:
        if not session.has_ticket or session.timeout <= 0:
            return False
        expires_at = session.time + session.timeout
        if expires_at <= time.time():
            return False
        self._sessions[(host, port)] = CachedSession(session, expires_at)
        return True

    def clear(self, host: str, port: int) -> None:
        self._sessions.pop((host, port), None)
