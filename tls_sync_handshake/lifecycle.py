from __future__ import annotations

from enum import Enum
from typing import Callable
from uuid import uuid4


class SessionState(str, Enum):
    CLOSED = "CLOSED"
    HANDSHAKING = "HANDSHAKING"
    ESTABLISHED = "ESTABLISHED"
    RESUMED = "RESUMED"
    TERMINATED = "TERMINATED"


_ALLOWED_TRANSITIONS = {
    SessionState.CLOSED: {SessionState.HANDSHAKING, SessionState.TERMINATED},
    SessionState.HANDSHAKING: {
        SessionState.ESTABLISHED,
        SessionState.RESUMED,
        SessionState.TERMINATED,
    },
    SessionState.ESTABLISHED: {SessionState.TERMINATED},
    SessionState.RESUMED: {SessionState.TERMINATED},
    SessionState.TERMINATED: set(),
}


class SessionLifecycle:
    def __init__(self, logger: Callable[[str], None] | None = print) -> None:
        self.session_id = uuid4().hex[:8]
        self.state = SessionState.CLOSED
        self._logger = logger

    def transition(self, next_state: SessionState) -> None:
        if next_state not in _ALLOWED_TRANSITIONS[self.state]:
            raise RuntimeError(
                f"Invalid session transition: {self.state.value} -> {next_state.value}"
            )
        previous = self.state
        self.state = next_state
        if self._logger is not None:
            self._logger(
                f"[{self.session_id}] {previous.value} -> {next_state.value}"
            )

    def terminate(self) -> None:
        if self.state is not SessionState.TERMINATED:
            self.transition(SessionState.TERMINATED)
