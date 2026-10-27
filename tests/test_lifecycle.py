import pytest

from tls_sync_handshake.lifecycle import SessionLifecycle, SessionState


def test_handshake_can_establish_and_terminate() -> None:
    lifecycle = SessionLifecycle(logger=None)

    lifecycle.transition(SessionState.HANDSHAKING)
    lifecycle.transition(SessionState.ESTABLISHED)
    lifecycle.terminate()

    assert lifecycle.state is SessionState.TERMINATED


def test_handshake_can_resume_and_terminate() -> None:
    lifecycle = SessionLifecycle(logger=None)

    lifecycle.transition(SessionState.HANDSHAKING)
    lifecycle.transition(SessionState.RESUMED)
    lifecycle.terminate()

    assert lifecycle.state is SessionState.TERMINATED


def test_invalid_transition_is_rejected() -> None:
    lifecycle = SessionLifecycle(logger=None)

    with pytest.raises(RuntimeError, match="Invalid session transition"):
        lifecycle.transition(SessionState.ESTABLISHED)
