"""Request-local handling of built-in regex timeouts."""

from contextlib import contextmanager
from contextvars import ContextVar

_strict = ContextVar("presidio_strict_scan", default=False)


class IncompleteScan(RuntimeError):  # noqa: N818
    """A built-in rule or allowlist did not finish scanning."""


@contextmanager
def strict_scan():
    """Raise IncompleteScan on a built-in regex timeout inside this scope."""
    token = _strict.set(True)
    try:
        yield
    finally:
        _strict.reset(token)


def check_scan_timeout():
    """Raise before the legacy timeout handler can return partial results."""
    if _strict.get():
        raise IncompleteScan("Presidio regex scan timed out") from None
