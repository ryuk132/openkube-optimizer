"""Private numeric TCP + TLS handshake boundary; no DNS or application bytes."""

import errno
import ipaddress
import math
import selectors
import socket
import ssl
import time
from typing import Never, Self, SupportsIndex

from .kubeconfig import _Failure
from .preflight import _Preflight
from .resolver import _IPV4, _IPV6, _MAX_ADDRESSES, _Resolution, _ResolvedAddress
from .tls import _TlsContext

_CONNECTION_POLICY_VERSION = "numeric-tcp-tls-v1"
_CONNECT_CAP_SECONDS = 5.0  # Existing operational limit, ADR 0008 D4.
_IN_PROGRESS = frozenset(
    (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR)
)


class _TlsConnection:
    """Sole owner after handshake; close releases without TLS shutdown/drain."""

    __slots__ = ("_socket",)
    _socket: ssl.SSLSocket | None

    def __init__(self, stream: ssl.SSLSocket) -> None:
        object.__setattr__(self, "_socket", stream)

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Private TLS connection")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Private TLS connection")

    def __repr__(self) -> str:
        return "<TLS connection: redacted>"

    def __getstate__(self) -> Never:
        raise TypeError("TLS connections cannot be serialized")

    def __reduce__(self) -> Never:
        self.__getstate__()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()

    def close(self) -> None:
        stream = self._socket
        object.__setattr__(self, "_socket", None)
        if stream is not None:
            _close(stream)

    def __enter__(self) -> Self:
        if self._socket is None:
            raise ValueError("TLS connection is closed")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _DeadlineExpired(Exception):
    """Internal signal, separate from a typed candidate-local OS timeout."""


class _InvalidCandidate(Exception):
    """Closed destination-validation signal with no retained address."""


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise _DeadlineExpired
    return left


def _wait(stream: socket.socket, events: int, deadline: float) -> None:
    # Each registration ends before wrap_socket can detach/transfer its fd.
    with selectors.DefaultSelector() as selector:
        selector.register(stream, events)
        if not selector.select(_remaining(deadline)):
            raise _DeadlineExpired
        _remaining(deadline)


def _close(stream: socket.socket) -> None:
    try:
        stream.close()
    except OSError:
        # Never retry a close that may already have released its descriptor.
        pass


def _sockaddr(
    candidate: _ResolvedAddress, port: int
) -> tuple[int, tuple[str, int] | tuple[str, int, int, int]]:
    if candidate.family not in (_IPV4, _IPV6) or len(candidate.packed) != (
        4 if candidate.family == _IPV4 else 16
    ):
        raise _InvalidCandidate
    address = ipaddress.ip_address(candidate.packed)
    if address.is_unspecified or address.is_multicast:
        raise _InvalidCandidate  # Accepted API-destination rule, not private-IP filtering.
    if candidate.family == _IPV4:
        return socket.AF_INET, (str(address), port)
    scope = 0
    if address.is_link_local:
        index = candidate.ifindex
        if type(index) is not int or not 1 <= index <= (1 << 31) - 1:
            raise _InvalidCandidate
        scope = index
    return socket.AF_INET6, (str(address), port, 0, scope)


def _handshake(stream: ssl.SSLSocket, deadline: float) -> None:
    while True:
        _remaining(deadline)
        try:
            stream.do_handshake()
        except ssl.SSLWantReadError:
            _wait(stream, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(stream, selectors.EVENT_WRITE, deadline)
        else:
            _remaining(deadline)
            return


def _connect(
    endpoint: _Preflight,
    resolution: _Resolution,
    context: _TlsContext,
    *,
    deadline: float,
) -> _TlsConnection | _Failure:
    """Consume validated inputs once in order under the unchanged caller deadline.

    Typed EOF/closed-stream/ConnectionError/OS-timeout failures permit fallback.
    Verification and other TLS errors abort; no OpenSSL string classification.
    """
    if not math.isfinite(deadline) or time.monotonic() >= deadline:
        return _Failure.TRANSPORT_DEADLINE_EXPIRED
    if not 1 <= len(resolution.addresses) <= _MAX_ADDRESSES:
        return _Failure.CONNECTION_FAILED
    for candidate in resolution.addresses:
        if time.monotonic() >= deadline:
            return _Failure.TRANSPORT_DEADLINE_EXPIRED
        raw: socket.socket | None = None
        stream: ssl.SSLSocket | None = None
        tls_phase = False
        try:
            family, target = _sockaddr(candidate, endpoint.port)
            connect_deadline = min(deadline, time.monotonic() + _CONNECT_CAP_SECONDS)
            raw = socket.socket(family, socket.SOCK_STREAM)
            raw.setblocking(False)
            _remaining(connect_deadline)
            code = raw.connect_ex(target)
            if code not in (0, *_IN_PROGRESS):
                continue
            if code:
                _wait(raw, selectors.EVENT_WRITE, connect_deadline)
            _remaining(connect_deadline)
            if raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                continue
            _remaining(deadline)
            tls_phase = True
            stream = context._context.wrap_socket(
                raw,
                server_hostname=endpoint.hostname,
                do_handshake_on_connect=False,
            )
            # Pinned CPython detaches raw on success. On a pre-detach failure
            # raw still owns the fd; after detachment CPython closes its failed
            # SSLSocket internally. The finally block checks that distinction.
            stream.setblocking(False)
            _handshake(stream, deadline)
            result = _TlsConnection(stream)
            stream = None  # Transfer the sole live socket to the holder.
            return result
        except _InvalidCandidate:
            continue
        except _DeadlineExpired:
            if tls_phase or time.monotonic() >= deadline:
                return _Failure.TRANSPORT_DEADLINE_EXPIRED
        except ssl.SSLCertVerificationError:
            return _Failure.TLS_VERIFICATION_FAILED
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionError, TimeoutError):
            pass
        except ssl.SSLError:
            return _Failure.TLS_HANDSHAKE_FAILED
        except OSError:
            if tls_phase:
                return _Failure.TLS_HANDSHAKE_FAILED
        finally:
            if stream is not None:
                _close(stream)
            if raw is not None and raw.fileno() >= 0:
                _close(raw)
    if time.monotonic() >= deadline:
        return _Failure.TRANSPORT_DEADLINE_EXPIRED
    return _Failure.CONNECTION_FAILED
