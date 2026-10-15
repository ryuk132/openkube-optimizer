"""Private single-request HTTP/1.1 exchange on an already-owned TLS stream.

h11 is imported only at exchange time. No DNS/connect/TLS setup, retry, redirect,
SDK, content decoder or wire projection lives here. Inputs/results are transient
adapter-only data; ordinary disclosure guards are not an in-process sandbox.
"""

import math
import re
import selectors
import ssl
import time
from typing import TYPE_CHECKING, Never, SupportsIndex
from urllib.parse import quote

from .connection import _DeadlineExpired, _remaining, _TlsConnection, _wait
from .kubeconfig import _Failure
from .preflight import _Preflight

if TYPE_CHECKING:
    import h11

_HTTP_POLICY_VERSION = "single-http-identity-v1"
_MAX_METADATA_BYTES = 16 * 1024  # Request and aggregate response, ADR 0008 D4.
_MAX_WIRE_BYTES = 32 * 1024 * 1024  # All received HTTP plaintext, including framing.
_MAX_BODY_BYTES = 16 * 1024 * 1024  # Identity body; content decoding is deferred.
_MAX_HEADER_FIELDS = 128  # Aggregate physical field lines, including trailers.
_IO_CHUNK_BYTES = 8192  # Local bounded step, not a new operational limit.
_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)+")
_QUERY_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


class _PrivateHttpRecord:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Immutable HTTP record")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Immutable HTTP record")

    def __getstate__(self) -> Never:
        raise TypeError("HTTP records cannot be serialized")

    def __reduce__(self) -> Never:
        self.__getstate__()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()


class _HttpRequest(_PrivateHttpRecord):
    """GET only; relative origin path, raw query pairs, controlled header pairs.

    Query values are escaped once here; callers must supply unencoded values.
    Host/Connection are generated here. Authentication is never discovered or
    copied from preflight; optional Authorization is an already-controlled value.
    """

    __slots__ = ("path", "query", "headers")
    path: str
    query: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]

    def __init__(
        self,
        *,
        path: str,
        query: tuple[tuple[str, str], ...] = (),
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "headers", headers)

    def __repr__(self) -> str:
        return "<HTTP request: redacted>"


class _HttpResponse(_PrivateHttpRecord):
    __slots__ = ("status", "body")
    status: int
    body: bytes

    def __init__(self, *, status: int, body: bytes) -> None:
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "body", body)

    def __repr__(self) -> str:
        return "<HTTP response: redacted>"


class _RequestInvalid(Exception):
    """Closed local-input signal, never outward diagnostic text."""


class _ResponseInvalid(Exception):
    """Closed response-policy signal, distinct from parser diagnostics."""


class _TooLarge(Exception):
    """Closed aggregate limit signal."""


class _Closed(Exception):
    """Closed transport signal."""


def _visible(value: str, *, spaces: bool = True) -> bool:
    return bool(value) and all((32 if spaces else 33) <= ord(c) <= 126 for c in value)


def _request_parts(
    endpoint: _Preflight, request: _HttpRequest
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    path = request.path
    if (
        len(path) > _MAX_METADATA_BYTES
        or _PATH.fullmatch(path) is None
        or any(segment in (".", "..") for segment in path.split("/"))
        or len(request.query) > _MAX_HEADER_FIELDS
        or len(request.headers) > 3
    ):
        raise _RequestInvalid
    # Preserve the literal prefix; share only its existing boundary separator.
    target = endpoint.base_path + (
        path[1:] if endpoint.base_path.endswith("/") else path
    )
    seen_query: set[str] = set()
    for name, value in request.query:
        if (
            len(name) + len(value) > _MAX_METADATA_BYTES
            or _QUERY_NAME.fullmatch(name) is None
            or name in seen_query
            or (value and not _visible(value))
        ):
            raise _RequestInvalid
        seen_query.add(name)
        encoded_size = sum(1 if c in _UNRESERVED else 3 for c in value)
        if len(target) + 2 + len(name) + encoded_size > _MAX_METADATA_BYTES:
            raise _RequestInvalid
        target += (
            ("?" if len(seen_query) == 1 else "&") + name + "=" + quote(value, safe="")
        )
    headers = [(b"Host", endpoint.authority.encode("ascii")), (b"Connection", b"close")]
    controlled: dict[str, bytes] = {"accept": b"application/json"}
    seen_headers: set[str] = set()
    for name, value in request.headers:
        if len(name) + len(value) > _MAX_METADATA_BYTES or not _visible(value):
            raise _RequestInvalid
        key = name.lower()
        if key not in ("accept", "authorization", "user-agent") or key in seen_headers:
            raise _RequestInvalid
        seen_headers.add(key)
        if value[0] == " " or value[-1] == " ":
            raise _RequestInvalid  # h11 must not trim opaque input.
        if key == "authorization" and (
            not value.startswith("Bearer ") or not _visible(value[7:], spaces=False)
        ):
            raise _RequestInvalid
        controlled[key] = value.encode("ascii")
    names = {
        "accept": b"Accept",
        "authorization": b"Authorization",
        "user-agent": b"User-Agent",
    }
    headers.extend((names[key], value) for key, value in controlled.items())
    target_bytes = target.encode("ascii")
    size = len(b"GET  HTTP/1.1\r\n\r\n") + len(target_bytes)
    size += sum(len(name) + len(value) + 4 for name, value in headers)
    if size > _MAX_METADATA_BYTES:
        raise _RequestInvalid
    return target_bytes, headers


class _Budget:
    __slots__ = ("metadata", "fields", "wire", "final_response")

    def __init__(self) -> None:
        self.metadata = 0
        self.fields = 0
        self.wire = 0
        self.final_response = False

    def metadata_block(self, count: int, fields: int) -> None:
        if (
            self.metadata + count > _MAX_METADATA_BYTES
            or self.fields + fields > _MAX_HEADER_FIELDS
        ):
            raise _TooLarge
        self.metadata += count
        self.fields += fields

    def received(self, count: int) -> None:
        if self.wire + count > _MAX_WIRE_BYTES:
            raise _TooLarge
        self.wire += count


def _parser(budget: _Budget) -> "h11.Connection":
    import h11
    from h11._receivebuffer import ReceiveBuffer

    # Pinned 0.16.0 implementation hook, characterized before use. This does
    # byte/physical-field accounting only: h11 selects metadata blocks and owns
    # every framing decision. Count before extraction/header construction so
    # duplicate normalized fields and whitespace cannot evade aggregate guards.
    parser = h11.Connection(
        h11.CLIENT, max_incomplete_event_size=_MAX_METADATA_BYTES + 1
    )

    class MeteredBuffer(ReceiveBuffer):
        in_metadata = False
        in_chunk_line = False

        def maybe_extract_lines(self) -> list[bytearray] | None:
            self.in_metadata = True
            try:
                lines = super().maybe_extract_lines()
                if lines is None and budget.metadata + len(self) > _MAX_METADATA_BYTES:
                    raise _TooLarge
                return lines
            finally:
                self.in_metadata = False

        def maybe_extract_next_line(self) -> bytearray | None:
            self.in_chunk_line = True
            try:
                line = super().maybe_extract_next_line()
                if line is None and len(self) > _MAX_METADATA_BYTES:
                    raise _TooLarge
                return line
            finally:
                self.in_chunk_line = False

        def _extract(self, count: int) -> bytearray:
            if self.in_chunk_line and count > _MAX_METADATA_BYTES:
                raise _TooLarge
            if self.in_metadata:
                # Initial/interim blocks include status + blank line; trailers
                # include only their terminating blank line. Folded lines count
                # conservatively as additional fields; no raw header is retained.
                fields = max(
                    0,
                    self._data.count(b"\n", 0, count)
                    - (1 if budget.final_response else 2),
                )
                budget.metadata_block(count, fields)
            return super()._extract(count)

    parser._receive_buffer = MeteredBuffer()
    return parser


def _send(stream: ssl.SSLSocket, data: bytes, deadline: float) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        _remaining(deadline)
        try:
            sent = stream.send(view[offset:])
        except ssl.SSLWantReadError:
            _wait(stream, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(stream, selectors.EVENT_WRITE, deadline)
        else:
            if sent <= 0:
                raise _Closed
            offset += sent
    _remaining(deadline)


def _receive(stream: ssl.SSLSocket, size: int, deadline: float) -> bytes:
    while True:
        _remaining(deadline)
        try:
            data = stream.recv(size)
        except ssl.SSLWantReadError:
            _wait(stream, selectors.EVENT_READ, deadline)
        except ssl.SSLWantWriteError:
            _wait(stream, selectors.EVENT_WRITE, deadline)
        else:
            _remaining(deadline)
            return data


def _exchange(
    endpoint: _Preflight,
    connection: _TlsConnection,
    request: _HttpRequest,
    *,
    deadline: float,
) -> _HttpResponse | _Failure:
    """Own and close the supplied connection on every path; exactly one GET."""
    writing = True
    protocol_error: type[Exception] = _ResponseInvalid
    try:
        if not math.isfinite(deadline) or time.monotonic() >= deadline:
            return _Failure.TRANSPORT_DEADLINE_EXPIRED
        stream = connection._socket
        if stream is None:
            return _Failure.HTTP_CONNECTION_CLOSED
        target, headers = _request_parts(endpoint, request)
        import h11

        protocol_error = h11.ProtocolError

        budget = _Budget()
        parser = _parser(budget)
        wire_request = parser.send(
            h11.Request(method=b"GET", target=target, headers=headers)
        )
        ending = parser.send(h11.EndOfMessage())
        if wire_request is None or ending is None:
            raise _RequestInvalid
        if len(wire_request) + len(ending) > _MAX_METADATA_BYTES:
            raise _RequestInvalid
        _send(stream, wire_request + ending, deadline)
        writing = False
        status: int | None = None
        body = bytearray()
        eof = False
        while True:
            _remaining(deadline)
            event = parser.next_event()
            if event is h11.NEED_DATA:
                if eof:
                    raise _ResponseInvalid
                chunk = _receive(
                    stream,
                    min(_IO_CHUNK_BYTES, _MAX_WIRE_BYTES - budget.wire + 1),
                    deadline,
                )
                budget.received(len(chunk))
                parser.receive_data(chunk)
                eof = not chunk
            elif isinstance(event, h11.InformationalResponse):
                if event.status_code == 101:
                    raise _ResponseInvalid
            elif isinstance(event, h11.Response):
                if status is not None or event.http_version not in (b"1.0", b"1.1"):
                    raise _ResponseInvalid
                status = event.status_code
                budget.final_response = True
                fields = dict(event.headers)
                if b"content-length" in fields and b"transfer-encoding" in fields:
                    raise _ResponseInvalid
                encodings = [v for n, v in event.headers if n == b"content-encoding"]
                if len(encodings) > 1 or (
                    encodings and encodings[0].lower() != b"identity"
                ):
                    raise _ResponseInvalid
                del fields  # Status/body only survive this framing boundary.
            elif isinstance(event, h11.Data):
                if len(body) + len(event.data) > _MAX_BODY_BYTES:
                    raise _TooLarge
                body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                if (
                    status is None
                    or parser.trailing_data[0]
                    or any(
                        name
                        in (
                            b"content-length",
                            b"transfer-encoding",
                            b"content-encoding",
                            b"connection",
                            b"host",
                            b"trailer",
                        )
                        for name, _ in event.headers
                    )
                ):
                    raise _ResponseInvalid
                _remaining(deadline)
                return _HttpResponse(status=status, body=bytes(body))
            elif isinstance(event, h11.ConnectionClosed):
                return _Failure.HTTP_CONNECTION_CLOSED
            else:
                raise _ResponseInvalid
    except _DeadlineExpired:
        return _Failure.TRANSPORT_DEADLINE_EXPIRED
    except _RequestInvalid:
        return _Failure.HTTP_REQUEST_INVALID
    except _TooLarge:
        return _Failure.HTTP_RESPONSE_TOO_LARGE
    except _Closed:
        return _Failure.HTTP_CONNECTION_CLOSED
    except _ResponseInvalid:
        return _Failure.HTTP_RESPONSE_INVALID
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        return _Failure.HTTP_CONNECTION_CLOSED
    except OSError:
        return (
            _Failure.HTTP_WRITE_FAILED if writing else _Failure.HTTP_CONNECTION_CLOSED
        )
    except protocol_error:
        if not writing and eof and budget.wire == 0:
            return _Failure.HTTP_CONNECTION_CLOSED
        return (
            _Failure.HTTP_REQUEST_INVALID if writing else _Failure.HTTP_RESPONSE_INVALID
        )
    finally:
        connection.close()
