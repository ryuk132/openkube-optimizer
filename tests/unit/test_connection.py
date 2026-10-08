"""Synthetic numeric TCP/TLS control flow, clocks, ownership and safe surfaces."""

import copy
import dataclasses
import errno
import ipaddress
import json
import pickle
import selectors
import socket
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Self, cast

import pytest

from openkube_optimizer.collection import connection as cn
from openkube_optimizer.collection import preflight as pf
from openkube_optimizer.collection import resolver as rs
from openkube_optimizer.collection.kubeconfig import _Failure as F
from openkube_optimizer.collection.tls import _TlsContext

HOST = "API.Connection-Canary.invalid"
DIAGNOSTIC = "native-errno-openssl-diagnostic-canary"
PORT = 36443


def endpoint() -> pf._Preflight:
    return pf._Preflight(
        hostname=HOST,
        port=PORT,
        authority=f"{HOST}:{PORT}",
        base_path="/unused",
        ca_path=Path("/unused-ca-canary"),
        auth=pf._BearerToken(token="unused-token-canary"),
    )


def resolution(*addresses: str) -> rs._Resolution:
    records = []
    for text in addresses:
        ip = ipaddress.ip_address(text)
        records.append(
            {"family": 2 if ip.version == 4 else 10, "address": list(ip.packed)}
        )
    result = rs._parse_reply(
        json.dumps(
            {
                "parameters": {
                    "addresses": records,
                    "name": "ignored-canonical-canary",
                    "flags": 1,
                }
            }
        ).encode()
        + b"\0"
    )
    assert isinstance(result, rs._Resolution)
    return result


class FakeSocket:
    def __init__(self, flow: "Flow", family: int) -> None:
        self.flow = flow
        self.fd = 100 + len(flow.raw)
        self.family = family
        self.closed = 0
        self.blocking = True
        self.code = errno.EINPROGRESS
        self.error = 0
        self.faults: dict[str, BaseException] = {}
        self.delay = 0.0
        self.connects = 0
        self.error_checks = 0

    def fileno(self) -> int:
        return self.fd

    def setblocking(self, value: bool) -> None:
        if "blocking" in self.faults:
            raise self.faults["blocking"]
        assert value is False
        self.blocking = value

    def connect_ex(self, target: tuple[object, ...]) -> int:
        assert not self.blocking
        self.flow.attempts.append(target)
        self.connects += 1
        self.flow.now += self.delay
        if "connect" in self.faults:
            raise self.faults["connect"]
        return self.code

    def getsockopt(self, level: int, option: int) -> int:
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_ERROR)
        self.error_checks += 1
        if "error" in self.faults:
            raise self.faults["error"]
        return self.error

    def close(self) -> None:
        assert self.fd >= 0, "Double close of a detached/closed raw socket"
        self.flow.closed.append(self.fd)
        self.closed += 1
        self.fd = -1
        if "close" in self.faults:
            raise self.faults["close"]


class FakeSSL:
    def __init__(self, raw: FakeSocket) -> None:
        self.flow = raw.flow
        self.fd = raw.fd
        raw.fd = -1
        self.closed = 0
        self.steps: list[BaseException | None] = [None]
        self.calls = 0
        self.delay = 0.0
        self.close_fault: BaseException | None = None

    def fileno(self) -> int:
        return self.fd

    def setblocking(self, value: bool) -> None:
        assert value is False

    def do_handshake(self) -> None:
        self.calls += 1
        self.flow.now += self.delay
        item = self.steps.pop(0)
        if item is not None:
            raise item

    def close(self) -> None:
        assert self.fd >= 0, "Double close of SSL socket"
        self.flow.closed.append(self.fd)
        self.closed += 1
        self.fd = -1
        if self.close_fault is not None:
            raise self.close_fault


class FakeContext:
    def __init__(self, flow: "Flow") -> None:
        self.flow = flow
        self.wrap_fault: BaseException | None = None
        self.detach_on_fault = False

    def wrap_socket(
        self, raw: FakeSocket, *, server_hostname: str, do_handshake_on_connect: bool
    ) -> FakeSSL:
        assert server_hostname == HOST and do_handshake_on_connect is False
        assert raw.blocking is False
        self.flow.names.append(server_hostname)
        if self.wrap_fault is not None:
            if self.detach_on_fault:
                self.flow.closed.append(raw.fd)
                raw.fd = -1  # Pinned CPython's internally closed post-detach path.
            raise self.wrap_fault
        stream = FakeSSL(raw)
        self.flow.streams.append(stream)
        self.flow.configure_ssl(stream, len(self.flow.streams) - 1)
        return stream


class FakeSelector:
    def __init__(self, flow: "Flow") -> None:
        self.flow = flow
        self.closed = False
        self.events = 0
        self.fd = -1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def register(self, stream: FakeSocket | FakeSSL, events: int) -> None:
        self.events = events
        self.fd = stream.fd
        if self.flow.select_fault is not None:
            raise self.flow.select_fault

    def select(self, timeout: float | None) -> list[object]:
        assert timeout is not None and 0 < timeout < 100, "Unbounded wait"
        self.flow.waits.append((self.fd, self.events, timeout))
        if self.flow.ready:
            self.flow.now += self.flow.wait_delay
            return [object()]
        self.flow.now += timeout
        return []


class Flow:
    def __init__(self) -> None:
        self.now = 100.0
        self.raw: list[FakeSocket] = []
        self.streams: list[FakeSSL] = []
        self.selectors: list[FakeSelector] = []
        self.attempts: list[tuple[object, ...]] = []
        self.names: list[str] = []
        self.closed: list[int] = []
        self.waits: list[tuple[int, int, float]] = []
        self.ready = True
        self.wait_delay = 0.0
        self.select_fault: BaseException | None = None
        self.create_fault: BaseException | None = None
        self.configure_raw: Callable[[FakeSocket, int], None] = lambda raw, index: None
        self.configure_ssl: Callable[[FakeSSL, int], None] = lambda stream, index: None
        self.context = FakeContext(self)

    def create(self, family: int, kind: int) -> FakeSocket:
        assert (
            family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM
        )
        if self.create_fault is not None:
            raise self.create_fault
        raw = FakeSocket(self, family)
        self.configure_raw(raw, len(self.raw))
        self.raw.append(raw)
        return raw

    def selector(self) -> FakeSelector:
        selector = FakeSelector(self)
        self.selectors.append(selector)
        return selector

    def connect(
        self, *, deadline: float = 115.0, addresses: tuple[str, ...] = ("127.0.0.1",)
    ) -> cn._TlsConnection | F:
        return cn._connect(
            endpoint(),
            resolution(*addresses),
            _TlsContext(cast(ssl.SSLContext, self.context)),
            deadline=deadline,
        )


@pytest.fixture
def flow(monkeypatch: pytest.MonkeyPatch) -> Iterator[Flow]:
    f = Flow()
    monkeypatch.setattr(socket, "socket", f.create)
    monkeypatch.setattr(selectors, "DefaultSelector", f.selector)
    monkeypatch.setattr(time, "monotonic", lambda: f.now)
    yield f
    assert all(s.closed for s in f.selectors)
    assert all(s.fd == -1 for s in f.raw)
    assert all(s.fd == -1 for s in f.streams)
    assert len(f.closed) == len(set(f.closed)), "Descriptor closed twice"


@pytest.mark.parametrize(
    "code", [0, errno.EINPROGRESS, errno.EALREADY, errno.EINTR, errno.EWOULDBLOCK]
)
def test_nonblocking_connect_and_socket_error_check(flow: Flow, code: int) -> None:
    flow.configure_raw = lambda raw, index: setattr(raw, "code", code)
    result = flow.connect()
    assert isinstance(result, cn._TlsConnection)
    assert flow.raw[0].error_checks == 1
    assert flow.raw[0].fd == -1 and flow.raw[0].closed == 0
    assert flow.streams[0].fd >= 0
    assert flow.names == [HOST]
    result.close()


@pytest.mark.parametrize(
    "code",
    [
        errno.ECONNREFUSED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.EACCES,
        errno.ETIMEDOUT,
    ],
)
def test_expected_tcp_failure_advances_once_in_order(flow: Flow, code: int) -> None:
    flow.configure_raw = lambda raw, index: setattr(
        raw, "code", code if index == 0 else 0
    )
    result = flow.connect(addresses=("127.0.0.2", "127.0.0.1", "::1"))
    assert isinstance(result, cn._TlsConnection)
    assert flow.attempts == [("127.0.0.2", PORT), ("127.0.0.1", PORT)]
    assert flow.raw[0].closed == 1 and len(flow.raw) == 2
    result.close()


def test_writability_does_not_override_so_error(flow: Flow) -> None:
    flow.configure_raw = lambda raw, index: setattr(
        raw, "error", errno.ECONNREFUSED if index == 0 else 0
    )
    result = flow.connect(addresses=("127.0.0.2", "::1"))
    assert isinstance(result, cn._TlsConnection)
    assert [raw.error_checks for raw in flow.raw] == [1, 1]
    assert flow.raw[0].closed == 1
    assert flow.attempts == [("127.0.0.2", PORT), ("::1", PORT, 0, 0)]
    result.close()


def test_all_tcp_candidates_fail(flow: Flow) -> None:
    flow.configure_raw = lambda raw, index: setattr(raw, "code", errno.ECONNREFUSED)
    assert flow.connect(addresses=("127.0.0.2", "127.0.0.1")) is F.CONNECTION_FAILED
    assert len(flow.attempts) == 2


def test_resolver_dedup_is_consumed_without_hidden_retry(flow: Flow) -> None:
    flow.configure_raw = lambda raw, index: setattr(raw, "code", errno.ECONNREFUSED)
    assert (
        flow.connect(addresses=("127.0.0.1", "127.0.0.1", "::1", "::1"))
        is F.CONNECTION_FAILED
    )
    assert flow.attempts == [("127.0.0.1", PORT), ("::1", PORT, 0, 0)]


@pytest.mark.parametrize(
    "deadline", [99.0, 100.0, float("nan"), float("inf"), float("-inf")]
)
def test_expired_or_nonfinite_budget_attempts_nothing(
    flow: Flow, deadline: float
) -> None:
    assert flow.connect(deadline=deadline) is F.TRANSPORT_DEADLINE_EXPIRED
    assert not flow.raw and not flow.selectors


@pytest.mark.parametrize("remaining,expected", [(15.0, 5.0), (5.0, 5.0), (2.0, 2.0)])
def test_candidate_cap_clips_to_global_budget(
    flow: Flow, remaining: float, expected: float
) -> None:
    flow.ready = False
    result = flow.connect(deadline=100 + remaining)
    assert result is (
        F.CONNECTION_FAILED if remaining > 5 else F.TRANSPORT_DEADLINE_EXPIRED
    )
    assert flow.waits[0][2] == expected


def test_removed_candidate_cap_is_detected(
    flow: Flow, monkeypatch: pytest.MonkeyPatch
) -> None:
    flow.ready = False
    monkeypatch.setattr(cn, "_CONNECT_CAP_SECONDS", 15.0)
    flow.connect(deadline=115)
    with pytest.raises(AssertionError):
        assert flow.waits[0][2] == 5.0


def test_cap_timeout_can_advance_without_resetting_request(flow: Flow) -> None:
    flow.ready = False

    def configure(raw: FakeSocket, index: int) -> None:
        if index == 1:
            flow.ready = True
            raw.code = 0

    flow.configure_raw = configure
    result = flow.connect(addresses=("127.0.0.2", "127.0.0.1"), deadline=108)
    assert isinstance(result, cn._TlsConnection)
    assert flow.now == 105 and flow.waits[0][2] == 5
    result.close()


def test_candidate_transition_exhausts_shared_budget(flow: Flow) -> None:
    flow.ready = False
    assert (
        flow.connect(addresses=("127.0.0.2", "127.0.0.1", "::1"), deadline=107)
        is F.TRANSPORT_DEADLINE_EXPIRED
    )
    assert [wait[2] for wait in flow.waits] == [5, 2]
    assert len(flow.raw) == 2


def test_expiry_between_candidates_prevents_next_socket(flow: Flow) -> None:
    def configure(raw: FakeSocket, index: int) -> None:
        raw.code = errno.ECONNREFUSED
        raw.delay = 2

    flow.configure_raw = configure
    assert (
        flow.connect(addresses=("127.0.0.2", "127.0.0.1"), deadline=101)
        is F.TRANSPORT_DEADLINE_EXPIRED
    )
    assert len(flow.raw) == 1 and not flow.names


def test_tls_uses_global_budget_after_tcp(flow: Flow) -> None:
    flow.wait_delay = 2

    def configure(stream: FakeSSL, index: int) -> None:
        stream.steps = [ssl.SSLWantReadError(), ssl.SSLWantWriteError(), None]

    flow.configure_ssl = configure
    result = flow.connect(deadline=110)
    assert isinstance(result, cn._TlsConnection)
    assert [(events, left) for _, events, left in flow.waits] == [
        (selectors.EVENT_WRITE, 5),
        (selectors.EVENT_READ, 8),
        (selectors.EVENT_WRITE, 6),
    ]
    result.close()


def test_expiry_after_successful_handshake_closes_connection(flow: Flow) -> None:
    flow.configure_ssl = lambda stream, index: setattr(stream, "delay", 16)
    assert flow.connect() is F.TRANSPORT_DEADLINE_EXPIRED
    assert flow.streams[0].closed == 1


def test_want_read_timeout_is_global_and_does_not_fallback(flow: Flow) -> None:
    def configure(stream: FakeSSL, index: int) -> None:
        stream.steps = [ssl.SSLWantReadError()]
        flow.ready = False

    flow.configure_ssl = configure
    assert (
        flow.connect(addresses=("127.0.0.1", "::1"), deadline=102)
        is F.TRANSPORT_DEADLINE_EXPIRED
    )
    assert len(flow.raw) == 1 and flow.waits[-1][1:] == (selectors.EVENT_READ, 2)


@pytest.mark.parametrize(
    "fault",
    [
        ssl.SSLEOFError(DIAGNOSTIC),
        ssl.SSLZeroReturnError(DIAGNOSTIC),
        ConnectionResetError(DIAGNOSTIC),
        ConnectionAbortedError(DIAGNOSTIC),
        BrokenPipeError(DIAGNOSTIC),
        TimeoutError(DIAGNOSTIC),
    ],
)
def test_typed_tls_transport_fault_advances(flow: Flow, fault: BaseException) -> None:
    flow.configure_ssl = lambda stream, index: setattr(
        stream, "steps", [fault] if index == 0 else [None]
    )
    result = flow.connect(addresses=("127.0.0.2", "127.0.0.1"))
    assert isinstance(result, cn._TlsConnection)
    assert flow.streams[0].closed == 1 and len(flow.attempts) == 2
    result.close()


@pytest.mark.parametrize(
    "fault,expected",
    [
        (ssl.SSLCertVerificationError(DIAGNOSTIC), F.TLS_VERIFICATION_FAILED),
        (ssl.SSLError(DIAGNOSTIC), F.TLS_HANDSHAKE_FAILED),
        (ssl.SSLSyscallError(DIAGNOSTIC), F.TLS_HANDSHAKE_FAILED),
        (OSError(errno.EINVAL, DIAGNOSTIC), F.TLS_HANDSHAKE_FAILED),
    ],
)
def test_verification_and_unclassified_tls_failures_abort(
    flow: Flow, fault: BaseException, expected: F
) -> None:
    flow.configure_ssl = lambda stream, index: setattr(stream, "steps", [fault])
    result = flow.connect(addresses=("127.0.0.2", "127.0.0.1"))
    assert result is expected and len(flow.attempts) == 1
    assert DIAGNOSTIC not in repr(result) and HOST not in str(result)


@pytest.mark.parametrize("detached", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        OSError(DIAGNOSTIC),
        KeyboardInterrupt(DIAGNOSTIC),
        SystemExit(DIAGNOSTIC),
        RuntimeError(DIAGNOSTIC),
    ],
)
def test_wrap_failure_ownership_and_controls(
    flow: Flow, detached: bool, fault: BaseException
) -> None:
    flow.context.wrap_fault = fault
    flow.context.detach_on_fault = detached
    if isinstance(fault, OSError):
        assert flow.connect() is F.TLS_HANDSHAKE_FAILED
    else:
        with pytest.raises(type(fault)):
            flow.connect()
    assert flow.raw[0].fd == -1
    assert flow.raw[0].closed == (0 if detached else 1)
    assert len(flow.closed) == 1


@pytest.mark.parametrize(
    "stage", ["create", "blocking", "connect", "error", "select", "handshake"]
)
@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_controls_propagate_after_cleanup(
    flow: Flow, stage: str, kind: type[BaseException]
) -> None:
    fault = kind(DIAGNOSTIC)
    if stage == "create":
        flow.create_fault = fault
    elif stage == "select":
        flow.select_fault = fault
    elif stage == "handshake":
        flow.configure_ssl = lambda stream, index: setattr(stream, "steps", [fault])
    else:
        flow.configure_raw = lambda raw, index: raw.faults.__setitem__(stage, fault)
    with pytest.raises(kind):
        flow.connect()


@pytest.mark.parametrize("stage", ["create", "blocking", "connect", "error", "select"])
def test_os_failure_is_fixed_and_cleaned(flow: Flow, stage: str) -> None:
    fault = OSError(errno.EIO, DIAGNOSTIC)
    if stage == "create":
        flow.create_fault = fault
    elif stage == "select":
        flow.select_fault = fault
    else:
        flow.configure_raw = lambda raw, index: raw.faults.__setitem__(stage, fault)
    assert flow.connect() is F.CONNECTION_FAILED


@pytest.mark.parametrize(
    "text,family,scope",
    [
        ("10.1.2.3", socket.AF_INET, 0),
        ("127.0.0.1", socket.AF_INET, 0),
        ("169.254.1.2", socket.AF_INET, 0),
        ("2001:db8::1", socket.AF_INET6, 0),
        ("::1", socket.AF_INET6, 0),
        ("fc00::1", socket.AF_INET6, 0),
        ("fe80::1", socket.AF_INET6, 7),
    ],
)
def test_numeric_sockaddr_and_required_scope(
    text: str, family: int, scope: int
) -> None:
    ip = ipaddress.ip_address(text)
    candidate = rs._ResolvedAddress(2 if ip.version == 4 else 10, ip.packed, 7)
    actual_family, target = cn._sockaddr(candidate, PORT)
    assert actual_family == family
    assert target == (
        (text, PORT) if family == socket.AF_INET else (text, PORT, 0, scope)
    )


@pytest.mark.parametrize("text", ["0.0.0.0", "::", "224.0.0.1", "ff02::1"])
def test_invalid_api_destinations_never_open_socket(flow: Flow, text: str) -> None:
    assert flow.connect(addresses=(text,)) is F.CONNECTION_FAILED
    assert not flow.raw


@pytest.mark.parametrize(
    "family,packed,index",
    [
        (0, b"\0" * 4, None),
        (2, b"\0" * 16, None),
        (10, b"\0" * 4, None),
        (10, ipaddress.IPv6Address("fe80::1").packed, None),
        (10, ipaddress.IPv6Address("fe80::1").packed, 0),
        (10, ipaddress.IPv6Address("fe80::1").packed, -1),
        (10, ipaddress.IPv6Address("fe80::1").packed, True),
        (10, ipaddress.IPv6Address("fe80::1").packed, 2147483648),
    ],
)
def test_invalid_scope_or_family_rejected(
    family: int, packed: bytes, index: int | None
) -> None:
    with pytest.raises(cn._InvalidCandidate):
        cn._sockaddr(rs._ResolvedAddress(family, packed, index), PORT)


@pytest.mark.parametrize("count", [0, 65])
def test_invalid_private_resolution_bound_opens_nothing(flow: Flow, count: int) -> None:
    items = tuple(rs._ResolvedAddress(2, b"\x7f\0\0\1", None) for _ in range(count))
    assert (
        cn._connect(
            endpoint(),
            rs._Resolution(items),
            _TlsContext(cast(ssl.SSLContext, flow.context)),
            deadline=115,
        )
        is F.CONNECTION_FAILED
    )
    assert not flow.raw


@pytest.mark.parametrize("context_error", [False, True])
def test_holder_context_and_idempotent_close(flow: Flow, context_error: bool) -> None:
    result = flow.connect()
    assert isinstance(result, cn._TlsConnection)
    if context_error:
        with pytest.raises(KeyboardInterrupt):
            with result as entered:
                assert entered is result
                raise KeyboardInterrupt
    else:
        with result:
            assert flow.streams[0].fd >= 0
    result.close()
    assert result._socket is None and flow.streams[0].closed == 1
    with pytest.raises(ValueError, match="^TLS connection is closed$"):
        result.__enter__()


def test_close_os_error_is_not_retried(flow: Flow) -> None:
    result = flow.connect()
    assert isinstance(result, cn._TlsConnection)
    flow.streams[0].close_fault = OSError(DIAGNOSTIC)
    result.close()
    result.close()
    assert result._socket is None and flow.streams[0].closed == 1


@pytest.mark.parametrize(
    "operation",
    [
        "state",
        "reduce",
        "pickle",
        "copy",
        "deepcopy",
        "json",
        "asdict",
        "vars",
        "set",
        "delete",
    ],
)
def test_holder_safe_surfaces(flow: Flow, operation: str) -> None:
    result = flow.connect()
    assert isinstance(result, cn._TlsConnection)
    assert str(result) == repr(result) == "<TLS connection: redacted>"
    assert not dataclasses.is_dataclass(result)
    actions: dict[str, Callable[[], object]] = {
        "state": result.__getstate__,
        "reduce": result.__reduce__,
        "pickle": lambda: pickle.dumps(result),
        "copy": lambda: copy.copy(result),
        "deepcopy": lambda: copy.deepcopy(result),
        "json": lambda: json.dumps(result),
        "asdict": lambda: dataclasses.asdict(result),  # type: ignore[call-overload]
        "vars": lambda: vars(result),
        "set": lambda: setattr(result, "_socket", None),
        "delete": lambda: delattr(result, "_socket"),
    }
    try:
        with pytest.raises((TypeError, AttributeError)):
            actions[operation]()
    finally:
        result.close()


@pytest.mark.parametrize("tcp_after", [False, True])
def test_exhausted_tls_transport_candidates_are_connection_failure(
    flow: Flow, tcp_after: bool
) -> None:
    flow.configure_ssl = lambda stream, index: setattr(
        stream, "steps", [ssl.SSLEOFError(DIAGNOSTIC)]
    )
    if tcp_after:
        flow.configure_raw = lambda raw, index: setattr(
            raw, "code", errno.ECONNREFUSED if index else 0
        )
    assert flow.connect(addresses=("127.0.0.1", "::1")) is F.CONNECTION_FAILED
    assert len(flow.attempts) == 2
