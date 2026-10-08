"""Bounded synthetic Varlink parsing and local-IPC fault injection only."""

import copy
import dataclasses
import errno
import ipaddress
import json
import os
import pickle
import selectors
import socket
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Self, cast

import pytest

from openkube_optimizer.collection import preflight as pf
from openkube_optimizer.collection import resolver as rs
from openkube_optimizer.collection.kubeconfig import _Failure as F

CANARY = "raw-resolver-hostname-diagnostic-canary"


def values(*items: object) -> tuple[object, ...]:
    return items


def record(address: str, ifindex: int | None = None) -> dict[str, object]:
    ip = ipaddress.ip_address(address)
    result: dict[str, object] = {
        "family": 2 if ip.version == 4 else 10,
        "address": list(ip.packed),
    }
    if ifindex is not None:
        result["ifindex"] = ifindex
    return result


def reply(records: Sequence[object]) -> bytes:
    return encode({"parameters": {"addresses": records, "name": CANARY, "flags": 1}})


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\0"


def endpoint(hostname: str = "API.Example.invalid") -> pf._Preflight:
    return pf._Preflight(
        hostname=hostname,
        port=6443,
        authority=hostname + ":6443",
        base_path="/fixed",
        ca_path=Path("/synthetic-unused-ca"),
        auth=pf._BearerToken(token="unused-token-canary"),
    )


@pytest.mark.parametrize(
    "addresses",
    [
        ["192.0.2.9"],
        ["192.0.2.9", "192.0.2.1"],
        ["2001:db8::9"],
        ["2001:db8::9", "2001:db8::1"],
        ["2001:db8::9", "192.0.2.1"],
        ["192.0.2.9", "2001:db8::1", "192.0.2.9", "2001:db8::2"],
        ["10.1.2.3", "127.0.0.1", "169.254.1.2", "::1", "fc00::1"],
        ["::ffff:192.0.2.1", "192.0.2.1"],
        ["0.0.0.0", "::", "224.0.0.1", "ff02::1"],
    ],
)
def test_families_order_and_exact_dedup(addresses: list[str]) -> None:
    result = rs._parse_reply(reply([record(ip) for ip in addresses]))
    assert isinstance(result, rs._Resolution)
    expected = list(dict.fromkeys(addresses))
    assert [str(ipaddress.ip_address(a.packed)) for a in result.addresses] == expected
    assert [a.family for a in result.addresses] == [
        2 if ipaddress.ip_address(a).version == 4 else 10 for a in expected
    ]
    assert all(a.ifindex is None for a in result.addresses)


def test_scope_preservation_does_not_collapse_distinct_interfaces() -> None:
    items = [
        record("fe80::1", 2),
        record("fe80::1", 3),
        record("fe80::1", 2),
        record("2001:db8::1", 2),
        record("2001:db8::1", 3),
        record("192.0.2.1", 2),
        record("192.0.2.1", 3),
    ]
    result = rs._parse_reply(reply(items))
    assert isinstance(result, rs._Resolution)
    assert [(a.packed, a.ifindex) for a in result.addresses] == [
        (ipaddress.ip_address(ip).packed, index)
        for ip, index in (
            ("fe80::1", 2),
            ("fe80::1", 3),
            ("2001:db8::1", 2),
            ("2001:db8::1", 3),
            ("192.0.2.1", 2),
            ("192.0.2.1", 3),
        )
    ]


@pytest.mark.parametrize("index", [None, 1, 2147483647])
def test_nullable_and_bounded_ifindex(index: int | None) -> None:
    item = record("2001:db8::1")
    item["ifindex"] = index
    result = rs._parse_reply(reply([item]))
    assert isinstance(result, rs._Resolution)
    assert result.addresses[0].ifindex == index


@pytest.mark.parametrize("count", [0, 1, 64, 65])
@pytest.mark.parametrize("duplicates", [False, True])
def test_raw_record_limit(count: int, duplicates: bool) -> None:
    items = [record(f"192.0.2.{1 if duplicates else n + 1}") for n in range(count)]
    result = rs._parse_reply(reply(items))
    if count == 0:
        assert result is F.RESOLUTION_EMPTY
    elif count > 64:
        assert result is F.RESOLUTION_TOO_MANY_RESULTS
    else:
        assert isinstance(result, rs._Resolution)
        assert len(result.addresses) == (1 if duplicates else count)


def test_candidate_limit_negative_canary(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = reply([record("192.0.2.1")] * 65)
    assert rs._parse_reply(wire) is F.RESOLUTION_TOO_MANY_RESULTS
    monkeypatch.setattr(rs, "_MAX_ADDRESSES", 65)
    with pytest.raises(AssertionError):
        assert rs._parse_reply(wire) is F.RESOLUTION_TOO_MANY_RESULTS


@pytest.mark.parametrize(
    "item",
    [
        None,
        False,
        1,
        "address",
        [],
        {},
        {"family": 2},
        {"address": [1, 2, 3, 4]},
        {"family": True, "address": [1, 2, 3, 4]},
        *[
            {"family": f, "address": [1, 2, 3, 4]}
            for f in values(0, 1, 3, "2", 2.0, None, [], {})
        ],
        *[
            {"family": 2, "address": a}
            for a in values(
                None,
                True,
                "1234",
                {},
                [],
                [1],
                [1] * 5,
                [1, 2, 3, True],
                [1, 2, 3, 256],
                [1, 2, 3, -1],
                [1, 2, 3, "4"],
                [1, 2, 3, 4.0],
            )
        ],
        {"family": 10, "address": [0] * 4},
        {"family": 2, "address": [0] * 16},
        *[
            dict(record("2001:db8::1"), ifindex=i)
            for i in values(0, -1, 2147483648, True, "2", 2.0, [], {})
        ],
        record("fe80::1"),
    ],
)
def test_invalid_address_record(item: object) -> None:
    assert rs._parse_reply(reply([item])) is F.RESOLUTION_INVALID


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        True,
        1,
        "reply",
        {},
        {"parameters": None},
        {"parameters": []},
        *[
            {"parameters": dict(addresses=[record("192.0.2.1")], name=n, flags=1)}
            for n in values(None, "", True, 1, [], {}, "\ud800")
        ],
        *[
            {"parameters": dict(addresses=[record("192.0.2.1")], name=CANARY, flags=f)}
            for f in values(None, True, 1.0, "1", [], {}, -1, 18446744073709551616)
        ],
        *[
            {"parameters": dict(addresses=a, name=CANARY, flags=1)}
            for a in values(None, True, 1, {}, "records")
        ],
        {"parameters": {"addresses": [record("192.0.2.1")], "flags": 1}},
        {"parameters": {"addresses": [record("192.0.2.1")], "name": CANARY}},
        {"parameters": {"name": CANARY, "flags": 1}},
        *[{"continues": c} for c in values(True, None, 0, "false", [], {})],
        {"error": None},
        {"error": True},
        {"error": "unexpected.raw.diagnostic"},
        {"error": "io.systemd.Resolve.DNSError", "parameters": []},
    ],
)
def test_invalid_container_and_required_metadata(value: object) -> None:
    assert rs._parse_reply(encode(value)) is F.RESOLUTION_INVALID


@pytest.mark.parametrize("error", sorted(rs._ERRORS))
def test_typed_resolver_errors_are_sanitized(error: str) -> None:
    result = rs._parse_reply(
        encode({"error": error, "parameters": {"diagnostic": CANARY}})
    )
    assert result is F.RESOLUTION_FAILED
    assert CANARY not in repr(result) and error not in repr(result)


@pytest.mark.parametrize("parameters", [None, {}, {"parameter": CANARY}])
def test_typed_interface_failure(parameters: object) -> None:
    assert (
        rs._parse_reply(
            encode(
                {
                    "error": "org.varlink.service.InvalidParameter",
                    "parameters": parameters,
                }
            )
        )
        is F.RESOLVER_UNAVAILABLE
    )


@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"\0",
        b"{}",
        b"{\0",
        b"[]\0",
        b"\xff\0",
        b"{}\0{}\0",
        b"{} garbage\0",
        b'{"parameters":{},"parameters":{}}\0',
        b'{"error":"io.systemd.Resolve.DNSError","error":"canary"}\0',
        b'{"parameters":{"name":"a","name":"b"}}\0',
        b'{"parameters":{"addresses":[{"family":2,"family":10}]}}\0',
        *[
            b'{"ignored":' + value + b"}\0"
            for value in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"9" * 21)
        ],
        b'{"x":[}\0',
    ],
)
def test_wire_and_duplicate_json_rejections(wire: bytes) -> None:
    assert rs._parse_reply(wire) is F.RESOLUTION_INVALID


@pytest.mark.parametrize("depth", [32, 33])
def test_depth_is_checked_before_tree_construction(
    monkeypatch: pytest.MonkeyPatch,
    depth: int,
) -> None:
    parameters = '{"addresses":[],"name":"canary","flags":1}'
    text = (
        '{"parameters":'
        + parameters
        + ',"unused":'
        + "[" * (depth - 1)
        + "0"
        + "]" * (depth - 1)
        + "}"
    )
    original = json.loads
    calls: list[int] = []

    def observe(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(json, "loads", observe)
    result = rs._parse_reply(text.encode() + b"\0")
    assert result is (F.RESOLUTION_EMPTY if depth == 32 else F.RESOLUTION_INVALID)
    assert calls == ([1] if depth == 32 else [])


def test_depth_scan_handles_quotes_escapes_and_unknown_bounded_metadata() -> None:
    value = json.loads(reply([record("192.0.2.1")])[:-1])
    value["ignored"] = {"text": '[\\"' + "[" * 100 + "]", "value": 1.5}
    assert isinstance(rs._parse_reply(encode(value)), rs._Resolution)


@pytest.mark.parametrize("extra", [0, 1])
def test_reply_byte_bound_before_json(
    monkeypatch: pytest.MonkeyPatch,
    extra: int,
) -> None:
    base = reply([record("192.0.2.1")])
    wire = base[:-1] + b" " * (65536 + extra - len(base)) + b"\0"
    original = json.loads
    calls: list[int] = []

    def observe(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(json, "loads", observe)
    result = rs._parse_reply(wire)
    assert (
        isinstance(result, rs._Resolution)
        if extra == 0
        else result is F.RESOLUTION_TOO_LARGE
    )
    assert calls == ([1] if extra == 0 else [])


@pytest.mark.parametrize("extra", [0, 1])
def test_request_byte_bound(monkeypatch: pytest.MonkeyPatch, extra: int) -> None:
    monkeypatch.setattr(json, "dumps", lambda *a, **kw: "x" * (1023 + extra))
    if extra:
        with pytest.raises(ValueError, match="^Invalid internal resolver request$"):
            rs._request("already.validated")
    else:
        assert len(rs._request("already.validated")) == 1024


@pytest.mark.parametrize(
    "hostname",
    [
        "API.Example.invalid",
        "a.b",
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61,
    ],
)
def test_request_preserves_original_hostname(hostname: str) -> None:
    wire = rs._request(hostname)
    assert len(wire) <= 1024
    assert json.loads(wire[:-1]) == {
        "method": "io.systemd.Resolve.ResolveHostname",
        "parameters": {"name": hostname, "family": 0, "flags": 256},
    }


@pytest.mark.parametrize(
    "hostname",
    ["singlelabel", "127.0.0.1", "::1", "api.example.", "xn--idn.example", "é.example"],
)
def test_preflight_rejects_unsupported_names_before_resolution(hostname: str) -> None:
    assert pf._endpoint("https://" + hostname) is F.INVALID_ENDPOINT


@pytest.mark.parametrize(
    "operation",
    [
        "set",
        "delete",
        "state",
        "reduce",
        "pickle",
        "copy",
        "deepcopy",
        "json",
        "asdict",
    ],
)
@pytest.mark.parametrize("holder", ["address", "resolution"])
def test_private_results_reject_mutation_and_serialization(
    operation: str, holder: str
) -> None:
    result = rs._parse_reply(reply([record("192.0.2.1")]))
    assert isinstance(result, rs._Resolution)
    target = result if holder == "resolution" else result.addresses[0]
    assert repr(target) == "<resolver result: redacted>"
    assert not hasattr(target, "__dict__")
    assert not dataclasses.is_dataclass(target)
    actions: dict[str, Callable[[], object]] = {
        "set": lambda: setattr(target, "addresses", ()),
        "delete": lambda: delattr(target, "addresses"),
        "state": target.__getstate__,
        "reduce": target.__reduce__,
        "pickle": lambda: pickle.dumps(target),
        "copy": lambda: copy.copy(target),
        "deepcopy": lambda: copy.deepcopy(target),
        "json": lambda: json.dumps(target),
        "asdict": lambda: dataclasses.asdict(target),  # type: ignore[call-overload]
    }
    with pytest.raises((AttributeError, TypeError)):
        actions[operation]()


class FakeSocket:
    def __init__(self) -> None:
        self.closed = False
        self.nonblocking = False
        self.code = 0
        self.error = 0
        self.peer = (123, 992, 992)
        self.chunks: list[bytes | BaseException] = [reply([record("192.0.2.1")])]
        self.sent = bytearray()
        self.connects: list[str] = []
        self.send_size = 4096
        self.send_fault: BaseException | None = None
        self.recv_sizes: list[int] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def setblocking(self, value: bool) -> None:
        assert value is False
        self.nonblocking = True

    def connect_ex(self, path: str) -> int:
        assert path == "/run/systemd/resolve/io.systemd.Resolve"
        self.connects.append(path)
        return self.code

    def getsockopt(self, level: int, option: int, *args: object) -> int | bytes:
        assert level == socket.SOL_SOCKET
        return (
            self.error if option == socket.SO_ERROR else struct.pack("3i", *self.peer)
        )

    def send(self, data: memoryview) -> int:
        if self.send_fault is not None:
            fault, self.send_fault = self.send_fault, None
            raise fault
        count = min(len(data), self.send_size)
        self.sent.extend(data[:count])
        return count

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class FakeSelector:
    def __init__(self) -> None:
        self.closed = False
        self.ready = True
        self.timeouts: list[float | None] = []
        self.advance: Callable[[], None] = lambda: None
        self.fault: BaseException | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def register(self, sock: FakeSocket, events: int) -> None:
        assert events == selectors.EVENT_WRITE

    def modify(self, sock: FakeSocket, events: int) -> None:
        assert events == selectors.EVENT_READ

    def select(self, timeout: float | None) -> list[object]:
        self.timeouts.append(timeout)
        self.advance()
        if self.fault is not None:
            raise self.fault
        return [object()] if self.ready else []


@pytest.fixture
def ipc(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[FakeSocket, FakeSelector]]:
    sock, selector = FakeSocket(), FakeSelector()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(time, "monotonic", lambda: 100.0)

    def create(family: int, kind: int) -> FakeSocket:
        assert (family, kind) == (socket.AF_UNIX, socket.SOCK_STREAM)
        return sock

    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(selectors, "DefaultSelector", lambda: selector)

    def info(path: str) -> os.stat_result:
        assert path in (*rs._PARENTS, rs._SOCKET_PATH)
        index = (*rs._PARENTS, rs._SOCKET_PATH).index(path)
        return cast(
            os.stat_result,
            SimpleNamespace(
                st_dev=1,
                st_ino=index + 1,
                st_mode=(stat.S_IFSOCK | 0o666) if index == 4 else stat.S_IFDIR | 0o755,
                st_uid=992 if index >= 3 else 0,
                st_gid=992 if index >= 3 else 0,
                st_ctime_ns=1,
            ),
        )

    monkeypatch.setattr(os, "lstat", info)
    yield sock, selector
    if sock.connects:
        assert sock.closed
    if selector.timeouts:
        assert selector.closed


def test_one_local_call_keeps_logical_authority(
    ipc: tuple[FakeSocket, FakeSelector],
) -> None:
    sock, _ = ipc
    original = endpoint()
    result = rs._resolve(original, deadline=101)
    assert isinstance(result, rs._Resolution)
    assert original.hostname == "API.Example.invalid"
    assert original.authority == "API.Example.invalid:6443"
    assert json.loads(sock.sent[:-1])["parameters"]["name"] == original.hostname
    assert sock.connects == [rs._SOCKET_PATH]
    assert sock.nonblocking and sock.closed
    assert not hasattr(result, "hostname")


@pytest.mark.parametrize(
    "code", [errno.ENOENT, errno.ECONNREFUSED, errno.EAGAIN, errno.EINTR, errno.EACCES]
)
def test_connect_failure_has_no_retry(
    ipc: tuple[FakeSocket, FakeSelector], code: int
) -> None:
    sock, _ = ipc
    sock.code = code
    assert rs._resolve(endpoint(), deadline=101) is F.RESOLVER_UNAVAILABLE
    assert len(sock.connects) == 1 and not sock.sent


def test_in_progress_connect(ipc: tuple[FakeSocket, FakeSelector]) -> None:
    ipc[0].code = errno.EINPROGRESS
    assert isinstance(rs._resolve(endpoint(), deadline=101), rs._Resolution)


@pytest.mark.parametrize("peer", [(0, 992, 992), (1, 1000, 992), (1, 992, 1000)])
def test_peer_credentials_rejected_before_send(
    ipc: tuple[FakeSocket, FakeSelector], peer: tuple[int, int, int]
) -> None:
    ipc[0].peer = peer
    assert rs._resolve(endpoint(), deadline=101) is F.RESOLVER_UNAVAILABLE
    assert not ipc[0].sent


@pytest.mark.parametrize(
    "fault", ["owner", "gid", "writable", "symlink", "file", "replacement", "missing"]
)
@pytest.mark.parametrize(
    "path", ["/", "/run", "/run/systemd", "/run/systemd/resolve", rs._SOCKET_PATH]
)
def test_trust_and_replacement_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    ipc: tuple[FakeSocket, FakeSelector],
    path: str,
    fault: str,
) -> None:
    original = os.lstat
    calls = 0

    def info(value: str) -> os.stat_result:
        nonlocal calls
        data = original(value)
        if value != path:
            return data
        calls += 1
        if fault == "missing":
            raise FileNotFoundError(CANARY)
        fields = {
            name: getattr(data, name)
            for name in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_ctime_ns",
            )
        }
        if fault == "owner":
            fields["st_uid"] = 1000
        if fault == "gid":
            fields["st_gid"] = 1000
        if fault == "writable":
            fields["st_mode"] |= 0o022
        if fault == "symlink":
            fields["st_mode"] = stat.S_IFLNK | 0o777
        if fault == "file":
            fields["st_mode"] = stat.S_IFREG | 0o644
        if fault == "replacement" and calls > 1:
            fields["st_ino"] += 1
        return cast(os.stat_result, SimpleNamespace(**fields))

    monkeypatch.setattr(os, "lstat", info)
    result = rs._resolve(endpoint(), deadline=101)
    # Root-owned ancestor group metadata is not authority; socket permissions
    # grant connecting, whereas parent write permissions grant replacement.
    if (fault == "gid" and path in rs._PARENTS[:3]) or (
        fault == "writable" and path == rs._SOCKET_PATH
    ):
        assert isinstance(result, rs._Resolution)
    else:
        assert result is F.RESOLVER_UNAVAILABLE
        assert not ipc[0].sent


@pytest.mark.parametrize("stage", ["select", "send", "recv"])
@pytest.mark.parametrize("exception", [KeyboardInterrupt, RuntimeError, OSError])
def test_fault_and_cancellation_cleanup(
    ipc: tuple[FakeSocket, FakeSelector],
    stage: str,
    exception: type[BaseException],
) -> None:
    sock, selector = ipc
    fault = exception(CANARY)
    if stage == "select":
        selector.fault = fault
    if stage == "send":
        sock.send_fault = fault
    if stage == "recv":
        sock.chunks = [fault]
    if exception is OSError:
        assert rs._resolve(endpoint(), deadline=101) is F.RESOLVER_UNAVAILABLE
    else:
        with pytest.raises(exception):
            rs._resolve(endpoint(), deadline=101)
    assert sock.closed and selector.closed


@pytest.mark.parametrize(
    "fault", ["empty", "invalid", "large", "many", "send-zero", "socket-error"]
)
def test_io_response_failures(ipc: tuple[FakeSocket, FakeSelector], fault: str) -> None:
    sock, _ = ipc
    expected = F.RESOLUTION_FAILED
    if fault == "empty":
        sock.chunks = []
    if fault == "invalid":
        sock.chunks = [b"{broken\0"]
        expected = F.RESOLUTION_INVALID
    if fault == "large":
        sock.chunks = [b"x" * 65537]
        expected = F.RESOLUTION_TOO_LARGE
    if fault == "many":
        sock.chunks = [reply([record("192.0.2.1")] * 65)]
        expected = F.RESOLUTION_TOO_MANY_RESULTS
    if fault == "send-zero":
        sock.send_size = 0
    if fault == "socket-error":
        sock.error = errno.ECONNREFUSED
        expected = F.RESOLVER_UNAVAILABLE
    assert rs._resolve(endpoint(), deadline=101) is expected
    assert all(0 < size <= 4096 for size in sock.recv_sizes)


def test_partial_and_would_block_io(ipc: tuple[FakeSocket, FakeSelector]) -> None:
    sock, _ = ipc
    wire = reply([record("192.0.2.1")])
    sock.send_size = 7
    sock.send_fault = BlockingIOError()
    sock.chunks = [BlockingIOError(), wire[:10], BlockingIOError(), wire[10:]]
    assert isinstance(rs._resolve(endpoint(), deadline=101), rs._Resolution)
    assert bytes(sock.sent) == rs._request(endpoint().hostname)


@pytest.mark.parametrize(
    "deadline", [99.0, 100.0, float("nan"), float("inf"), float("-inf")]
)
def test_expired_or_nonfinite_deadline_opens_nothing(
    ipc: tuple[FakeSocket, FakeSelector], deadline: float
) -> None:
    assert rs._resolve(endpoint(), deadline=deadline) is F.RESOLUTION_TIMEOUT
    assert not ipc[0].connects


def test_slow_progress_never_resets_absolute_deadline(
    ipc: tuple[FakeSocket, FakeSelector], monkeypatch: pytest.MonkeyPatch
) -> None:
    sock, selector = ipc
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    selector.advance = lambda: clock.__setitem__(0, clock[0] + 0.2)
    sock.send_size = 1
    assert rs._resolve(endpoint(), deadline=101) is F.RESOLUTION_TIMEOUT
    assert all(a > b for a, b in zip(selector.timeouts, selector.timeouts[1:]))  # type: ignore[operator]
    assert len(sock.connects) == 1 and sock.closed


def test_wait_timeout_closes_ipc(ipc: tuple[FakeSocket, FakeSelector]) -> None:
    ipc[1].ready = False
    assert rs._resolve(endpoint(), deadline=101) is F.RESOLUTION_TIMEOUT
    assert not ipc[0].sent


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_unsupported_profile_has_no_io(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(sys, "platform", platform)

    def deny(*args: object, **kwargs: object) -> None:
        pytest.fail("Unsupported profile performed I/O")

    monkeypatch.setattr(os, "lstat", deny)
    monkeypatch.setattr(socket, "socket", deny)
    assert rs._resolve(endpoint(), deadline=100) is F.RESOLVER_UNAVAILABLE
