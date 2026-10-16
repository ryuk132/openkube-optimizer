"""Bounded real h11 framing over synthetic SSL I/O and injected clocks."""

import copy
import dataclasses
import json
import pickle
import selectors
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Never, Self, cast

import h11
import pytest

from openkube_optimizer.collection import connection as cn
from openkube_optimizer.collection import http as ht
from openkube_optimizer.collection import preflight as pf
from openkube_optimizer.collection.kubeconfig import _Failure as F

CANARY = "body-token-header-native-diagnostic-canary"
PATH = "/api/v1/namespaces/synthetic/pods"


def endpoint(
    server: str = "https://API.Http-Canary.invalid:38443/proxy/",
) -> pf._Preflight:
    values = pf._endpoint(server)
    assert isinstance(values, tuple)
    return pf._Preflight(
        hostname=values[0],
        port=values[1],
        authority=values[2],
        base_path=values[3],
        ca_path=Path("/unused-credential-canary"),
        auth=pf._BearerToken(token=CANARY),
    )


def length(body: bytes = b"synthetic") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )


class Stream:
    def __init__(self, flow: "Flow") -> None:
        self.flow = flow
        self.fd = 101
        self.sent = bytearray()
        self.response = length()
        self.offset = 0
        self.send_steps: list[int | BaseException] = []
        self.recv_steps: list[bytes | BaseException] = []
        self.send_delay = 0.0
        self.recv_delay = 0.0
        self.read_size = 8192
        self.sends = 0
        self.reads = 0
        self.close_count = 0

    def send(self, data: memoryview) -> int:
        self.sends += 1
        self.flow.now += self.send_delay
        step = self.send_steps.pop(0) if self.send_steps else len(data)
        if isinstance(step, BaseException):
            raise step
        count = min(step, len(data))
        self.sent.extend(data[:count])
        return count

    def recv(self, size: int) -> bytes:
        assert 0 < size <= ht._IO_CHUNK_BYTES
        self.reads += 1
        self.flow.now += self.recv_delay
        if self.recv_steps:
            step = self.recv_steps.pop(0)
            if isinstance(step, BaseException):
                raise step
            assert len(step) <= size
            return step
        data = self.response[self.offset : self.offset + min(size, self.read_size)]
        self.offset += len(data)
        return data

    def close(self) -> None:
        assert self.fd >= 0, "SSL owner double closed"
        self.close_count += 1
        self.fd = -1


class Selector:
    def __init__(self, flow: "Flow") -> None:
        self.flow = flow
        self.closed = False
        self.events = 0
        flow.selectors.append(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def register(self, stream: Stream, events: int) -> None:
        assert stream is self.flow.stream
        self.events = events

    def select(self, timeout: float | None) -> list[object]:
        assert timeout is not None and 0 < timeout <= self.flow.deadline - self.flow.now
        self.flow.waits.append((self.events, timeout))
        self.flow.now += self.flow.wait_delay if self.flow.ready else timeout
        return [object()] if self.flow.ready else []


class Flow:
    def __init__(self) -> None:
        self.now = 100.0
        self.deadline = 115.0
        self.wait_delay = 0.0
        self.ready = True
        self.waits: list[tuple[int, float]] = []
        self.selectors: list[Selector] = []
        self.stream = Stream(self)
        self.connection = cn._TlsConnection(cast(ssl.SSLSocket, self.stream))

    def exchange(
        self,
        request: ht._HttpRequest | None = None,
        server: str = "https://API.Http-Canary.invalid:38443/proxy/",
    ) -> ht._HttpResponse | F:
        return ht._exchange(
            endpoint(server),
            self.connection,
            request or ht._HttpRequest(path=PATH),
            deadline=self.deadline,
        )


@pytest.fixture
def flow(monkeypatch: pytest.MonkeyPatch) -> Iterator[Flow]:
    value = Flow()
    monkeypatch.setattr(time, "monotonic", lambda: value.now)
    monkeypatch.setattr(selectors, "DefaultSelector", lambda: Selector(value))
    yield value
    assert value.connection._socket is None
    assert value.stream.close_count == 1
    assert all(s.closed for s in value.selectors)


@pytest.mark.parametrize("prefix", ["", "/", "/proxy", "/proxy/", "/proxy/API"])
@pytest.mark.parametrize(
    "authority",
    [
        "API.Http-Canary.invalid",
        "API.Http-Canary.invalid:443",
        "API.Http-Canary.invalid:0008443",
    ],
)
def test_get_host_prefix_query_and_controlled_headers(
    flow: Flow, prefix: str, authority: str
) -> None:
    request = ht._HttpRequest(
        path=PATH,
        query=(("limit", "200"), ("continue", "opaque+/=%&#?")),
        headers=(
            ("Authorization", "Bearer " + CANARY + "~+/%="),
            ("User-Agent", "synthetic test"),
        ),
    )
    result = flow.exchange(request, "https://" + authority + prefix)
    assert (
        isinstance(result, ht._HttpResponse)
        and result.status == 200
        and result.body == b"synthetic"
    )
    expected = prefix + (PATH[1:] if prefix.endswith("/") else PATH)
    assert flow.stream.sent.startswith(
        b"GET "
        + expected.encode()
        + b"?limit=200&continue=opaque%2B%2F%3D%25%26%23%3F HTTP/1.1\r\n"
    )
    assert b"Host: " + authority.encode() + b"\r\n" in flow.stream.sent
    assert (
        b"Authorization: Bearer " + CANARY.encode() + b"~+/%=\r\n" in flow.stream.sent
    )
    assert b"Accept: application/json\r\n" in flow.stream.sent
    assert b"Connection: close\r\n" in flow.stream.sent
    assert (
        b"127.0.0.1" not in flow.stream.sent
        and b"Accept-Encoding" not in flow.stream.sent
    )
    peer = h11.Connection(h11.SERVER)
    peer.receive_data(bytes(flow.stream.sent))
    assert isinstance(peer.next_event(), h11.Request)
    assert isinstance(peer.next_event(), h11.EndOfMessage)
    assert peer.next_event() is h11.NEED_DATA


@pytest.mark.parametrize(
    "path",
    [
        "",
        "relative",
        "https://host.invalid/a",
        "//host.invalid/a",
        "/a//b",
        "/a/../b",
        "/a/./b",
        "/%2f",
        "/%2E%2E",
        "/a?x=1",
        "/a#f",
        "/a\\b",
        "/a\r\nGET",
        "/é",
        "/" + "a" * 16384,
    ],
)
def test_rejected_targets_send_nothing(flow: Flow, path: str) -> None:
    assert flow.exchange(ht._HttpRequest(path=path)) is F.HTTP_REQUEST_INVALID
    assert not flow.stream.sent


@pytest.mark.parametrize(
    "headers",
    [
        (("Host", "other.invalid"),),
        (("Connection", "keep-alive"),),
        (("Content-Length", "1"),),
        (("Accept-Encoding", "gzip"),),
        (("Accept\r\nHost", "x"),),
        ((" Accept", "x"),),
        (("Accept", "x\r\nHost: y"),),
        (("Accept", "x\0"),),
        (("Accept", "é"),),
        (("Accept", " x"),),
        (("Accept", "x "),),
        (("Accept", ""),),
        (("Authorization", "Bearer "),),
        (("Authorization", "Bearer x y"),),
        (("Authorization", "Basic x"),),
        (("Accept", "x"), ("accept", "x")),
        (("Accept", "x"), ("Accept", "x")),
        (("Accept", "x" * 16384),),
    ],
)
def test_header_envelope_rejects_unsafe_or_uncontrolled_inputs(
    flow: Flow, headers: tuple[tuple[str, str], ...]
) -> None:
    assert (
        flow.exchange(ht._HttpRequest(path=PATH, headers=headers))
        is F.HTTP_REQUEST_INVALID
    )
    assert not flow.stream.sent


@pytest.mark.parametrize(
    "query",
    [
        (("x", "a\n"),),
        (("x", "é"),),
        (("a&b", "c"),),
        (("x", "1"), ("x", "2")),
        (("x", "%" * 6000),),
        tuple((f"x{n}", "v") for n in range(129)),
    ],
)
def test_query_envelope_and_escaping_bounds(
    flow: Flow, query: tuple[tuple[str, str], ...]
) -> None:
    assert (
        flow.exchange(ht._HttpRequest(path=PATH, query=query)) is F.HTTP_REQUEST_INVALID
    )
    assert not flow.stream.sent


@pytest.mark.parametrize("over", [False, True])
def test_request_metadata_exact_boundary(flow: Flow, over: bool) -> None:
    empty = ht._HttpRequest(path=PATH, headers=(("User-Agent", "x"),))
    target, headers = ht._request_parts(endpoint(), empty)
    size = (
        len(b"GET  HTTP/1.1\r\n\r\n")
        + len(target)
        + sum(len(n) + len(v) + 4 for n, v in headers)
    )
    value = "x" * (ht._MAX_METADATA_BYTES - size + 1 + int(over))
    result = flow.exchange(ht._HttpRequest(path=PATH, headers=(("User-Agent", value),)))
    if over:
        assert result is F.HTTP_REQUEST_INVALID and not flow.stream.sent
    else:
        assert isinstance(result, ht._HttpResponse) and len(flow.stream.sent) == 16384


@pytest.mark.parametrize(
    "status", [200, 201, 204, 304, 302, 400, 401, 403, 429, 500, 503, 999]
)
def test_status_is_framing_only_no_retry_or_redirect(flow: Flow, status: int) -> None:
    flow.stream.response = f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 0\r\nLocation: https://redirect.invalid/\r\nRetry-After: 1\r\nDate: ignored\r\n\r\n".encode()
    result = flow.exchange()
    assert (
        isinstance(result, ht._HttpResponse)
        and result.status == status
        and result.body == b""
    )
    assert flow.stream.sent.count(b"GET ") == 1
    assert not hasattr(result, "headers") and not hasattr(result, "connection")


@pytest.mark.parametrize("read_size", [1, 7, 8192])
@pytest.mark.parametrize(
    "wire,body",
    [
        (length(b"abc"), b"abc"),
        (b"HTTP/1.0 200 OK\r\n\r\nabc", b"abc"),
        (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc", b"abc"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=y\r\na\r\n2\r\nbc\r\n0\r\nX-Trailer: ignored\r\n\r\n",
            b"abc",
        ),
        (
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: ignored\r\n\r\n"
            + length(b"abc"),
            b"abc",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\nContent-Type: application/json\r\n\r\nabc",
            b"abc",
        ),
    ],
)
def test_pinned_h11_events_across_fragmentation(
    flow: Flow, read_size: int, wire: bytes, body: bytes
) -> None:
    flow.stream.response = wire
    flow.stream.read_size = read_size
    result = flow.exchange()
    assert isinstance(result, ht._HttpResponse) and result.body == body


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 bad status\r\n\r\n",
        b"HTTP/1.1 099 Invalid\r\n\r\n",
        b"junk\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: bad\0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: synthetic\r\n\r\n",
        b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: identity\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n",
        length(b"") + b"unsolicited-extra-response-canary",
    ],
)
def test_malformed_incomplete_or_unsupported_response_is_fixed(
    flow: Flow, wire: bytes
) -> None:
    flow.stream.response = wire
    assert flow.exchange() is F.HTTP_RESPONSE_INVALID


def test_peer_eof_before_response_is_closed(flow: Flow) -> None:
    flow.stream.response = b""
    assert flow.exchange() is F.HTTP_CONNECTION_CLOSED


@pytest.mark.parametrize("trailer", [False, True])
@pytest.mark.parametrize("over", [False, True])
def test_response_metadata_aggregate_exact_bound(
    flow: Flow, trailer: bool, over: bool
) -> None:
    interim = b"HTTP/1.1 103 Early Hints\r\nX: a\r\n\r\n"
    if trailer:
        initial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        suffix = b"X: \r\n\r\n"
        padding = b"a" * (16384 - len(interim) - len(initial) - len(suffix) + int(over))
        flow.stream.response = (
            interim + initial + b"1\r\nx\r\n0\r\nX: " + padding + b"\r\n\r\n"
        )
    else:
        initial = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: \r\n\r\n"
        padding = b"a" * (16384 - len(interim) - len(initial) + int(over))
        flow.stream.response = interim + initial.replace(
            b"X: \r\n", b"X: " + padding + b"\r\n"
        )
    result = flow.exchange()
    assert (
        result is F.HTTP_RESPONSE_TOO_LARGE
        if over
        else isinstance(result, ht._HttpResponse)
    )


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("duplicates", [False, True])
def test_response_header_count_includes_raw_duplicates(
    flow: Flow, over: bool, duplicates: bool
) -> None:
    header = b"Content-Length: 0\r\n" if duplicates else b"X: a\r\n"
    fields = header * (128 + int(over) - (0 if duplicates else 1))
    flow.stream.response = (
        b"HTTP/1.1 200 OK\r\n"
        + fields
        + (b"" if duplicates else b"Content-Length: 0\r\n")
        + b"\r\n"
    )
    result = flow.exchange()
    assert (
        result is F.HTTP_RESPONSE_TOO_LARGE
        if over
        else isinstance(result, ht._HttpResponse)
    )


@pytest.mark.parametrize("over", [False, True])
def test_real_sixteen_mib_body_boundary(flow: Flow, over: bool) -> None:
    flow.stream.response = length(b"x" * (16 * 1024 * 1024 + int(over)))
    result = flow.exchange()
    if over:
        assert result is F.HTTP_RESPONSE_TOO_LARGE
    else:
        assert (
            isinstance(result, ht._HttpResponse)
            and len(result.body) == 16 * 1024 * 1024
        )


@pytest.mark.parametrize("over", [False, True])
def test_wire_counter_exact_thirtytwo_mib_boundary(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, over: bool
) -> None:
    budget = ht._Budget()
    budget.wire = 32 * 1024 * 1024 - len(flow.stream.response) + int(over)
    monkeypatch.setattr(ht, "_Budget", lambda: budget)
    result = flow.exchange()
    assert (
        result is F.HTTP_RESPONSE_TOO_LARGE
        if over
        else isinstance(result, ht._HttpResponse)
    )
    assert budget.wire <= 32 * 1024 * 1024


@pytest.mark.parametrize("guard", ["metadata", "fields", "body", "wire"])
def test_removing_response_limit_is_detected(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, guard: str
) -> None:
    if guard == "metadata":
        flow.stream.response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: " + b"a" * 16384 + b"\r\n\r\n"
        )
        monkeypatch.setattr(ht, "_MAX_METADATA_BYTES", 32768)
    elif guard == "fields":
        flow.stream.response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + b"X: a\r\n" * 128 + b"\r\n"
        )
        monkeypatch.setattr(ht, "_MAX_HEADER_FIELDS", 256)
    elif guard == "body":
        flow.stream.response = length(b"x" * (ht._MAX_BODY_BYTES + 1))
        monkeypatch.setattr(ht, "_MAX_BODY_BYTES", ht._MAX_BODY_BYTES + 1)
    else:
        budget = ht._Budget()
        budget.wire = ht._MAX_WIRE_BYTES - len(flow.stream.response) + 1
        monkeypatch.setattr(ht, "_Budget", lambda: budget)
        monkeypatch.setattr(ht, "_MAX_WIRE_BYTES", ht._MAX_WIRE_BYTES + 1)
    result = flow.exchange()
    with pytest.raises(AssertionError):
        assert result is F.HTTP_RESPONSE_TOO_LARGE


@pytest.mark.parametrize("phase", ["send", "recv"])
def test_partial_writes_and_tls_wants_use_correct_direction(
    flow: Flow, phase: str
) -> None:
    flow.wait_delay = 1
    if phase == "send":
        flow.stream.send_steps = [
            3,
            ssl.SSLWantReadError(),
            2,
            ssl.SSLWantWriteError(),
            1,
        ]
    else:
        flow.stream.recv_steps = [ssl.SSLWantWriteError(), ssl.SSLWantReadError()]
    result = flow.exchange()
    assert isinstance(result, ht._HttpResponse)
    expected = (
        [selectors.EVENT_READ, selectors.EVENT_WRITE]
        if phase == "send"
        else [selectors.EVENT_WRITE, selectors.EVENT_READ]
    )
    assert flow.waits == [(expected[0], 15), (expected[1], 14)]
    assert flow.stream.sent.count(b"GET ") == 1


@pytest.mark.parametrize("phase", ["send", "recv"])
@pytest.mark.parametrize("kind", [ssl.SSLWantReadError, ssl.SSLWantWriteError])
def test_want_timeout_never_resets_deadline(
    flow: Flow, phase: str, kind: type[ssl.SSLError]
) -> None:
    flow.ready = False
    if phase == "send":
        flow.stream.send_steps = [2, kind()]
    else:
        flow.stream.recv_steps = [kind()]
    assert flow.exchange() is F.TRANSPORT_DEADLINE_EXPIRED
    assert flow.now == flow.deadline and flow.stream.sent.count(b"GET ") <= 1


@pytest.mark.parametrize("deadline", [99.0, 100.0, float("inf"), float("nan")])
def test_expired_entry_sends_nothing(flow: Flow, deadline: float) -> None:
    flow.deadline = deadline
    assert flow.exchange() is F.TRANSPORT_DEADLINE_EXPIRED
    assert not flow.stream.sent and not flow.stream.reads


@pytest.mark.parametrize("phase", ["send", "headers", "body"])
def test_progress_never_extends_deadline(flow: Flow, phase: str) -> None:
    flow.deadline = 101
    if phase == "send":
        flow.stream.send_steps = [2, 2, 2]
        flow.stream.send_delay = 0.6
    else:
        flow.stream.response = length(b"abcd")
        flow.stream.read_size = (
            1 if phase == "headers" else len(flow.stream.response) - 3
        )
        flow.stream.recv_delay = 0.6
    assert flow.exchange() is F.TRANSPORT_DEADLINE_EXPIRED
    assert flow.stream.reads == 0 if phase == "send" else flow.stream.reads == 2


@pytest.mark.parametrize("phase", ["send", "recv", "parts"])
@pytest.mark.parametrize(
    "fault", [KeyboardInterrupt(CANARY), SystemExit(CANARY), RuntimeError(CANARY)]
)
def test_control_and_unexpected_faults_propagate_after_close(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, phase: str, fault: BaseException
) -> None:
    if phase == "send":
        flow.stream.send_steps = [fault]
    elif phase == "recv":
        flow.stream.recv_steps = [fault]
    else:

        def broken(*args: object) -> Never:
            raise fault

        monkeypatch.setattr(ht, "_request_parts", broken)
    with pytest.raises(type(fault)):
        flow.exchange()


@pytest.mark.parametrize("phase", ["send", "recv"])
@pytest.mark.parametrize(
    "fault",
    [
        OSError(CANARY),
        ConnectionResetError(CANARY),
        ssl.SSLEOFError(CANARY),
        ssl.SSLZeroReturnError(CANARY),
        ssl.SSLError(CANARY),
    ],
)
def test_native_io_faults_are_sanitized(
    flow: Flow, phase: str, fault: BaseException
) -> None:
    if phase == "send":
        flow.stream.send_steps = [fault]
    else:
        flow.stream.recv_steps = [fault]
    result = flow.exchange()
    expected = (
        F.HTTP_CONNECTION_CLOSED
        if phase == "recv"
        or isinstance(fault, (ssl.SSLEOFError, ssl.SSLZeroReturnError))
        else F.HTTP_WRITE_FAILED
    )
    assert result is expected and CANARY not in str(result)


def test_zero_send_and_already_closed_holder(flow: Flow) -> None:
    flow.stream.send_steps = [0]
    assert flow.exchange() is F.HTTP_CONNECTION_CLOSED
    assert flow.exchange() is F.HTTP_CONNECTION_CLOSED


@pytest.mark.parametrize(
    "surface",
    [
        "state",
        "reduce",
        "reduce-ex",
        "pickle",
        "copy",
        "deepcopy",
        "vars",
        "asdict",
        "json",
        "set",
        "del",
    ],
)
@pytest.mark.parametrize("response", [False, True])
def test_private_records_block_ordinary_disclosure(
    surface: str, response: bool
) -> None:
    record = (
        ht._HttpResponse(status=200, body=CANARY.encode())
        if response
        else ht._HttpRequest(
            path="/" + CANARY, headers=(("Authorization", "Bearer " + CANARY),)
        )
    )
    assert CANARY not in repr(record) and CANARY not in str(record)
    operations: dict[str, Callable[[], object]] = {
        "state": lambda: record.__getstate__(),
        "reduce": lambda: record.__reduce__(),
        "reduce-ex": lambda: record.__reduce_ex__(4),
        "pickle": lambda: pickle.dumps(record),
        "copy": lambda: copy.copy(record),
        "deepcopy": lambda: copy.deepcopy(record),
        "vars": lambda: vars(record),
        "asdict": lambda: dataclasses.asdict(record),  # type: ignore[call-overload]
        "json": lambda: json.dumps(record),
        "set": lambda: setattr(record, "body", b""),
        "del": lambda: delattr(record, "body"),
    }
    with pytest.raises((TypeError, AttributeError)) as caught:
        operations[surface]()
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("fragmented", [False, True])
def test_chunk_line_guard_applies_before_complete_and_incomplete_extraction(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, over: bool, fragmented: bool
) -> None:
    if not fragmented:
        monkeypatch.setattr(ht, "_IO_CHUNK_BYTES", 32768)
        flow.stream.read_size = 32768
    header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    chunk_line = b"1;x=" + b"a" * (16384 - len(b"1;x=\r\n") + int(over)) + b"\r\n"
    flow.stream.response = header + chunk_line + b"z\r\n0\r\n\r\n"
    result = flow.exchange()
    assert (
        result is F.HTTP_RESPONSE_TOO_LARGE
        if over
        else isinstance(result, ht._HttpResponse)
    )


def test_identity_encoding_has_no_decoder_or_header_retention(flow: Flow) -> None:
    flow.stream.response = b"HTTP/1.1 200 OK\r\nContent-Encoding: IDENTITY\r\nContent-Length: 1\r\nContent-Type: ignored\r\n\r\nx"
    result = flow.exchange()
    assert isinstance(result, ht._HttpResponse) and result.body == b"x"


@pytest.mark.parametrize("failure", [False, True])
def test_parser_releases_buffers_without_waiting_for_cyclic_gc(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    import gc
    import weakref

    original = ht._parser
    observed: list[weakref.ReferenceType[h11.Connection]] = []

    def tracked(budget: ht._Budget) -> h11.Connection:
        parser = original(budget)
        observed.append(weakref.ref(parser))
        return parser

    monkeypatch.setattr(ht, "_parser", tracked)
    if failure:
        flow.stream.response = b"HTTP/1.1 200 OK\r\nX: " + b"a" * 16384
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        result = flow.exchange()
        assert (
            result is F.HTTP_RESPONSE_TOO_LARGE
            if failure
            else isinstance(result, ht._HttpResponse)
        )
        assert len(observed) == 1 and observed[0]() is None
    finally:
        if was_enabled:
            gc.enable()


@pytest.mark.parametrize("status", [300, 302, 404, 429, 500, 599])
@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("coalesced", [False, True])
@pytest.mark.parametrize("interim", [False, True])
def test_non_2xx_stops_at_final_headers(
    flow: Flow,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status: int,
    chunked: bool,
    coalesced: bool,
    interim: bool,
) -> None:
    import weakref

    references: list[weakref.ReferenceType[h11.Connection]] = []
    original = ht._parser

    def observed(budget: ht._Budget) -> h11.Connection:
        parser = original(budget)
        references.append(weakref.ref(parser))
        return parser

    monkeypatch.setattr(ht, "_parser", observed)
    framing = (
        b"Transfer-Encoding: chunked\r\n"
        if chunked
        else b"Content-Length: 999999999999\r\n"
    )
    headers = f"HTTP/1.1 {status} Synthetic\r\n".encode() + framing + b"\r\n"
    body = CANARY.encode()
    if chunked:
        body = hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n"
    first = headers + (body if coalesced else b"")
    if interim:
        first = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n" + first
    forbidden_read = AssertionError("Error body read attempted")
    flow.stream.recv_steps = [first, forbidden_read]
    result = flow.exchange()
    assert isinstance(result, ht._HttpResponse)
    assert result.status == status and result.body == b""
    assert flow.stream.reads == 1 and flow.stream.recv_steps == [forbidden_read]
    assert flow.stream.sent.count(b"GET ") == 1
    assert flow.stream.close_count == 1 and flow.connection._socket is None
    assert not flow.waits
    assert CANARY not in repr(result) + str(result) + caplog.text
    assert all(reference() is None for reference in references)


@pytest.mark.parametrize("chunked", [False, True])
def test_h11_early_close_state_is_single_use(chunked: bool) -> None:
    parser = ht._parser(ht._Budget())
    parser.send(
        h11.Request(
            method=b"GET",
            target=b"/",
            headers=[(b"Host", b"synthetic"), (b"Connection", b"close")],
        )
    )
    parser.send(h11.EndOfMessage())
    framing = (
        b"Transfer-Encoding: chunked" if chunked else b"Content-Length: 999999999999"
    )
    parser.receive_data(b"HTTP/1.1 404 Synthetic\r\n" + framing + b"\r\n\r\n")
    event = parser.next_event()
    assert isinstance(event, h11.Response) and event.status_code == 404
    assert parser.their_state is h11.SEND_BODY
    assert parser.our_state is h11.MUST_CLOSE
    assert parser.next_event() is h11.NEED_DATA
    with pytest.raises(h11.LocalProtocolError):
        parser.start_next_cycle()


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_non_2xx_result_control_flow_closes(
    flow: Flow, monkeypatch: pytest.MonkeyPatch, control: type[BaseException]
) -> None:
    flow.stream.recv_steps = [
        b"HTTP/1.1 404 Synthetic\r\nContent-Length: 999999999\r\n\r\n"
    ]

    def abort(*, status: int, body: bytes) -> Never:
        assert status == 404 and body == b""
        raise control

    monkeypatch.setattr(ht, "_HttpResponse", abort)
    with pytest.raises(control):
        flow.exchange()
    assert flow.stream.reads == 1
    assert flow.connection._socket is None and flow.stream.close_count == 1
