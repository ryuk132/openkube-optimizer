"""Private resolved-v255 boundary: one bounded local call, no candidate connects."""

import errno
import ipaddress
import json
import math
import os
import selectors
import socket
import stat
import struct
import sys
import time
from typing import Never, SupportsIndex

from .kubeconfig import _Failure
from .preflight import _Preflight

_RESOLVER_POLICY_VERSION = "resolved-varlink-v1"
_SOCKET_PATH = "/run/systemd/resolve/io.systemd.Resolve"
_PARENTS = ("/", "/run", "/run/systemd", "/run/systemd/resolve")
_METHOD = "io.systemd.Resolve.ResolveHostname"
_NO_SEARCH = 1 << 8
_MAX_REQUEST_BYTES = 1024
_MAX_RESPONSE_BYTES = 65536
_MAX_ADDRESSES = 64  # Raw records, before deduplication; ADR 0008 D4.
_MAX_JSON_DEPTH = 32
# Linux wire family constants; parser tests remain portable on macOS.
_IPV4 = 2
_IPV6 = 10
_ERRORS = frozenset(
    "io.systemd.Resolve." + name
    for name in (
        "NoNameServers",
        "NoSuchResourceRecord",
        "QueryTimedOut",
        "MaxAttemptsReached",
        "InvalidReply",
        "QueryAborted",
        "DNSSECValidationFailed",
        "NoTrustAnchor",
        "ResourceRecordTypeUnsupported",
        "NetworkDown",
        "NoSource",
        "StubLoop",
        "DNSError",
        "CNAMELoop",
        "BadAddressSize",
    )
)


class _PrivateResult:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Immutable resolver result")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Immutable resolver result")

    def __repr__(self) -> str:
        return "<resolver result: redacted>"

    def __getstate__(self) -> Never:
        raise TypeError("Resolver results cannot be serialized")

    def __reduce__(self) -> Never:
        self.__getstate__()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()


class _ResolvedAddress(_PrivateResult):
    __slots__ = ("family", "packed", "ifindex")
    family: int
    packed: bytes
    ifindex: int | None

    def __init__(self, family: int, packed: bytes, ifindex: int | None) -> None:
        object.__setattr__(self, "family", family)
        object.__setattr__(self, "packed", packed)
        object.__setattr__(self, "ifindex", ifindex)


class _Resolution(_PrivateResult):
    __slots__ = ("addresses",)
    addresses: tuple[_ResolvedAddress, ...]

    def __init__(self, addresses: tuple[_ResolvedAddress, ...]) -> None:
        object.__setattr__(self, "addresses", addresses)


class _InvalidReply(Exception):
    """Internal parser signal, never returned with a traceback/raw tree."""


def _invalid() -> Never:
    raise _InvalidReply


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > 20:
        _invalid()
    return int(text)


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        _invalid()
    return value


def _constant(text: str) -> Never:
    _invalid()


def _check_depth(text: str) -> None:
    # Byte bound precedes decoding; scan container depth BEFORE json builds a tree.
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                _invalid()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _invalid()
    if depth or quoted:
        _invalid()


def _parse_reply(wire: bytes) -> _Resolution | _Failure:
    """Parse one NUL-terminated, byte/depth-bounded transient JSON reply."""
    if len(wire) > _MAX_RESPONSE_BYTES:
        return _Failure.RESOLUTION_TOO_LARGE
    if not wire.endswith(b"\0") or b"\0" in wire[:-1]:
        return _Failure.RESOLUTION_INVALID
    try:
        text = wire[:-1].decode("utf-8", errors="strict")
        _check_depth(text)
        tree: object = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_float,
            parse_constant=_constant,
        )
        if not isinstance(tree, dict) or tree.get("continues", False) is not False:
            _invalid()
        if "error" in tree:
            error = tree["error"]
            parameters = tree.get("parameters")
            if (
                not isinstance(error, str)
                or parameters is not None
                and not isinstance(parameters, dict)
            ):
                _invalid()
            if error in _ERRORS:
                return _Failure.RESOLUTION_FAILED
            if error.startswith("org.varlink.service."):
                return _Failure.RESOLVER_UNAVAILABLE
            _invalid()
        parameters = tree.get("parameters")
        if not isinstance(parameters, dict):
            _invalid()
        # Required metadata is validated, then discarded. Never substitute name.
        name, flags = parameters.get("name"), parameters.get("flags")
        if (
            not isinstance(name, str)
            or not name
            or type(flags) is not int
            or not 0 <= flags <= (1 << 64) - 1
        ):
            _invalid()
        name.encode("utf-8", errors="strict")
        records = parameters.get("addresses")
        if not isinstance(records, list):
            _invalid()
        if len(records) > _MAX_ADDRESSES:
            return _Failure.RESOLUTION_TOO_MANY_RESULTS
        if not records:
            return _Failure.RESOLUTION_EMPTY
        projected: list[_ResolvedAddress] = []
        seen: set[tuple[int, bytes, int | None]] = set()
        for record in records:
            if not isinstance(record, dict):
                _invalid()
            family, octets, ifindex = (
                record.get("family"),
                record.get("address"),
                record.get("ifindex"),
            )
            if type(family) is not int or family not in (_IPV4, _IPV6):
                _invalid()
            if not isinstance(octets, list) or len(octets) != (
                4 if family == _IPV4 else 16
            ):
                _invalid()
            if any(type(n) is not int or not 0 <= n <= 255 for n in octets):
                _invalid()
            if ifindex is not None and (
                type(ifindex) is not int or not 1 <= ifindex <= (1 << 31) - 1
            ):
                _invalid()
            packed = bytes(octets)
            address = ipaddress.ip_address(packed)
            # Representation only. Private/loopback/link-local are allowed.
            # Link-local IPv6 must carry a usable numeric interface index.
            if family == _IPV6 and address.is_link_local and ifindex is None:
                _invalid()
            key = (family, packed, ifindex)
            if key not in seen:
                seen.add(key)
                projected.append(_ResolvedAddress(*key))
        return _Resolution(tuple(projected))
    except (ValueError, UnicodeError, _InvalidReply):
        return _Failure.RESOLUTION_INVALID


def _request(hostname: str) -> bytes:
    wire = (
        json.dumps(
            {
                "method": _METHOD,
                "parameters": {"name": hostname, "family": 0, "flags": _NO_SEARCH},
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\0"
    )
    if len(wire) > _MAX_REQUEST_BYTES:
        raise ValueError("Invalid internal resolver request")
    return wire


class _Unavailable(Exception):
    """Closed trust/profile signal; not exposed outside this boundary."""


def _socket_identity() -> tuple[tuple[int, ...], ...]:
    identities: list[tuple[int, ...]] = []
    for path in (*_PARENTS, _SOCKET_PATH):
        info = os.lstat(path)
        if path in _PARENTS:
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise _Unavailable
            if path != _PARENTS[-1] and info.st_uid != 0:
                raise _Unavailable
        elif not stat.S_ISSOCK(info.st_mode):
            raise _Unavailable
        identities.append(
            (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_ctime_ns,
            )
        )
    if identities[-1][3:5] != identities[-2][3:5]:
        raise _Unavailable
    # Root controls the immutable-to-untrusted-users ancestry; it delegates
    # the final directory to the service account. No NSS account lookup.
    return tuple(identities)


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError
    return left


def _wait(selector: selectors.BaseSelector, deadline: float) -> None:
    if not selector.select(_remaining(deadline)):
        raise TimeoutError
    _remaining(deadline)


def _resolve(endpoint: _Preflight, *, deadline: float) -> _Resolution | _Failure:
    """One logical call with the caller's finite absolute monotonic deadline.

    Requires an M3.2-validated endpoint. Never changes its logical hostname.
    No worker, cache, fallback, retries, or independently reset time budget.
    """
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        return _Failure.RESOLVER_UNAVAILABLE
    if not math.isfinite(deadline):
        return _Failure.RESOLUTION_TIMEOUT
    try:
        _remaining(deadline)
        wire = _request(endpoint.hostname)
        identity = _socket_identity()
        _remaining(deadline)
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock,
            selectors.DefaultSelector() as selector,
        ):
            sock.setblocking(False)
            code = sock.connect_ex(_SOCKET_PATH)
            # AF_UNIX EAGAIN means a full accept queue, NOT an in-progress
            # connection; do not retry or treat SO_ERROR=0 as success there.
            if code not in (0, errno.EINPROGRESS):
                return _Failure.RESOLVER_UNAVAILABLE
            selector.register(sock, selectors.EVENT_WRITE)
            _wait(selector, deadline)
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                return _Failure.RESOLVER_UNAVAILABLE
            pid, uid, gid = struct.unpack(
                "3i",
                sock.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if (
                pid <= 0
                or (uid, gid) != identity[-1][3:5]
                or _socket_identity() != identity
            ):
                return _Failure.RESOLVER_UNAVAILABLE
            _remaining(deadline)
            pending = memoryview(wire)
            while pending:
                _wait(selector, deadline)
                try:
                    count = sock.send(pending)
                except BlockingIOError:
                    continue
                if count == 0:
                    return _Failure.RESOLUTION_FAILED
                pending = pending[count:]
            selector.modify(sock, selectors.EVENT_READ)
            reply = bytearray()
            while True:
                _wait(selector, deadline)
                try:
                    chunk = sock.recv(min(4096, _MAX_RESPONSE_BYTES + 1 - len(reply)))
                except BlockingIOError:
                    continue
                if not chunk:
                    return _Failure.RESOLUTION_FAILED
                reply.extend(chunk)
                if len(reply) > _MAX_RESPONSE_BYTES:
                    return _Failure.RESOLUTION_TOO_LARGE
                if b"\0" in chunk:
                    result = _parse_reply(bytes(reply))
                    _remaining(deadline)
                    return result
    except TimeoutError:
        return _Failure.RESOLUTION_TIMEOUT
    except (OSError, _Unavailable):
        return _Failure.RESOLVER_UNAVAILABLE
