"""Private Linux trusted-local-file boundary; no credential parsing or TLS.

The caller trusts the selected files and local filesystem. Descriptor pinning
and metadata diagnostics do not prevent concurrent in-place mutation, establish
filesystem locality/trust, hard-cancel native I/O or guarantee memory erasure.
"""

import os
import stat
import sys
from pathlib import Path
from types import TracebackType
from typing import Never, Self, SupportsIndex

from openkube_optimizer.collection.kubeconfig import _Failure
from openkube_optimizer.collection.preflight import _ClientCertificate, _Preflight

_CREDENTIAL_INPUT_POLICY_VERSION = "credential-input-v1"
_MAX_BYTES = 1024 * 1024


def _close_fd(fd: int | None) -> None:
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            # Linux releases the descriptor even on close errors; never retry
            # a descriptor number which may already have been reused.
            pass


class _CredentialMaterial:
    """Own CA bytes and optional client descriptors until explicit close/exit.

    No token, credential pathname or certificate/key inspection copy is held.
    Private descriptor access belongs only to the future TLS adapter.
    """

    __slots__ = ("_ca_snapshot", "_certificate_fd", "_key_fd", "_closed")
    _ca_snapshot: bytes
    _certificate_fd: int | None
    _key_fd: int | None
    _closed: bool

    def __init__(
        self, *, ca_snapshot: bytes, certificate_fd: int | None, key_fd: int | None
    ) -> None:
        object.__setattr__(self, "_ca_snapshot", ca_snapshot)
        object.__setattr__(self, "_certificate_fd", certificate_fd)
        object.__setattr__(self, "_key_fd", key_fd)
        object.__setattr__(self, "_closed", False)

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Immutable credential material")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Immutable credential material")

    def __repr__(self) -> str:
        return "<credential material: redacted>"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()

    def __getstate__(self) -> Never:
        raise TypeError("Credential material cannot be serialized")

    def close(self) -> None:
        if self._closed:
            return
        certificate, key = self._certificate_fd, self._key_fd
        # Relinquish ownership before closing. No GC or retry is required.
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_ca_snapshot", b"")
        object.__setattr__(self, "_certificate_fd", None)
        object.__setattr__(self, "_key_fd", None)
        try:
            _close_fd(certificate)
        finally:
            _close_fd(key)

    def __enter__(self) -> Self:
        if self._closed:
            raise TypeError("Credential material is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # atime may change during our read. mtime/ctime are diagnostics, not an
    # immutable-snapshot guarantee against a compromised filesystem/host.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_bounded(fd: int, *, snapshot: bool) -> bytes | _Failure:
    data = bytearray() if snapshot else None
    consumed = 0
    while consumed <= _MAX_BYTES:
        chunk = os.read(fd, min(65536, _MAX_BYTES + 1 - consumed))
        if not chunk:
            return bytes(data) if data is not None else b""
        consumed += len(chunk)
        if consumed > _MAX_BYTES:
            return _Failure.CREDENTIAL_TOO_LARGE
        if data is not None:
            data.extend(chunk)
        del chunk
    return _Failure.CREDENTIAL_TOO_LARGE


def _open_inspected(path: Path, *, snapshot: bool) -> tuple[int, bytes] | _Failure:
    pinned: int | None = None
    readable: int | None = None
    try:
        # O_PATH performs classification without a FIFO/device data-open. The
        # trusted kernel follows selected symlinks; no pathname canonicalization.
        path_flag: int = getattr(os, "O_PATH")
        pinned = os.open(path, path_flag | os.O_CLOEXEC)
        selected = os.fstat(pinned)
        if not stat.S_ISREG(selected.st_mode):
            return _Failure.CREDENTIAL_NONREGULAR
        if selected.st_size > _MAX_BYTES:
            return _Failure.CREDENTIAL_TOO_LARGE
        readable = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_CLOEXEC)
        before = os.fstat(readable)
        if _fingerprint(selected) != _fingerprint(before):
            return _Failure.CREDENTIAL_CHANGED
        data = _read_bounded(readable, snapshot=snapshot)
        if isinstance(data, _Failure):
            return data
        if _fingerprint(before) != _fingerprint(os.fstat(readable)):
            return _Failure.CREDENTIAL_CHANGED
        if not snapshot:
            os.lseek(readable, 0, os.SEEK_SET)
        result = readable, data
        readable = None  # Ownership transfers only after successful inspection.
        return result
    except (OSError, ValueError):
        return _Failure.CREDENTIAL_UNAVAILABLE
    finally:
        try:
            _close_fd(readable)
        finally:
            _close_fd(pinned)


def _load_credentials(preflight: _Preflight) -> _CredentialMaterial | _Failure:
    """Consume only validated references; caller owns and must close success.

    Token authentication needs only the CA snapshot. The bearer token remains
    owned by preflight and is never copied into this boundary.
    """
    if sys.platform != "linux" or not hasattr(os, "O_PATH"):
        return _Failure.CREDENTIAL_PROFILE_UNAVAILABLE
    ca_snapshot = b""
    certificate: int | None = None
    key: int | None = None
    try:
        ca = _open_inspected(preflight.ca_path, snapshot=True)
        if isinstance(ca, _Failure):
            return ca
        ca_fd, ca_snapshot = ca
        _close_fd(ca_fd)
        del ca
        if isinstance(preflight.auth, _ClientCertificate):
            inspected = _open_inspected(preflight.auth.certificate_path, snapshot=False)
            if isinstance(inspected, _Failure):
                return inspected
            certificate, _ = inspected
            inspected = _open_inspected(preflight.auth.key_path, snapshot=False)
            if isinstance(inspected, _Failure):
                return inspected
            key, _ = inspected
            del inspected
        material = _CredentialMaterial(
            ca_snapshot=ca_snapshot, certificate_fd=certificate, key_fd=key
        )
        certificate = key = None  # Ownership transferred to the explicit owner.
        return material
    finally:
        try:
            _close_fd(certificate)
        finally:
            _close_fd(key)
