"""Synthetic trusted-local-file tests; Linux behavior requires actual procfs."""

import copy
import dataclasses
import json
import os
import pickle
import socket
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

from openkube_optimizer.collection import credentials as cr
from openkube_optimizer.collection import kubeconfig as kc
from openkube_optimizer.collection import preflight as pf

CA = b"synthetic-ca-content-canary"
CERTIFICATE = b"synthetic-certificate-content-canary"
KEY = b"synthetic-private-key-content-canary"
TOKEN = "synthetic-token-do-not-copy-canary"
PATH_NAMES = (
    "synthetic-ca-path-canary",
    "synthetic-cert-path-canary",
    "synthetic-key-path-canary",
)


@pytest.fixture
def linux() -> None:
    if sys.platform != "linux":
        pytest.skip("Native O_PATH/procfs requires the Linux validation environment")
    assert hasattr(os, "O_PATH")


def selected(tmp_path: Path, *, certificate: bool = True) -> pf._Preflight:
    for name, data in zip(PATH_NAMES, (CA, CERTIFICATE, KEY), strict=True):
        (tmp_path / name).write_bytes(data)
    auth = (
        f"client-certificate: {PATH_NAMES[1]}, client-key: {PATH_NAMES[2]}"
        if certificate
        else f"token: {TOKEN}"
    )
    config = tmp_path / "explicit-synthetic-kubeconfig"
    config.write_text(
        f"""apiVersion: v1
kind: Config
contexts: [{{name: chosen, context: {{cluster: cluster, user: user}}}}]
clusters: [{{name: cluster, cluster: {{server: https://api.example.invalid, certificate-authority: {PATH_NAMES[0]}}}}}]
users: [{{name: user, user: {{{auth}}}}}]
""",
        encoding="utf-8",
    )
    document = kc._load_document(config)
    assert isinstance(document, kc._Document)
    result = pf._preflight(document, context_name="chosen")
    assert isinstance(result, pf._Preflight)
    return result


@pytest.fixture
def tracked(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    original_open, original_fstat = os.open, os.fstat
    opened: list[int] = []

    def record(path: str | Path, flags: int) -> int:
        assert flags & os.O_CLOEXEC
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        fd = original_open(path, flags)
        opened.append(fd)
        return fd

    # Share pytest's patch stack with test-body patches of this same target.
    monkeypatch.setattr(os, "open", record)
    yield opened
    for fd in set(opened):
        with pytest.raises(OSError):
            original_fstat(fd)


@pytest.mark.parametrize("body_error", [False, True])
def test_tracked_fixture_restores_original_between_lifetimes(
    tmp_path: Path, body_error: bool
) -> None:
    original_open = os.open
    fixture_body = cast(
        Callable[[pytest.MonkeyPatch], Iterator[list[int]]],
        getattr(tracked, "__wrapped__"),
    )
    path = tmp_path / "synthetic-fixture-lifetime"
    path.write_bytes(b"fixture-lifetime")

    # Exercise two test lifetimes, with the dependent fixture finalized first.
    for _ in range(2):
        assert os.open is original_open
        with pytest.MonkeyPatch.context() as owner:
            lifetime = fixture_body(owner)
            opened = next(lifetime)
            wrapper = os.open
            assert wrapper is not original_open

            def temporary(path: str | Path, flags: int) -> int:
                return wrapper(path, flags)

            try:
                with owner.context() as nested:
                    nested.setattr(os, "open", temporary)
                    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                    os.close(fd)
                assert os.open is wrapper
                assert opened == [fd]
                # Reproduce a test-body patch on the same fixture-scoped owner.
                owner.setattr(os, "open", temporary)
                if body_error:
                    raise RuntimeError("synthetic test-body exception")
            except RuntimeError:
                assert body_error
            finally:
                with pytest.raises(StopIteration):
                    next(lifetime)
        assert os.open is original_open


@pytest.mark.parametrize("certificate", [False, True])
@pytest.mark.parametrize("symlinks", [False, True])
def test_regular_material_ownership_and_symlinks(
    linux: None, tmp_path: Path, tracked: list[int], certificate: bool, symlinks: bool
) -> None:
    preflight = selected(tmp_path, certificate=certificate)
    setup_opens = len(tracked)
    if symlinks:
        for name in PATH_NAMES:
            path = tmp_path / name
            target = path.with_suffix(".target")
            path.rename(target)
            path.symlink_to(target)
    before = {
        p: (p.stat().st_mode, p.read_bytes()) for p in tmp_path.iterdir() if p.is_file()
    }
    result = cr._load_credentials(preflight)
    assert isinstance(result, cr._CredentialMaterial)
    with result as material:
        assert material._ca_snapshot == CA
        assert not hasattr(material, "token")
        assert not hasattr(material, "auth")
        if certificate:
            assert material._certificate_fd is not None and material._key_fd is not None
            assert (
                os.read(material._certificate_fd, len(CERTIFICATE) + 1) == CERTIFICATE
            )
            assert os.read(material._key_fd, len(KEY) + 1) == KEY
            assert not os.get_inheritable(material._certificate_fd)
            assert not os.get_inheritable(material._key_fd)
        else:
            assert material._certificate_fd is material._key_fd is None
            assert len(tracked) - setup_opens == 2  # CA O_PATH + procfs read only.
    assert result._ca_snapshot == b""
    assert result._certificate_fd is result._key_fd is None
    result.close()
    with pytest.raises(TypeError, match="Credential material is closed"):
        with result:
            pytest.fail("Closed owner reentered")
    assert {
        p: (p.stat().st_mode, p.read_bytes()) for p in tmp_path.iterdir() if p.is_file()
    } == before


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("size", [0, cr._MAX_BYTES, cr._MAX_BYTES + 1])
def test_each_file_size_boundary(
    linux: None, tmp_path: Path, tracked: list[int], index: int, size: int
) -> None:
    preflight = selected(tmp_path)
    (tmp_path / PATH_NAMES[index]).write_bytes(b"x" * size)
    result = cr._load_credentials(preflight)
    if size > cr._MAX_BYTES:
        assert result is kc._Failure.CREDENTIAL_TOO_LARGE
    else:
        assert isinstance(result, cr._CredentialMaterial)
        with result:
            if index == 0:
                assert len(result._ca_snapshot) == size


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "socket"])
def test_nonregular_inputs_never_receive_data_open(
    linux: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    preflight = selected(tmp_path, certificate=False)
    path = tmp_path / PATH_NAMES[0]
    path.unlink()
    unix_socket: socket.socket | None = None
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "socket":
        unix_socket = socket.socket(socket.AF_UNIX)
        unix_socket.bind(str(path))  # Synthetic pathname fixture, no network.
    original_open = os.open
    flags_seen: list[int] = []

    def only_path(path: str | Path, flags: int) -> int:
        flags_seen.append(flags)
        assert flags & getattr(os, "O_PATH")
        return original_open(path, flags)

    try:
        with monkeypatch.context() as guard:
            guard.setattr(os, "open", only_path)
            result = cr._load_credentials(preflight)
        assert result is (
            kc._Failure.CREDENTIAL_UNAVAILABLE
            if kind == "missing"
            else kc._Failure.CREDENTIAL_NONREGULAR
        )
        assert len(flags_seen) == 1
    finally:
        if unix_socket is not None:
            unix_socket.close()


@pytest.mark.parametrize("mode", [stat.S_IFCHR, stat.S_IFBLK, stat.S_IFLNK])
def test_other_nonregular_descriptor_metadata(
    linux: None,
    tmp_path: Path,
    tracked: list[int],
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
) -> None:
    preflight = selected(tmp_path, certificate=False)
    setup_opens = len(tracked)
    original_fstat = os.fstat

    def changed_type(fd: int) -> os.stat_result:
        fields = list(original_fstat(fd))
        fields[0] = mode | 0o600
        return os.stat_result(fields)

    with monkeypatch.context() as guard:
        guard.setattr(os, "fstat", changed_type)
        assert cr._load_credentials(preflight) is kc._Failure.CREDENTIAL_NONREGULAR
    assert len(tracked) - setup_opens == 1


@pytest.mark.parametrize("index", [0, 1, 2])
def test_actual_overflow_despite_understated_size(
    linux: None,
    tmp_path: Path,
    tracked: list[int],
    monkeypatch: pytest.MonkeyPatch,
    index: int,
) -> None:
    preflight = selected(tmp_path)
    path = tmp_path / PATH_NAMES[index]
    path.write_bytes(b"x" * (cr._MAX_BYTES + 1))
    inode = path.stat().st_ino
    original_fstat, original_read = os.fstat, os.read
    consumed = 0

    def understated(fd: int) -> os.stat_result:
        actual = original_fstat(fd)
        if actual.st_ino != inode:
            return actual
        fields = list(actual)
        fields[6] = 0
        return os.stat_result(fields)

    def short_read(fd: int, size: int) -> bytes:
        nonlocal consumed
        data = original_read(fd, min(size, 997))
        if original_fstat(fd).st_ino == inode:
            assert size <= cr._MAX_BYTES + 1 - consumed
            consumed += len(data)
        return data

    with monkeypatch.context() as guard:
        guard.setattr(os, "fstat", understated)
        guard.setattr(os, "read", short_read)
        assert cr._load_credentials(preflight) is kc._Failure.CREDENTIAL_TOO_LARGE
    assert consumed == cr._MAX_BYTES + 1


def test_short_reads_success(
    linux: None, tmp_path: Path, tracked: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path)
    original_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, size: original_read(fd, min(size, 2)))
    result = cr._load_credentials(preflight)
    assert isinstance(result, cr._CredentialMaterial)
    with result:
        assert result._ca_snapshot == CA


@pytest.mark.parametrize("index", [0, 1, 2])
def test_detectable_in_place_modification(
    linux: None,
    tmp_path: Path,
    tracked: list[int],
    monkeypatch: pytest.MonkeyPatch,
    index: int,
) -> None:
    preflight = selected(tmp_path)
    path = tmp_path / PATH_NAMES[index]
    inode = path.stat().st_ino
    original_read, original_fstat = os.read, os.fstat
    modified = False

    def changing_read(fd: int, size: int) -> bytes:
        nonlocal modified
        data = original_read(fd, size)
        if not modified and original_fstat(fd).st_ino == inode:
            modified = True
            with path.open("ab") as stream:
                stream.write(b"obvious-synthetic-modification")
        return data

    monkeypatch.setattr(os, "read", changing_read)
    assert cr._load_credentials(preflight) is kc._Failure.CREDENTIAL_CHANGED
    assert modified


@pytest.mark.parametrize(
    ("index", "stage"),
    [
        (index, stage)
        for index in range(3)
        for stage in ("path-open", "reopen", "fstat", "read", "seek")
        if not (index == 0 and stage == "seek")
    ],
)
def test_partial_failures_close_all_owned_descriptors(
    linux: None,
    tmp_path: Path,
    tracked: list[int],
    monkeypatch: pytest.MonkeyPatch,
    index: int,
    stage: str,
) -> None:
    preflight = selected(tmp_path)
    target_inode = (tmp_path / PATH_NAMES[index]).stat().st_ino
    original_open, original_fstat = os.open, os.fstat
    original_read, original_seek = os.read, os.lseek
    current_path = ""

    def failed_open(path: str | Path, flags: int) -> int:
        nonlocal current_path
        if isinstance(path, Path):
            current_path = path.name
        if current_path == PATH_NAMES[index] and (
            (stage == "path-open" and isinstance(path, Path))
            or (stage == "reopen" and isinstance(path, str))
        ):
            raise OSError(TOKEN + str(path))
        return original_open(path, flags)

    def failed_fstat(fd: int) -> os.stat_result:
        info = original_fstat(fd)
        if stage == "fstat" and info.st_ino == target_inode:
            raise OSError(TOKEN)
        return info

    def failed_read(fd: int, size: int) -> bytes:
        if stage == "read" and original_fstat(fd).st_ino == target_inode:
            raise OSError(TOKEN)
        return original_read(fd, size)

    def failed_seek(fd: int, offset: int, whence: int) -> int:
        if stage == "seek" and original_fstat(fd).st_ino == target_inode:
            raise OSError(TOKEN)
        return original_seek(fd, offset, whence)

    with monkeypatch.context() as guard:
        guard.setattr(os, "open", failed_open)
        guard.setattr(os, "fstat", failed_fstat)
        guard.setattr(os, "read", failed_read)
        guard.setattr(os, "lseek", failed_seek)
        result = cr._load_credentials(preflight)
    assert result is kc._Failure.CREDENTIAL_UNAVAILABLE
    assert TOKEN not in str(result) + repr(result)


@pytest.mark.parametrize("symlink", [False, True])
def test_retained_descriptors_pin_original_object_after_path_replacement(
    linux: None, tmp_path: Path, tracked: list[int], symlink: bool
) -> None:
    preflight = selected(tmp_path)
    if symlink:
        for name in PATH_NAMES[1:]:
            path = tmp_path / name
            target = path.with_suffix(".original")
            path.rename(target)
            path.symlink_to(target)
    result = cr._load_credentials(preflight)
    assert isinstance(result, cr._CredentialMaterial)
    with result:
        assert result._certificate_fd is not None and result._key_fd is not None
        for name in PATH_NAMES[1:]:
            path = tmp_path / name
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(b"different-synthetic-object")
            path.unlink()
            if symlink:
                path.symlink_to(replacement)
            else:
                replacement.rename(path)
        assert os.read(result._certificate_fd, 1000) == CERTIFICATE
        assert os.read(result._key_fd, 1000) == KEY


def test_procfs_reopen_uses_pin_even_after_symlink_retarget(
    linux: None, tmp_path: Path, tracked: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path, certificate=False)
    path = tmp_path / PATH_NAMES[0]
    target = path.with_suffix(".original")
    path.rename(target)
    path.symlink_to(target)
    replacement = path.with_suffix(".new")
    replacement.write_bytes(b"replacement-canary")
    original_open = os.open

    def retarget_after_pin(name: str | Path, flags: int) -> int:
        fd = original_open(name, flags)
        if name == path:
            path.unlink()
            path.symlink_to(replacement)
        return fd

    monkeypatch.setattr(os, "open", retarget_after_pin)
    result = cr._load_credentials(preflight)
    assert isinstance(result, cr._CredentialMaterial)
    with result:
        assert result._ca_snapshot == CA


def test_unsupported_profile_fails_without_any_file_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path)

    def forbidden(*args: object) -> None:
        pytest.fail("Unsupported profile performed file access")

    with monkeypatch.context() as guard:
        guard.setattr(sys, "platform", "darwin")
        guard.setattr(os, "open", forbidden)
        assert (
            cr._load_credentials(preflight)
            is kc._Failure.CREDENTIAL_PROFILE_UNAVAILABLE
        )


def test_missing_o_path_fails_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path)

    def forbidden(*args: object) -> None:
        pytest.fail("Missing O_PATH performed a fallback open")

    with monkeypatch.context() as guard:
        guard.setattr(sys, "platform", "linux")
        guard.delattr(os, "O_PATH", raising=False)
        guard.setattr(os, "open", forbidden)
        assert (
            cr._load_credentials(preflight)
            is kc._Failure.CREDENTIAL_PROFILE_UNAVAILABLE
        )


def test_reopen_identity_mismatch_rejects_and_closes(
    linux: None, tmp_path: Path, tracked: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path, certificate=False)
    other = tmp_path / "different-synthetic-object"
    other.write_bytes(b"different")
    original_open = os.open

    def wrong_object(path: str | Path, flags: int) -> int:
        return original_open(other if isinstance(path, str) else path, flags)

    monkeypatch.setattr(os, "open", wrong_object)
    assert cr._load_credentials(preflight) is kc._Failure.CREDENTIAL_CHANGED


def test_inspection_interruption_closes_already_owned_descriptors(
    linux: None, tmp_path: Path, tracked: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = selected(tmp_path)
    key_inode = (tmp_path / PATH_NAMES[2]).stat().st_ino
    original_read, original_fstat = os.read, os.fstat

    def interrupted(fd: int, size: int) -> bytes:
        if original_fstat(fd).st_ino == key_inode:
            raise KeyboardInterrupt
        return original_read(fd, size)

    monkeypatch.setattr(os, "read", interrupted)
    with pytest.raises(KeyboardInterrupt):
        cr._load_credentials(preflight)


def assert_private(record: object) -> None:
    canaries = [CA.decode(), CERTIFICATE.decode(), KEY.decode(), TOKEN, *PATH_NAMES]
    assert all(value not in repr(record) + str(record) for value in canaries)
    operations: list[Callable[[object], object]] = [
        vars,
        json.dumps,
        cast(Callable[[object], object], dataclasses.asdict),
        copy.copy,
        copy.deepcopy,
        lambda value: getattr(value, "__getstate__")(),
        lambda value: getattr(value, "__reduce__")(),
    ]
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):

        def serialize(value: object, protocol: int = protocol) -> object:
            return pickle.dumps(value, protocol)

        def reduce(value: object, protocol: int = protocol) -> object:
            return getattr(value, "__reduce_ex__")(protocol)

        operations.extend((serialize, reduce))
    for operation in operations:
        with pytest.raises(TypeError) as rejected:
            operation(record)
        assert all(
            value not in str(rejected.value) + repr(rejected.value)
            for value in canaries
        )
        assert rejected.value.__cause__ is rejected.value.__context__ is None


def test_owner_confinement_close_and_negative_canary(tmp_path: Path) -> None:
    paths = [tmp_path / PATH_NAMES[1], tmp_path / PATH_NAMES[2]]
    for path, data in zip(paths, (CERTIFICATE, KEY), strict=True):
        path.write_bytes(data)
    descriptors = [os.open(path, os.O_RDONLY) for path in paths]
    material = cr._CredentialMaterial(
        ca_snapshot=CA, certificate_fd=descriptors[0], key_fd=descriptors[1]
    )
    with material:
        assert_private(material)
        for name in material.__slots__:
            with pytest.raises(AttributeError):
                setattr(material, name, TOKEN)
            with pytest.raises(AttributeError):
                delattr(material, name)
    material.close()
    assert_private(material)
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)

    class Unguarded:
        __slots__ = ("contents",)

        def __init__(self) -> None:
            self.contents = CA

        def __repr__(self) -> str:
            return "<redacted>"

    assert CA.decode() in repr(Unguarded().__getstate__())
    with pytest.raises(pytest.fail.Exception):
        assert_private(Unguarded())


def test_context_body_exception_still_closes_both_descriptors(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in PATH_NAMES[1:]]
    for path in paths:
        path.write_bytes(b"synthetic")
    descriptors = [os.open(path, os.O_RDONLY) for path in paths]
    material = cr._CredentialMaterial(
        ca_snapshot=CA, certificate_fd=descriptors[0], key_fd=descriptors[1]
    )
    with pytest.raises(RuntimeError, match="synthetic body failure"):
        with material:
            raise RuntimeError("synthetic body failure")
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("certificate", [False, True])
def test_owner_constructor_exception_closes_transferred_descriptors(
    linux: None,
    tmp_path: Path,
    tracked: list[int],
    monkeypatch: pytest.MonkeyPatch,
    certificate: bool,
) -> None:
    preflight = selected(tmp_path, certificate=certificate)

    def failed_owner(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic constructor failure")

    monkeypatch.setattr(cr, "_CredentialMaterial", failed_owner)
    with pytest.raises(RuntimeError, match="synthetic constructor failure"):
        cr._load_credentials(preflight)


def test_close_error_is_not_retried_and_other_descriptor_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = [tmp_path / name for name in PATH_NAMES[1:]]
    for path in paths:
        path.write_bytes(b"synthetic")
    descriptors = [os.open(path, os.O_RDONLY) for path in paths]
    material = cr._CredentialMaterial(
        ca_snapshot=CA, certificate_fd=descriptors[0], key_fd=descriptors[1]
    )
    original_close = os.close
    closed: list[int] = []

    def late_error(fd: int) -> None:
        closed.append(fd)
        original_close(fd)  # Model Linux releasing the FD before reporting error.
        raise OSError(TOKEN)

    with monkeypatch.context() as guard:
        guard.setattr(os, "close", late_error)
        material.close()
        material.close()
    assert closed == descriptors
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


# Reused by clean installed-wheel validation; no pytest import in the child.
CREDENTIAL_GATE_SCRIPT = r"""
import os, sys, threading, _thread, asyncio, ssl, socket, subprocess, re, stat
from pathlib import Path
from importlib.util import find_spec
root = Path(sys.argv[1])
certificate, mode = sys.argv[2] == 'certificate', sys.argv[3]
package_root = str(Path(find_spec('openkube_optimizer').origin).parent)
# Construct the actual M3.2 result using only the synthetic selected config.
# M3.3A must not reread it after guards start.
from openkube_optimizer.collection import kubeconfig as kc, preflight as pf
document = kc._load_document(root / 'explicit-synthetic-kubeconfig')
assert isinstance(document, kc._Document)
preflight = pf._preflight(document, context_name='chosen')
assert isinstance(preflight, pf._Preflight)
del document
paths = {str(preflight.ca_path)}
if certificate:
    assert isinstance(preflight.auth, pf._ClientCertificate)
    paths.update((str(preflight.auth.certificate_path), str(preflight.auth.key_path)))
else:
    assert isinstance(preflight.auth, pf._BearerToken)
phase = 'imports'
violations, owned, pins = [], set(), set()
consumed = {}
class GuardViolation(RuntimeError):
    pass
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise GuardViolation('Prohibited credential gate activity')
class Imports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'kubernetes', 'h11'}:
            reject()
def audit(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    if event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    if event == 'open':
        name, _, flags = args
        module_read = (
            phase == 'imports' and isinstance(name, str)
            and name.startswith(package_root + '/') and name.endswith(('.py', '.pyc'))
        )
        selected_read = phase == 'flow' and name in paths
        pinned_read = phase == 'flow' and name in {f'/proc/self/fd/{fd}' for fd in pins}
        if not (module_read or selected_read or pinned_read):
            reject()
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = os._Environ.__iter__ = reject
threading.Thread.start = _thread.start_new_thread = reject
if hasattr(_thread, 'start_joinable_thread'):
    _thread.start_joinable_thread = reject
asyncio.BaseEventLoop.create_task = asyncio.new_event_loop = reject
ssl.SSLContext = socket.socket = socket.getaddrinfo = reject
os.stat = os.lstat = os.readlink = os.access = reject
os.path.realpath = Path.resolve = Path.exists = reject
from openkube_optimizer.collection import credentials as cr
assert not violations
original_open, original_close, original_read = os.open, os.close, os.read
def tracked_open(name, flags):
    fd = original_open(name, flags)
    owned.add(fd)
    consumed[fd] = 0
    if flags & getattr(os, 'O_PATH', 0):
        pins.add(fd)
    return fd
def tracked_close(fd):
    original_close(fd)
    owned.remove(fd)
    pins.discard(fd)
def tracked_read(fd, size):
    assert fd in owned and size <= 1048577 - consumed[fd]
    data = original_read(fd, size)
    consumed[fd] += len(data)
    return data
os.open, os.close, os.read = tracked_open, tracked_close, tracked_read
phase = 'flow'
if mode != 'clean':
    actions = {
        'kubeconfig': lambda: open(root / 'explicit-synthetic-kubeconfig'),
        'environment': lambda: os.getenv('KUBECONFIG'),
        'sdk': lambda: __import__('kubernetes'),
        'ssl': lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        'socket': lambda: socket.socket(),
        'dns': lambda: socket.getaddrinfo('api.example.invalid', 443),
        'helper': lambda: subprocess.run(['never-execute']),
        'thread': lambda: threading.Thread(target=lambda: None).start(),
        'task': lambda: asyncio.BaseEventLoop.create_task(None, None),
        'resolve': lambda: preflight.ca_path.resolve(),
    }
    try:
        actions[mode]()
    except GuardViolation:
        pass
material = cr._load_credentials(preflight)
if sys.platform != 'linux':
    assert material is kc._Failure.CREDENTIAL_PROFILE_UNAVAILABLE
    assert not owned
else:
    assert isinstance(material, cr._CredentialMaterial)
    with material:
        assert material._ca_snapshot == b'synthetic-ca-content-canary'
        assert len(owned) == (2 if certificate else 0)
        assert not hasattr(material, 'token') and not hasattr(material, 'auth')
    assert not owned
assert not pins
assert len(threading.enumerate()) == 1
assert not any(name.split('.')[0] in {'kubernetes', 'h11'} for name in sys.modules)
assert not violations, 'Guard detected prohibited activity'
"""


CREDENTIAL_IMPORT_SCRIPT = r"""
import os, sys, re, stat, types, threading, _thread, asyncio, ssl, socket
from pathlib import Path
from importlib.util import find_spec
package_root = str(Path(find_spec('openkube_optimizer').origin).parent)
violations = []
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise AssertionError('Prohibited credential import activity')
class Imports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'kubernetes', 'h11', 'yaml'}:
            reject()
def audit(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    if event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    if event == 'open':
        name, _, flags = args
        if not isinstance(name, str) or not name.startswith(package_root + '/') or not name.endswith(('.py', '.pyc')):
            reject()
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = os._Environ.__iter__ = reject
threading.Thread.start = _thread.start_new_thread = reject
if hasattr(_thread, 'start_joinable_thread'):
    _thread.start_joinable_thread = reject
asyncio.BaseEventLoop.create_task = asyncio.new_event_loop = reject
ssl.SSLContext = socket.socket = socket.getaddrinfo = reject
from openkube_optimizer.collection import credentials
assert not violations
assert not any(name.split('.')[0] in {'kubernetes', 'h11', 'yaml'} for name in sys.modules)
assert len(threading.enumerate()) == 1
"""


def test_credential_module_import_alone_has_no_activation(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", CREDENTIAL_IMPORT_SCRIPT],
        cwd=tmp_path,
        env={
            "KUBECONFIG": str(tmp_path / "forbidden"),
            "HOME": str(tmp_path / "no-home"),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


@pytest.mark.parametrize("certificate", [False, True])
@pytest.mark.parametrize(
    "mode",
    [
        "clean",
        "kubeconfig",
        "environment",
        "sdk",
        "ssl",
        "socket",
        "dns",
        "helper",
        "thread",
        "task",
        "resolve",
    ],
)
def test_isolated_credential_boundary_and_negative_canaries(
    tmp_path: Path, certificate: bool, mode: str
) -> None:
    selected(tmp_path, certificate=certificate)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            CREDENTIAL_GATE_SCRIPT,
            str(tmp_path),
            "certificate" if certificate else "token",
            mode,
        ],
        cwd=tmp_path,
        env={
            "KUBECONFIG": str(tmp_path / "forbidden"),
            "HOME": str(tmp_path / "no-home"),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if mode == "clean":
        assert result.returncode == 0, result.stderr
        assert result.stdout == result.stderr == ""
    else:
        assert result.returncode != 0
        assert "Guard detected prohibited activity" in result.stderr
        assert result.stdout == ""
