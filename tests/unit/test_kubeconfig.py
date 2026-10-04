"""Synthetic-only tests of the private document boundary, never authentication."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from openkube_optimizer.collection import kubeconfig as kc

MINIMAL = b"apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"
CANARY = "synthetic-secret-do-not-expose"


def load(tmp_path: Path, data: bytes) -> kc._Document | kc._Failure:
    path = tmp_path / CANARY
    path.write_bytes(data)
    return kc._load_document(path)


def test_minimum_and_unselected_data_remain_inert(tmp_path: Path) -> None:
    data = MINIMAL.replace(
        b"users: []",
        b"users: [{name: unused, user: {exec: {command: never-run}, auth-provider: {name: unused}}}]",
    )
    result = load(
        tmp_path,
        data
        + b"current-context: nonexistent\nextra: [yes, false, null, 012, 2026-10-04]\n",
    )
    assert isinstance(result, kc._Document)
    assert result._data["current-context"] == "nonexistent"
    assert result._data["extra"] == ["yes", "false", "null", "012", "2026-10-04"]
    assert result._data["clusters"] == []


@pytest.mark.parametrize("size", [len(MINIMAL), kc._MAX_BYTES - 1, kc._MAX_BYTES])
def test_byte_limits_accept_equality(tmp_path: Path, size: int) -> None:
    assert isinstance(
        load(tmp_path, MINIMAL + b" " * (size - len(MINIMAL))), kc._Document
    )


def test_oversize(tmp_path: Path) -> None:
    assert (
        load(tmp_path, MINIMAL + b" " * (kc._MAX_BYTES + 1 - len(MINIMAL)))
        is kc._Failure.TOO_LARGE
    )


def test_actual_read_limit_despite_inaccurate_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversize"
    path.write_bytes(MINIMAL + b" " * kc._MAX_BYTES)
    original_fstat, original_read = os.fstat, os.read
    descriptors: list[int] = []
    consumed = 0

    def understated(fd: int) -> os.stat_result:
        info = list(original_fstat(fd))
        info[6] = 0
        return os.stat_result(info)

    def short_read(fd: int, size: int) -> bytes:
        nonlocal consumed
        descriptors.append(fd)
        assert size <= kc._MAX_BYTES + 1 - consumed
        data = original_read(fd, min(size, 65536))
        consumed += len(data)
        return data

    monkeypatch.setattr(os, "fstat", understated)
    monkeypatch.setattr(os, "read", short_read)
    assert kc._load_document(path) is kc._Failure.TOO_LARGE
    assert consumed == kc._MAX_BYTES + 1
    with pytest.raises(OSError):
        original_fstat(descriptors[0])


def test_trusted_symlink(tmp_path: Path) -> None:
    target = tmp_path / "regular"
    target.write_bytes(MINIMAL)
    link = tmp_path / "link"
    link.symlink_to(target)
    assert isinstance(kc._load_document(link), kc._Document)


def test_nonregular_and_missing_inputs(tmp_path: Path) -> None:
    assert kc._load_document(tmp_path) is kc._Failure.INVALID_INPUT
    assert kc._load_document(tmp_path / CANARY) is kc._Failure.INVALID_INPUT
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert kc._load_document(fifo) is kc._Failure.INVALID_INPUT


def test_descriptor_type_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "regular"
    path.write_bytes(MINIMAL)
    monkeypatch.setattr(os, "fstat", lambda fd: tmp_path.stat())
    assert kc._load_document(path) is kc._Failure.INVALID_INPUT


@pytest.mark.parametrize(
    ("data", "failure"),
    [
        (MINIMAL + b"\xff", kc._Failure.INVALID_UTF8),
        (MINIMAL + b"extra: [", kc._Failure.MALFORMED_YAML),
        (MINIMAL + b'extra: "\\UFFFFFFFF"', kc._Failure.MALFORMED_YAML),
        (MINIMAL + b'extra: "\\U00110000"', kc._Failure.MALFORMED_YAML),
        (MINIMAL + b"---\n" + MINIMAL, kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"kind: Config\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: {a: one, a: two}\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: &anchor value\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: *missing\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: {<<: {a: value}}\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: !!str value\n", kc._Failure.UNSUPPORTED_YAML),
        (MINIMAL + b"extra: !custom value\n", kc._Failure.UNSUPPORTED_YAML),
        (
            MINIMAL + b"extra: !!python/object/apply:os.system [never-run]\n",
            kc._Failure.UNSUPPORTED_YAML,
        ),
        (MINIMAL + b"extra: {[a, b]: value}\n", kc._Failure.UNSUPPORTED_YAML),
        (
            b"%TAG !x! tag:example.invalid,2026:\n---\n" + MINIMAL,
            kc._Failure.UNSUPPORTED_YAML,
        ),
        (b"[]", kc._Failure.INVALID_STRUCTURE),
        (b"plain", kc._Failure.INVALID_STRUCTURE),
        (MINIMAL.replace(b"apiVersion: v1\n", b""), kc._Failure.INVALID_STRUCTURE),
        (
            MINIMAL.replace(b"apiVersion: v1", b"apiVersion: v2"),
            kc._Failure.INVALID_STRUCTURE,
        ),
        (MINIMAL.replace(b"kind: Config\n", b""), kc._Failure.INVALID_STRUCTURE),
        (
            MINIMAL.replace(b"kind: Config", b"kind: config"),
            kc._Failure.INVALID_STRUCTURE,
        ),
    ],
)
def test_rejections(tmp_path: Path, data: bytes, failure: kc._Failure) -> None:
    assert load(tmp_path, data) is failure


@pytest.mark.parametrize("key", [b"clusters", b"contexts", b"users"])
@pytest.mark.parametrize("value", [b"{}", b"null", b"string", b"false"])
def test_required_sequences(tmp_path: Path, key: bytes, value: bytes) -> None:
    assert (
        load(tmp_path, MINIMAL.replace(key + b": []", key + b": " + value))
        is kc._Failure.INVALID_STRUCTURE
    )


@pytest.mark.parametrize("key", [b"clusters", b"contexts", b"users"])
def test_missing_sequences(tmp_path: Path, key: bytes) -> None:
    assert (
        load(tmp_path, MINIMAL.replace(key + b": []\n", b""))
        is kc._Failure.INVALID_STRUCTURE
    )


@pytest.mark.parametrize("depth", [31, 32, 33, 1000])
@pytest.mark.parametrize(("opening", "closing"), [(b"[", b"]"), (b"{a: ", b"}")])
def test_depth_before_deep_construction(
    tmp_path: Path, depth: int, opening: bytes, closing: bytes
) -> None:
    # Root mapping is depth 1; each nested mapping/sequence adds one container.
    data = MINIMAL + b"extra: " + opening * (depth - 1) + b"x" + closing * (depth - 1)
    result = load(tmp_path, data)
    if depth <= 32:
        assert isinstance(result, kc._Document)
    else:
        assert result is kc._Failure.UNSUPPORTED_YAML


@pytest.mark.parametrize("suffix", ["", " [", " !!str value", " \udcff"])
def test_no_sensitive_representations_or_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], suffix: str
) -> None:
    raw = MINIMAL + f"extra: {CANARY}{suffix}\n".encode(
        "utf-8", errors="surrogateescape"
    )
    result = load(tmp_path, raw)
    assert CANARY not in str(result)
    assert CANARY not in repr(result)
    assert str(tmp_path) not in repr(result)
    assert not isinstance(result, BaseException)
    assert capsys.readouterr() == ("", "")


def test_descriptor_closed_on_success_and_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fixture"
    path.write_bytes(MINIMAL)
    original_open = os.open
    descriptors: list[int] = []

    def record_open(path: Path, flags: int) -> int:
        fd = original_open(path, flags)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(os, "open", record_open)
    assert isinstance(kc._load_document(path), kc._Document)
    with pytest.raises(OSError):
        os.fstat(descriptors[-1])

    def failed_read(fd: int, size: int) -> bytes:
        raise OSError(CANARY)

    monkeypatch.setattr(os, "read", failed_read)
    assert kc._load_document(path) is kc._Failure.INVALID_INPUT
    with pytest.raises(OSError):
        os.fstat(descriptors[-1])


def test_import_and_loading_have_no_implicit_io(tmp_path: Path) -> None:
    path = tmp_path / "explicit"
    path.write_bytes(
        MINIMAL + b"current-context: ignored\nunused: {exec: {command: never-run}}\n"
    )
    script = r"""
import os, sys, threading, _thread
from pathlib import Path
path = Path(sys.argv[1])
violations = []
loading = False
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise AssertionError('Unexpected side effect')
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
        name = args[0]
        allowed = isinstance(name, str) and name.endswith(('.py', '.pyc'))
        if not allowed and not (loading and name == str(path)):
            reject()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = reject
threading.Thread.start = reject
_thread.start_new_thread = reject
from openkube_optimizer.collection import kubeconfig as kc
assert 'yaml' not in sys.modules
loading = True
assert isinstance(kc._load_document(path), kc._Document)
assert not violations
assert not any(n.split('.')[0] in {'kubernetes', 'h11'} for n in sys.modules)
assert len(threading.enumerate()) == 1
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(path)],
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
