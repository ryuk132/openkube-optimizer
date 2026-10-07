"""Offline dependency and import contracts for the first M3 slice."""

import ast
import subprocess
import sys
from importlib.metadata import distribution
from importlib.util import resolve_name
from pathlib import Path

import pytest

import openkube_optimizer

PACKAGE = Path(openkube_optimizer.__file__).parent


def _imports(source: str, package: str) -> list[str]:
    modules: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if node.level:
                module = resolve_name(module, package)
            modules.append(module)
            modules.extend(f"{module}.{alias.name}" for alias in node.names)
    return modules


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import kubernetes.client", ["kubernetes.client"]),
        ("from h11 import Connection", ["h11", "h11.Connection"]),
        (
            "from .. import collection",
            ["openkube_optimizer", "openkube_optimizer.collection"],
        ),
    ],
)
def test_import_scan_includes_relative_and_from_imports(
    source: str, expected: list[str]
) -> None:
    assert _imports(source, "openkube_optimizer.domain") == expected


def test_sdk_imports_stay_in_collection_and_pure_layers_stay_independent() -> None:
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE)
        package = ".".join(("openkube_optimizer", *relative.parts[:-1]))
        for module in _imports(path.read_text(), package):
            root = module.split(".")[0]
            if root in {"kubernetes", "h11"}:
                assert relative.parts[0] == "collection", relative
            if root == "yaml":
                assert relative.as_posix() == "collection/kubeconfig.py", relative
            if relative.parts[0] in {"domain", "analysis"}:
                assert root != "ssl", (relative, module)
                assert (
                    root in sys.stdlib_module_names
                    or module == "openkube_optimizer"
                    or module == "openkube_optimizer.domain"
                    or module.startswith("openkube_optimizer.domain.")
                    or (
                        relative.parts[0] == "analysis"
                        and (
                            module == "openkube_optimizer.analysis"
                            or module.startswith("openkube_optimizer.analysis.")
                        )
                    )
                ), (relative, module)


def _run_isolated(script: str, tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        cwd=tmp_path,
        env={"KUBECONFIG": str(tmp_path / "must-not-be-opened")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_openkube_imports_without_external_dependencies_or_side_effects(
    tmp_path: Path,
) -> None:
    _run_isolated(
        """
import os
import sys
import threading
import _thread

events = []
def reject(*args, **kwargs):
    events.append('forbidden operation')
    raise AssertionError('Import side effect')

class PureImports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in sys.stdlib_module_names:
            return None
        if fullname == 'openkube_optimizer' or fullname.startswith('openkube_optimizer.'):
            return None
        reject()

def audit(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    if event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    if event == 'open':
        path = args[0]
        if not isinstance(path, str) or not path.endswith(('.py', '.pyc')):
            reject()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()

sys.meta_path.insert(0, PureImports())
sys.addaudithook(audit)
os._Environ.__getitem__ = reject
threading.Thread.start = reject
_thread.start_new_thread = reject
import openkube_optimizer
import openkube_optimizer.collection
import openkube_optimizer.collection.kubeconfig
import openkube_optimizer.collection.preflight
import openkube_optimizer.domain.models
import openkube_optimizer.domain.quantities
assert not events
assert not any(name.split('.')[0] in {'kubernetes', 'h11'} for name in sys.modules)
assert len(threading.enumerate()) == 1
""",
        tmp_path,
    )


@pytest.mark.parametrize(
    "inject_socket_canary",
    [False, True],
    ids=["sdk-import", "unexpected-socket-canary"],
)
def test_approved_dependencies_import_without_activating_authentication(
    tmp_path: Path,
    inject_socket_canary: bool,
) -> None:
    installed = distribution("openkube-optimizer")
    assert sorted(installed.requires or []) == [
        "h11==0.16.0",
        "kubernetes==36.0.3",
        "pyyaml==6.0.3",
    ]
    script = """
import os
import socket
import sys
import threading
import _thread

forbidden = []
socket_probes = []
environment_keys = set()
original_getitem = os._Environ.__getitem__
def observe_environment(self, key):
    environment_keys.add(key)
    return original_getitem(self, key)
os._Environ.__getitem__ = observe_environment

def reject(*args, **kwargs):
    forbidden.append('activation')
    raise AssertionError('Unexpected import activation')
threading.Thread.start = reject
_thread.start_new_thread = reject

def audit(event, args):
    if event == 'socket.__new__':
        # The pinned urllib3 import probes IPv6 via _has_ipv6. Record every
        # attempt before blocking it; a caught OSError must not hide a violation.
        origin = []
        frame = sys._getframe(1)
        for _ in range(3):
            if frame is None:
                break
            origin.append((frame.f_globals.get('__name__', ''), frame.f_code.co_name))
            frame = frame.f_back
        del frame
        socket_probes.append((args[1], tuple(origin)))
        raise OSError('Offline import test')
    if event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    if event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    if event == 'open':
        path = args[0]
        if not isinstance(path, str) or not (
            path.endswith(('.py', '.pyc'))
            or path == '/System/Library/CoreServices/SystemVersion.plist'
        ):
            reject()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()

def profile(frame, event, arg):
    if event != 'call':
        return
    module = frame.f_globals.get('__name__', '')
    name = frame.f_code.co_name
    if module in {
        'kubernetes.config.kube_config', 'kubernetes.config.exec_provider',
        'kubernetes.config.incluster_config'
    } and name != '<module>':
        # Class bodies execute on import; authentication functions do not.
        if name[0].islower() or name.startswith('_'):
            reject()
    if module == 'kubernetes.client.configuration' and name in {
        '__init__', 'set_default', 'get_default_copy'
    }:
        reject()

sys.addaudithook(audit)
sys.setprofile(profile)
import kubernetes
if inject_socket_canary:
    # Same family, unrelated caller, swallowed exception: still must fail below.
    try:
        socket.socket(socket.AF_INET6)
    except OSError:
        pass
import h11
sys.setprofile(None)
assert kubernetes.__version__ == '36.0.3'
assert h11.__version__ == '0.16.0'
assert kubernetes.client.Configuration._default is None
assert 'KUBECONFIG' in environment_keys
assert kubernetes.config.kube_config.KUBE_CONFIG_DEFAULT_LOCATION.endswith('must-not-be-opened')
assert not forbidden
assert len(threading.enumerate()) == 1
# Exactly one attempt, from the known import-time capability probe only.
# Raising above prevents socket creation, including the probe's local bind.
assert socket_probes == [(socket.AF_INET6, (
    ('socket', '__init__'),
    ('urllib3.util.connection', '_has_ipv6'),
    ('urllib3.util.connection', '<module>'),
))], 'Unexpected socket attempts'
"""
    script = f"inject_socket_canary = {inject_socket_canary!r}\n" + script
    if inject_socket_canary:
        with pytest.raises(
            AssertionError, match="AssertionError: Unexpected socket attempts"
        ):
            _run_isolated(script, tmp_path)
    else:
        _run_isolated(script, tmp_path)
