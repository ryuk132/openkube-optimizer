"""Isolated real-resolved gate; application communication is fixed local IPC."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Also executed directly from the installed wheel, outside the checkout.
# No pytest, source-tree imports, test fixtures, DNS helpers or remote connect.
RESOLVER_SCRIPT = r"""
import _thread
import ipaddress
import json
import math
import os
import selectors
import socket
import ssl
import stat
import struct
import sys
import threading
import time
from pathlib import Path

case = sys.argv[1]
path = '/run/systemd/resolve/io.systemd.Resolve'
violations = []
created = []
connections = []
sent = bytearray()
received = bytearray()
native = sys.platform == 'linux'
before_fds = set(os.listdir('/proc/self/fd')) if native else None
before_threads = tuple(threading.enumerate())

def reject(*args, **kwargs):
    violations.append('forbidden')
    raise AssertionError('Forbidden activity')

class Imports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in sys.stdlib_module_names:
            return None
        if fullname == 'openkube_optimizer' or fullname.startswith('openkube_optimizer.'):
            return None
        reject()

def audit(event, args):
    if event == 'socket.__new__':
        if args[1:4] != (socket.AF_UNIX, socket.SOCK_STREAM, 0):
            reject()
    elif event == 'socket.connect':
        if args[0].family != socket.AF_UNIX or args[1] != path:
            reject()
        connections.append(path)
    elif event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    elif event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    elif event == 'open':
        if not isinstance(args[0], str) or not args[0].endswith(('.py', '.pyc')):
            reject()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()

original_socket = socket.socket
class ObservedSocket(original_socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        created.append(self)
    def send(self, data, *args):
        if case == 'stall':
            sent.extend(data)
            return len(data)  # Test injection: service awaits an unsent request.
        if case == 'partial':
            super().send(data[:1], *args)
            sent.extend(data)
            return len(data)  # Test injection: never finish the NUL framing.
        count = super().send(data, *args)
        sent.extend(data[:count])
        return count
    def recv(self, size, *args):
        chunk = super().recv(size, *args)
        if case == 'malformed' and chunk:
            return b'{"parameters":{},"parameters":{}}\0'
        received.extend(chunk)
        return chunk

socket.socket = ObservedSocket
for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'getnameinfo'):
    setattr(socket, name, reject)
ssl.SSLContext = reject
ssl.create_default_context = reject
ssl.SSLSocket.do_handshake = reject
threading.Thread.start = reject
_thread.start_new_thread = reject
os._Environ.__getitem__ = reject
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)

import openkube_optimizer.collection.resolver as rs
from openkube_optimizer.collection.preflight import _Preflight, _BearerToken
from openkube_optimizer.collection.kubeconfig import _Failure

if case.startswith('canary-'):
    actions = {
        'getaddrinfo': lambda: socket.getaddrinfo('canary.invalid', 443),
        'gethostbyname': lambda: socket.gethostbyname('canary.invalid'),
        'gethostbyname_ex': lambda: socket.gethostbyname_ex('canary.invalid'),
        'getnameinfo': lambda: socket.getnameinfo(('127.0.0.1', 443), 0),
        'tcp': lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        'unix': lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect('/tmp/forbidden-canary'),
        'tls': lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        'handshake': lambda: ssl.SSLSocket.do_handshake(None),
        'thread': lambda: threading.Thread(target=lambda: None).start(),
        'process': lambda: os.system('forbidden-canary'),
        'h11': lambda: __import__('h11'),
        'kubernetes': lambda: __import__('kubernetes'),
        'environment': lambda: os.environ['HOSTALIASES'],
        'file': lambda: open('/etc/resolv.conf'),
    }
    try:
        actions[case.removeprefix('canary-')]()
    except BaseException:
        pass
    # A swallowed exception must still be detected by the negative guard.
    assert not violations, 'Forbidden activity detected'

if case == 'import':
    assert not created and not connections
    result = None
elif case == 'unsupported':
    assert not native
    result = rs._resolve(_Preflight(hostname='example.com', port=443,
        authority='example.com', base_path='', ca_path=Path('/unused-ca'),
        auth=_BearerToken(token='unused-secret-canary')), deadline=time.monotonic()+1)
    assert result is _Failure.RESOLVER_UNAVAILABLE
    assert not created and not connections
else:
    assert native
    # The localhost fixture characterizes native IPv6/multiple replies only;
    # it does not claim endpoint-policy acceptance or public IPv6 DNS support.
    name = 'localhost.localdomain' if case == 'mixed' else (
        'openkube-synthetic-not-present.invalid' if case == 'failure' else 'example.com')
    endpoint = _Preflight(hostname=name, port=443, authority=name,
        base_path='', ca_path=Path('/unused-ca'), auth=_BearerToken(token='unused-secret-canary'))
    start = time.monotonic()
    duration = 0.05 if case in {'stall', 'partial'} else 3
    result = rs._resolve(endpoint, deadline=start+duration)
    elapsed = time.monotonic()-start
    assert endpoint.hostname == name and endpoint.authority == name
    assert connections == [path] and len(created) == 1
    assert json.loads(sent[:-1]) == {'method':'io.systemd.Resolve.ResolveHostname',
        'parameters':{'name':name,'family':0,'flags':256}}
    if case in {'stall', 'partial'}:
        assert result is _Failure.RESOLUTION_TIMEOUT
        assert duration*0.8 <= elapsed < duration+0.5
    elif case == 'malformed':
        assert result is _Failure.RESOLUTION_INVALID
    elif case == 'failure':
        assert result is _Failure.RESOLUTION_FAILED
        raw = json.loads(received[:-1])
        assert raw['error'] == 'io.systemd.Resolve.DNSError'
        assert raw['parameters']['rcode'] == 3
        del raw
    else:
        assert isinstance(result, rs._Resolution)
        raw = json.loads(received[:-1])
        records = raw['parameters']['addresses']
        expected = tuple(dict.fromkeys((a['family'], bytes(a['address']), a.get('ifindex')) for a in records))
        actual = tuple((a.family, a.packed, a.ifindex) for a in result.addresses)
        assert actual == expected and 1 <= len(records) <= 64
        if case == 'mixed':
            assert {a.family for a in result.addresses} == {2,10}
            assert len(result.addresses) >= 2
        else:
            assert any(a.family == 2 for a in result.addresses)
        assert repr(result) == '<resolver result: redacted>'
        del records, raw, expected, actual

assert not violations, 'Forbidden activity detected'
assert all(s.fileno() == -1 for s in created)
assert tuple(threading.enumerate()) == before_threads
if native:
    assert set(os.listdir('/proc/self/fd')) == before_fds
assert not any(n.split('.')[0] in {'kubernetes','h11','yaml'} for n in sys.modules)
print(json.dumps({'case':case,'local_connections':len(connections),
    'closed':True,'no_remote_tcp':True,'result':result.value if isinstance(result,_Failure) else 'private_result'}))
"""


def run(case: str, tmp_path: Path, *, canary: bool = False) -> dict[str, object]:
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", RESOLVER_SCRIPT, case],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env={
            "HOSTALIASES": "/unused-canary",
            "LOCALDOMAIN": "canary.invalid",
            "RES_OPTIONS": "ndots:15",
            "KUBECONFIG": "/unused-kubeconfig-canary",
        },
    )
    if canary:
        assert process.returncode != 0
        assert "Forbidden activity detected" in process.stderr
        assert not process.stdout
        return {}
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    value: object = json.loads(process.stdout)
    assert isinstance(value, dict)
    assert value["closed"] and value["no_remote_tcp"]
    return value


@pytest.fixture
def linux() -> None:
    if sys.platform != "linux":
        pytest.skip("Real resolved Varlink requires the native Ubuntu lab")


@pytest.mark.parametrize(
    "case", ["success", "mixed", "failure", "stall", "partial", "malformed"]
)
def test_real_varlink_only(linux: None, tmp_path: Path, case: str) -> None:
    assert run(case, tmp_path)["local_connections"] == 1


def test_import_is_inert_on_both_platforms(tmp_path: Path) -> None:
    assert run("import", tmp_path)["local_connections"] == 0


def test_macos_profile_fails_without_io(tmp_path: Path) -> None:
    if sys.platform != "darwin":
        # Ubuntu must have zero skips; unsupported behavior is mocked in units.
        return
    assert run("unsupported", tmp_path)["result"] == "resolver_unavailable"


@pytest.mark.parametrize(
    "canary",
    [
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "getnameinfo",
        "tcp",
        "unix",
        "tls",
        "handshake",
        "thread",
        "process",
        "h11",
        "kubernetes",
        "environment",
        "file",
    ],
)
def test_negative_side_effect_guards(tmp_path: Path, canary: str) -> None:
    run("canary-" + canary, tmp_path, canary=True)
