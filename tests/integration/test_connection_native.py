"""Isolated real loopback TCP/TLS probes; also run from clean installed wheels.

Only the synthetic server harness starts threads/listeners. Guards apply to
its calling thread after fixture/context/server setup, before M3.4B import or
execution. Negative canaries prove attempted and swallowed violations fail.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

CONNECTION_SCRIPT = r"""
import _thread
import copy
import importlib.abc
import ipaddress
import json
import os
import selectors
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

case, fixture = sys.argv[1:]
fixture = Path(fixture)
main = threading.get_ident()
violations = []
attempts = []
raw_sockets = []
ssl_sockets = []
closed_fds = []
closed_owners = []
selector_objects = []
waits = []
names = []
server_errors = []
received = []
stop = threading.Event()
original_socket = socket.socket
original_selector = selectors.DefaultSelector
original_ssl_new = ssl.SSLContext.__new__
original_handshake = ssl.SSLSocket.do_handshake
allowed = []
active_deadline = float('inf')
guarded = False

def caller():
    return threading.get_ident() == main

def deny(label):
    violations.append(label)
    raise AssertionError('Forbidden connection side effect')

def descriptors():
    directory = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
    return set(os.listdir(directory))

baseline = descriptors()
threads = []
listeners = []
policy_before = None
context = None
endpoint = None
resolution = None
cn = None

if case != 'import':
    from openkube_optimizer.collection import connection as cn
    from openkube_optimizer.collection import preflight as pf
    from openkube_optimizer.collection import resolver as rs
    from openkube_optimizer.collection.credentials import _CredentialMaterial
    from openkube_optimizer.collection.kubeconfig import _Failure as F
    from openkube_optimizer.collection.tls import _TlsContext, _build_tls_context
    with _CredentialMaterial(ca_snapshot=(fixture / 'server-ca.pem').read_bytes(),
                             certificate_fd=None, key_fd=None) as material:
        context = _build_tls_context(material)
    assert isinstance(context, _TlsContext)

    def policy():
        c = context._context
        return (c.check_hostname, c.verify_mode, c.minimum_version,
                c.maximum_version, c.verify_flags, c.options,
                c.cert_store_stats(), c.get_ciphers())

    policy_before = policy()

    class ObservedSSL(ssl.SSLSocket):
        def _real_close(self):
            if caller() and self.fileno() >= 0:
                closed_fds.append(self.fileno())
                closed_owners.append(id(self))
            return super()._real_close()

        def do_handshake(self, *args, **kwargs):
            if caller():
                assert self.gettimeout() == 0
                if self not in ssl_sockets:
                    ssl_sockets.append(self)
                if case == 'want-write' and not getattr(self, '_injected', False):
                    self._injected = True
                    raise ssl.SSLWantWriteError()
                if case == 'interrupt':
                    raise KeyboardInterrupt('control-flow-canary')
                if case == 'system-exit':
                    raise SystemExit('control-flow-canary')
            return super().do_handshake(*args, **kwargs)

    context._context.sslsocket_class = ObservedSSL
    server_cert = {'wrong-host': 'wrong-host.pem', 'ip-only': 'ip-only.pem',
                   'untrusted': 'untrusted-server.pem'}.get(case, 'server.pem')
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(fixture / server_cert, fixture / 'server-key.pem')
    server_context.set_servername_callback(lambda stream, name, ctx: names.append(name))

    def serve(listener, behavior):
        peer = None
        stream = None
        try:
            listener.settimeout(2)
            peer, _ = listener.accept()
            peer.settimeout(2)
            if behavior == 'eof':
                return
            if behavior == 'protocol':
                # Invalid TLS record, never HTTP or application request bytes.
                peer.sendall(b'\x00\x00\x00\x00\x00')
                return
            if behavior == 'stall':
                assert stop.wait(2), 'Unreleased synthetic stalled peer'
                return
            stream = server_context.wrap_socket(peer, server_side=True)
            received.append(stream.recv(1))
        except ssl.SSLError:
            # Expected handshake alerts/EOF on rejected synthetic certificates.
            pass
        except ConnectionError:
            pass
        except BaseException as error:
            # Test harness must surface its own faults after bounded joining.
            server_errors.append(type(error).__name__)
        finally:
            if stream is not None:
                stream.close()
            if peer is not None and peer.fileno() >= 0:
                peer.close()
            listener.close()

    def listen(address, port, behavior):
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        listener = original_socket(family, socket.SOCK_STREAM)
        listeners.append(listener)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, port))
        listener.listen(1)
        thread = threading.Thread(target=serve, args=(listener, behavior), daemon=False)
        threads.append(thread)
        thread.start()
        return listener.getsockname()[1]

    no_listener = case.startswith('canary-') or case in ('expired', 'all-refused')
    address = '::1' if case == 'ipv6' else '127.0.0.1'
    if no_listener:
        reservation = original_socket(socket.AF_INET, socket.SOCK_STREAM)
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
        reservation.close()
    else:
        behavior = {'eof-fallback': 'eof', 'protocol-fatal': 'protocol',
                    'stall': 'stall', 'wrap-pre': 'stall',
                    'wrap-post': 'stall', 'wrap-control': 'stall',
                    'interrupt': 'stall', 'system-exit': 'stall',
                    'context-exception': 'tls'}.get(case, 'tls')
        port = listen(address, 0, behavior)
        if case == 'eof-fallback':
            listen('::1', port, 'tls')
    addresses = [address]
    if case == 'refusal':
        addresses = ['::1', address, address]
    if case in ('eof-fallback', 'wrong-host', 'ip-only', 'untrusted',
                'protocol-fatal', 'stall'):
        addresses = ['127.0.0.1', '::1']
    if case == 'all-refused':
        addresses = ['::1', '127.0.0.1']
    records = []
    for address in addresses:
        packed = ipaddress.ip_address(address)
        family = 2 if packed.version == 4 else 10
        records.append({'family': family, 'address': list(packed.packed), 'ifindex': 1})
        allowed.append((address, port) if family == 2 else (address, port, 0, 0))
    resolution = rs._parse_reply(json.dumps({'parameters': {
        'addresses': records, 'name': 'ignored-resolver-canonical-canary',
        'flags': 1}}).encode() + b'\0')
    assert isinstance(resolution, rs._Resolution)
    allowed = list(dict.fromkeys(allowed))
    values = pf._endpoint('https://API.Test.invalid:' + str(port) + '/unused')
    assert isinstance(values, tuple)
    endpoint = pf._Preflight(hostname=values[0], port=values[1], authority=values[2],
        base_path=values[3], ca_path=Path('/unused-credential-canary'),
        auth=pf._BearerToken(token='unused-authorization-canary'))
    if case == 'wrap-pre':
        context._context.wrap_socket = lambda *a, **k: (_ for _ in ()).throw(
            OSError('pre-detachment-canary'))
    if case in ('wrap-post', 'wrap-control'):
        def fail_wrap(*args, **kwargs):
            if case == 'wrap-control':
                raise KeyboardInterrupt('post-detachment-canary')
            raise OSError('post-detachment-canary')
        context._context._wrap_socket = fail_wrap

class ObservedRaw(original_socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if caller():
            raw_sockets.append(self)

    def connect_ex(self, target):
        # CPython connect_ex does not emit socket.connect audit events.
        if caller():
            if target not in allowed:
                deny('unapproved-address')
            attempts.append(target)
            assert len(attempts) <= len(allowed)
        assert self.gettimeout() == 0
        return super().connect_ex(target)

    def setblocking(self, value):
        if caller():
            assert value is False
        return super().setblocking(value)

    def send(self, *args, **kwargs):
        if caller():
            deny('raw-application-write')
        return super().send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        if caller():
            deny('raw-application-write')
        return super().sendall(*args, **kwargs)

    def getsockopt(self, level, option, *args):
        if caller():
            assert level == socket.SOL_SOCKET and option in (socket.SO_ERROR, socket.SO_TYPE)
            if option == socket.SO_ERROR:
                self.error_checked = True
        return super().getsockopt(level, option, *args)

    def close(self):
        if caller() and self.fileno() >= 0:
            closed_fds.append(self.fileno())
            closed_owners.append(id(self))
        return super().close()

class ObservedSelector(original_selector):
    def __init__(self):
        super().__init__()
        self.finished = False
        self.direction = None
        selector_objects.append(self)

    def register(self, stream, events, *args):
        self.direction = events
        return super().register(stream, events, *args)

    def select(self, timeout=None):
        assert timeout is not None and 0 < timeout <= 5
        assert timeout <= active_deadline - time.monotonic() + 0.01
        waits.append(self.direction)
        return super().select(timeout)

    def close(self):
        self.finished = True
        return super().close()

socket.socket = ObservedRaw
selectors.DefaultSelector = ObservedSelector

def forbidden(*args, **kwargs):
    return deny('forbidden-call')

for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'getnameinfo'):
    setattr(socket, name, forbidden)
if case != 'import':
    rs._resolve = forbidden

# Existing context wrapping/handshake are allowed; fresh context/policy/file
# setup and application I/O in the production calling thread are forbidden.
def context_new(cls, *args, **kwargs):
    if caller():
        deny('new-context')
    return original_ssl_new(cls, *args, **kwargs)
ssl.SSLContext.__new__ = staticmethod(context_new)

def guarded_method(original, label):
    def wrapped(*args, **kwargs):
        if caller():
            deny(label)
        return original(*args, **kwargs)
    return wrapped

for name in ('set_ciphers', 'load_default_certs', 'set_default_verify_paths',
             'load_verify_locations', 'load_cert_chain', 'set_alpn_protocols'):
    setattr(ssl.SSLContext, name, guarded_method(getattr(ssl.SSLContext, name), name))
for name in ('send', 'sendall', 'write', 'recv', 'recv_into', 'read', 'unwrap'):
    setattr(ssl.SSLSocket, name, guarded_method(getattr(ssl.SSLSocket, name), name))
threading.Thread.start = guarded_method(threading.Thread.start, 'thread')
_thread.start_new_thread = guarded_method(_thread.start_new_thread, 'thread')
os._Environ.__getitem__ = guarded_method(os._Environ.__getitem__, 'environment')

class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.partition('.')[0]
        if top not in sys.stdlib_module_names and top != 'openkube_optimizer':
            deny('external-import')
sys.meta_path.insert(0, Imports())

def audit(event, args):
    if not guarded or not caller():
        return
    if event == 'socket.__new__':
        if case == 'import' or args[1] not in (socket.AF_INET, socket.AF_INET6) or args[2] != socket.SOCK_STREAM:
            deny('socket-family')
    elif event == 'socket.connect':
        target = args[1]
        if target not in allowed:
            deny('unapproved-address')
    elif event.startswith('socket.'):
        deny('socket-operation')
    elif event == 'open':
        path = args[0]
        if not isinstance(path, str) or not path.endswith(('.py', '.pyc')) or args[1] not in ('r', None):
            deny('file')
    elif event.startswith(('subprocess.', 'os.exec', 'os.spawn')) or event in ('os.system', 'os.fork', 'os.posix_spawn'):
        deny('helper')
sys.addaudithook(audit)
guarded = True
result = None
try:
    if case == 'import':
        from openkube_optimizer.collection import connection as cn
        assert not raw_sockets and not selector_objects
        assert not {'h11', 'kubernetes', 'yaml'} & sys.modules.keys()
        result = 'inert'
    elif case.startswith('canary-'):
        name = case.removeprefix('canary-')
        try:
            if name == 'dns': socket.getaddrinfo('canary.invalid', 443)
            elif name == 'resolved': rs._resolve(endpoint, deadline=time.monotonic()+1)
            elif name == 'unix': socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            elif name == 'address':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
                    raw.setblocking(False)
                    raw.connect_ex(('192.0.2.254', 443))
            elif name == 'context': ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            elif name == 'trust': context._context.load_default_certs()
            elif name == 'credentials': context._context.load_cert_chain('/credential-canary')
            elif name == 'ciphers': context._context.set_ciphers('DEFAULT')
            elif name == 'alpn': context._context.set_alpn_protocols(['http/1.1'])
            elif name == 'h11': __import__('h11')
            elif name == 'kubernetes': __import__('kubernetes')
            elif name == 'process': os.system('false')
            elif name == 'thread': threading.Thread(target=lambda: None).start()
            elif name == 'environment': os.environ['KUBECONFIG']
            elif name == 'file': Path('/credential-canary').read_bytes()
            elif name == 'http': ssl.SSLSocket.sendall(None, b'GET / HTTP/1.1\r\n\r\n')
            else: raise AssertionError('Unknown negative canary')
        except AssertionError:
            pass  # Swallowing must not hide the ledger violation below.
        result = 'canary'
    else:
        active_deadline = time.monotonic() + (0.08 if case == 'stall' else 2)
        if case == 'expired':
            active_deadline = time.monotonic() - 1
        try:
            value = cn._connect(endpoint, resolution, context, deadline=active_deadline)
        except (KeyboardInterrupt, SystemExit) as error:
            assert case in ('interrupt', 'system-exit', 'wrap-control')
            assert type(error) is (SystemExit if case == 'system-exit' else KeyboardInterrupt)
            result = 'control-flow'
        else:
            if isinstance(value, cn._TlsConnection):
                assert case in ('success', 'ipv6', 'refusal', 'eof-fallback', 'want-write', 'context-exception')
                assert value._socket is not None and value._socket.fileno() >= 0
                assert repr(value) == '<TLS connection: redacted>'
                if case == 'context-exception':
                    try:
                        with value:
                            raise KeyboardInterrupt('holder-control-canary')
                    except KeyboardInterrupt:
                        pass
                else:
                    value.close()
                value.close()
                assert value._socket is None
                result = 'connected'
            else:
                expected = (F.TLS_VERIFICATION_FAILED if case in ('wrong-host', 'ip-only', 'untrusted')
                    else F.TRANSPORT_DEADLINE_EXPIRED if case in ('expired', 'stall')
                    else F.CONNECTION_FAILED if case == 'all-refused'
                    else F.TLS_HANDSHAKE_FAILED)
                assert value is expected
                result = value.value
            count = 0 if case == 'expired' else 2 if case in ('refusal', 'eof-fallback', 'all-refused') else 1
            assert len(attempts) == count
            assert attempts == allowed[:count]
finally:
    guarded = False
    stop.set()
    for thread in threads:
        thread.join(3)
        assert not thread.is_alive(), 'Synthetic listener leaked'
    for listener in listeners:
        listener.close()
    if context is not None:
        assert policy() == policy_before
    assert not server_errors, 'Synthetic server failed'
    assert all(not data for data in received), 'Application bytes transmitted'
    assert all(raw.fileno() == -1 for raw in raw_sockets)
    assert all(stream.fileno() == -1 for stream in ssl_sockets)
    assert all(selector.finished for selector in selector_objects)
    assert len(closed_owners) == len(set(closed_owners)), 'Owned descriptor closed twice'
    # fd numbers can legitimately be reused between ordered candidates. Every
    # owned object is closed, native wrap probes establish no double closing.
    assert descriptors() == baseline, 'Connection descriptor leak'
assert not violations, 'Connection side-effect guard rejected attempt'
if case not in ('import', 'expired', 'all-refused') and not case.startswith('canary-'):
    if case not in ('wrap-pre', 'wrap-post', 'wrap-control', 'interrupt', 'system-exit', 'stall', 'protocol-fatal'):
        assert names == ['API.Test.invalid'] * (1 if case == 'eof-fallback' else len(attempts) - (1 if case == 'refusal' else 0))
    if case in ('success', 'ipv6', 'refusal', 'eof-fallback', 'context-exception'):
        assert selectors.EVENT_READ in waits
    if case == 'want-write':
        assert selectors.EVENT_WRITE in waits
print(json.dumps({'case': case, 'result': result, 'attempts': len(attempts),
                  'closed': True, 'no_dns': True, 'no_http': True,
                  'no_sdk': True, 'sni': bool(names)}))
"""

CASES = (
    "import",
    "success",
    "ipv6",
    "refusal",
    "eof-fallback",
    "wrong-host",
    "ip-only",
    "untrusted",
    "protocol-fatal",
    "expired",
    "all-refused",
    "stall",
    "want-write",
    "wrap-pre",
    "wrap-post",
    "wrap-control",
    "interrupt",
    "system-exit",
    "context-exception",
)
CANARIES = (
    "dns",
    "resolved",
    "unix",
    "address",
    "context",
    "trust",
    "credentials",
    "ciphers",
    "alpn",
    "h11",
    "kubernetes",
    "process",
    "thread",
    "environment",
    "file",
    "http",
)


def run(case: str, tmp_path: Path, *, canary: bool = False) -> dict[str, object]:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", CONNECTION_SCRIPT, case, str(fixtures)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
    )
    if canary:
        assert process.returncode != 0
        assert "Connection side-effect guard rejected attempt" in process.stderr
        assert not process.stdout
        return {}
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    value: object = json.loads(process.stdout)
    assert isinstance(value, dict)
    assert value["closed"] and value["no_dns"] and value["no_http"] and value["no_sdk"]
    return value


@pytest.mark.parametrize("case", CASES)
def test_real_numeric_tcp_tls(tmp_path: Path, case: str) -> None:
    run(case, tmp_path)


@pytest.mark.parametrize("canary", CANARIES)
def test_negative_connection_guards(tmp_path: Path, canary: str) -> None:
    run("canary-" + canary, tmp_path, canary=True)
