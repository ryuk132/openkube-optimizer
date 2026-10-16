"""Isolated real loopback TLS/HTTP probes reusable by clean installed wheels."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

HTTP_SCRIPT = r"""
import _thread
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
guarded = False
violations = []
selectors_seen = []
waits = []
server_errors = []
requests_seen = []
received_tail = []
written = bytearray()
stop = threading.Event()
threads = []
listeners = []
connection = None
stream = None
result = None
policy_before = None
context = None
CANARY = 'request-body-h11-native-diagnostic-canary'
PATH = '/api/v1/namespaces/synthetic/pods'

def caller():return threading.get_ident() == main

def deny(label):
    violations.append(label)
    raise AssertionError('Forbidden HTTP side effect')

def fds():
    return set(os.listdir('/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'))

baseline = fds()
original_selector = selectors.DefaultSelector
original_ssl_new = ssl.SSLContext.__new__
expected_status = 200
expected_body_size = len(CANARY)
deadline = 0.0  # Assigned once below, after fixture/context setup, before TCP/TLS.

if case != 'import':
    import h11
    from openkube_optimizer.collection import connection as cn, http as ht
    from openkube_optimizer.collection import preflight as pf, resolver as rs
    from openkube_optimizer.collection.credentials import _CredentialMaterial
    from openkube_optimizer.collection.kubeconfig import _Failure as F
    from openkube_optimizer.collection.tls import _TlsContext, _build_tls_context
    with _CredentialMaterial(ca_snapshot=(fixture/'server-ca.pem').read_bytes(), certificate_fd=None,key_fd=None) as material:
        context = _build_tls_context(material)
    assert isinstance(context,_TlsContext)
    def policy():
        c=context._context
        return (c.check_hostname,c.verify_mode,c.minimum_version,c.maximum_version,c.verify_flags,c.options,c.cert_store_stats(),c.get_ciphers())
    policy_before=policy()

    class ObservedSSL(ssl.SSLSocket):
        sends = 0
        reads = 0
        def send(self,data,*args,**kwargs):
            if guarded and caller():
                self.sends += 1
                if case == 'want-read' and self.sends == 1:raise ssl.SSLWantReadError()
                if case == 'want-write' and self.sends == 1:raise ssl.SSLWantWriteError()
                if case == 'write-failure':raise OSError(CANARY)
                if case == 'control' and self.sends == 2:raise KeyboardInterrupt(CANARY)
                if case in ('partial','control'):data=data[:7]
            count=super().send(data,*args,**kwargs)
            if guarded and caller():written.extend(data[:count])
            return count
        def recv(self,*args,**kwargs):
            if guarded and caller():self.reads += 1
            return super().recv(*args,**kwargs)
    context._context.sslsocket_class=ObservedSSL
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(fixture/'server.pem',fixture/'server-key.pem')
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listeners.append(listener)
    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
    port=listener.getsockname()[1]
    authority='API.Test.invalid:000'+str(port)
    parsed=pf._endpoint('https://'+authority+'/proxy/')
    assert isinstance(parsed,tuple)
    endpoint=pf._Preflight(hostname=parsed[0],port=parsed[1],authority=parsed[2],base_path=parsed[3],
        ca_path=Path('/unused-credential-canary'),auth=pf._BearerToken(token='unused-endpoint-auth-canary'))
    resolution=rs._Resolution((rs._ResolvedAddress(2,ipaddress.ip_address('127.0.0.1').packed,None),))

    NO_DRAIN = ('error-length', 'error-chunked', 'error-stall', 'error-same-chunk', 'error-interim', 'redirect-stall')

    def response_parts(server):
        global expected_status,expected_body_size
        body=CANARY.encode()
        normal=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        if case in NO_DRAIN:
            expected_status = 302 if case == 'redirect-stall' else 500 if case == 'error-chunked' else 429 if case == 'error-stall' else 404
            expected_body_size = 0
            framing = b'Transfer-Encoding: chunked' if case == 'error-chunked' else b'Content-Length: 999999999999'
            headers = f'HTTP/1.1 {expected_status} Synthetic\r\n'.encode() + framing + b'\r\n\r\n'
            if case == 'error-interim':headers = b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n' + headers
            yield headers + (body if case == 'error-same-chunk' else b'')
            # Do not send a body. Wait for client closure, not a harness signal:
            # draining would exhaust the caller deadline and fail the result.
            received_tail.append(server.recv(1))
            return
        if case == 'chunked':
            yield b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            for part in (body[:3],body[3:]):yield hex(len(part))[2:].encode()+b';x=synthetic\r\n'+part+b'\r\n'
            yield b'0\r\nX-Trailer: ignored\r\n\r\n'
        elif case == 'interim':
            yield b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: ignored\r\n\r\n'+normal
        elif case in ('redirect','denied','server-error'):
            expected_status={'redirect':302,'denied':403,'server-error':503}[case];expected_body_size=0
            yield f'HTTP/1.1 {expected_status} Synthetic\r\nLocation: https://redirect.invalid/\r\nRetry-After: 1\r\nContent-Length: '.encode()+str(len(body)).encode()+b'\r\n\r\n'+body
        elif case == 'empty':
            expected_status=204;expected_body_size=0
            yield b'HTTP/1.1 204 No Content\r\n\r\n'
        elif case == 'close':yield b'HTTP/1.0 200 OK\r\n\r\n'+body
        elif case == 'malformed':yield b'HTTP/1.1 '+body+b'\r\n\r\n'
        elif case == 'incomplete':yield b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc'
        elif case == 'conflicting':yield b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na'
        elif case == 'compressed':yield b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n'
        elif case == 'header-limit':
            yield b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: '+b'a'*16384+b'\r\n\r\n'
        elif case == 'count-limit':
            yield b'HTTP/1.1 200 OK\r\n'+b'Content-Length: 0\r\n'*129+b'\r\n'
        elif case == 'trailer-limit':
            yield b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: '+b'a'*16384+b'\r\n\r\n'
        elif case in ('body-exact','body-over'):
            expected_body_size=16*1024*1024+(case=='body-over')
            yield b'HTTP/1.1 200 OK\r\nContent-Length: '+str(expected_body_size).encode()+b'\r\n\r\n'
            for _ in range(256):yield b'x'*65536
            if case=='body-over':yield b'x'
        elif case in ('wire-exact','wire-over'):
            initial=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            limit=32*1024*1024+(case=='wire-over')
            yield initial
            remaining=limit-len(initial)-len(b'0\r\n\r\n')
            sizes=[]
            while remaining:
                size=min(8192,remaining)
                if 0 < remaining-size < 9:size-=9-(remaining-size)
                assert size>=9
                sizes.append(size);remaining-=size
            expected_body_size=len(sizes)
            for size in sizes:yield b'1;x='+b'a'*(size-9)+b'\r\nx\r\n'
            yield b'0\r\n\r\n'
        elif case=='multi-chunk':
            for offset in range(0,len(normal),3):yield normal[offset:offset+3]
        elif case=='stall-header':assert stop.wait(5)
        elif case=='stall-body':
            yield b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc'
            assert stop.wait(5)
        elif case=='no-response':return
        else:yield normal

    def serve():
        peer=None;server=None
        try:
            peer,_=listener.accept();peer.settimeout(5)
            server=server_context.wrap_socket(peer,server_side=True)
            if case=='want-read':server.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
            parser=h11.Connection(h11.SERVER,max_incomplete_event_size=16385)
            received=bytearray()
            while True:
                event=parser.next_event()
                if event is h11.NEED_DATA:
                    data=server.recv(4096)
                    received.extend(data)
                    assert len(received)<=16384
                    if not data:
                        assert case in ('expired','control','write-failure') or case.startswith('canary-')
                        return
                    parser.receive_data(data)
                elif isinstance(event,h11.Request):
                    assert event.method==b'GET' and event.target==b'/proxy'+PATH.encode()+b'?limit=200&continue=opaque%2B%2F%3D%25%26%23%3F'
                    fields=dict(event.headers)
                    assert fields[b'host']==authority.encode()
                    assert fields[b'authorization']==b'Bearer '+CANARY.encode()
                    assert fields[b'connection']==b'close'
                    assert fields[b'accept']==b'application/json'
                    assert b'accept-encoding' not in fields
                    assert b'unused-endpoint-auth-canary' not in received
                    requests_seen.append(bytes(received))
                elif isinstance(event,h11.EndOfMessage):break
                else:raise AssertionError('Unexpected request event/body')
            for part in response_parts(server):server.sendall(part)
            if case not in ('close','incomplete','no-response') + NO_DRAIN:
                received_tail.append(server.recv(1))
        except (ssl.SSLError,ConnectionError):pass
        except BaseException as error:server_errors.append(type(error).__name__)
        finally:
            if server is not None:server.close()
            if peer is not None and peer.fileno()>=0:peer.close()
            listener.close()
    thread=threading.Thread(target=serve,daemon=False)
    threads.append(thread);thread.start()
    deadline=time.monotonic() + (0.25 if case in ('stall-header','stall-body','expired') else 4)
    connection=cn._connect(endpoint,resolution,context,deadline=deadline)
    if not isinstance(connection,cn._TlsConnection):
        stop.set()
        for listener in listeners:listener.close()
        for thread in threads:thread.join(6);assert not thread.is_alive(),'TLS setup listener leaked'
        raise AssertionError('Synthetic TLS setup did not finish before caller deadline')
    stream=connection._socket
    assert isinstance(stream,ObservedSSL) and stream.gettimeout()==0
    request=ht._HttpRequest(path=PATH,query=(('limit','200'),('continue','opaque+/=%&#?')),
        headers=(('Authorization','Bearer '+CANARY),('User-Agent','synthetic HTTP gate')))
    if case=='expired':time.sleep(0.30) # Harness only: expire the original TLS/HTTP deadline.

class Selector(original_selector):
    def __init__(self):
        super().__init__();self.finished=False;self.events=None;selectors_seen.append(self)
    def register(self,stream,events,*args):
        self.events=events;return super().register(stream,events,*args)
    def select(self,timeout=None):
        assert timeout is not None and 0<timeout<=deadline-time.monotonic()+0.01
        waits.append(self.events)
        return super().select(timeout)
    def close(self):self.finished=True;return super().close()
selectors.DefaultSelector=Selector

def forbidden(*args,**kwargs):return deny('forbidden-call')
for name in ('getaddrinfo','gethostbyname','gethostbyname_ex','getnameinfo'):setattr(socket,name,forbidden)
if case!='import':rs._resolve=forbidden

def guarded_method(original,label):
    def wrapped(*args,**kwargs):
        if caller():deny(label)
        return original(*args,**kwargs)
    return wrapped

def new_context(cls,*args,**kwargs):
    if caller():deny('context')
    return original_ssl_new(cls,*args,**kwargs)
ssl.SSLContext.__new__=staticmethod(new_context)
for name in ('set_ciphers','set_alpn_protocols','load_default_certs','set_default_verify_paths','load_verify_locations','load_cert_chain'):
    setattr(ssl.SSLContext,name,guarded_method(getattr(ssl.SSLContext,name),name))
ssl.SSLSocket.do_handshake=guarded_method(ssl.SSLSocket.do_handshake,'handshake')
ssl.SSLSocket.unwrap=guarded_method(ssl.SSLSocket.unwrap,'shutdown')
for cls in (socket.socket,ssl.SSLSocket):
    for name in ('connect','connect_ex'):setattr(cls,name,guarded_method(getattr(cls,name),'connect'))
threading.Thread.start=guarded_method(threading.Thread.start,'thread')
_thread.start_new_thread=guarded_method(_thread.start_new_thread,'thread')
os._Environ.__getitem__=guarded_method(os._Environ.__getitem__,'environment')

class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        top=fullname.partition('.')[0]
        if fullname=='http.client' or fullname=='urllib.request' or (top not in sys.stdlib_module_names and top not in ('openkube_optimizer','h11')):
            deny('import')
sys.meta_path.insert(0,Imports())

def audit(event,args):
    if not guarded or not caller():return
    if event.startswith('socket.'):deny('socket')
    if event=='open':
        path=args[0]
        if not isinstance(path,str) or not path.endswith(('.py','.pyc')) or args[1] not in ('r',None):deny('file')
    if event.startswith(('subprocess.','os.exec','os.spawn')) or event in ('os.system','os.fork','os.posix_spawn'):deny('process')
sys.addaudithook(audit)
guarded=True
try:
    if case=='import':
        from openkube_optimizer.collection import http as ht
        assert not {'h11','kubernetes','yaml'} & sys.modules.keys()
        result='inert'
    elif case.startswith('canary-'):
        name=case.removeprefix('canary-')
        try:
            if name=='dns':socket.getaddrinfo('canary.invalid',443)
            elif name=='resolved':rs._resolve(endpoint,deadline=deadline)
            elif name=='socket':socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            elif name=='connect':stream.connect_ex(('192.0.2.254',443))
            elif name=='context':ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            elif name=='trust':context._context.load_default_certs()
            elif name=='credentials':context._context.load_cert_chain('/credential-canary')
            elif name=='handshake':stream.do_handshake()
            elif name=='kubernetes':__import__('kubernetes')
            elif name=='urllib3':__import__('urllib3')
            elif name=='requests':__import__('requests')
            elif name=='http-client':__import__('http.client')
            elif name=='thread':threading.Thread(target=lambda:None).start()
            elif name=='process':os.system('false')
            elif name=='environment':os.environ['KUBECONFIG']
            elif name=='file':Path('/credential-canary').read_bytes()
            else:raise AssertionError('Unknown canary')
        except AssertionError:pass # Ledger must expose swallowed attempts below.
        result='canary'
    else:
        started=time.monotonic()
        try:value=ht._exchange(endpoint,connection,request,deadline=deadline)
        except KeyboardInterrupt:
            assert case=='control';result='control-flow'
        else:
            if isinstance(value,ht._HttpResponse):
                assert case not in ('malformed','incomplete','conflicting','compressed','no-response','header-limit','count-limit','trailer-limit','body-over','wire-over','stall-header','stall-body','expired','write-failure')
                assert value.status==expected_status and len(value.body)==expected_body_size
                assert repr(value)=='<HTTP response: redacted>' and CANARY not in str(value)
                assert not hasattr(value,'headers')
                result='response'
                if case=='retry-closed':assert ht._exchange(endpoint,connection,request,deadline=deadline) is F.HTTP_CONNECTION_CLOSED
            else:
                expected=(F.TRANSPORT_DEADLINE_EXPIRED if case in ('stall-header','stall-body','expired')
                    else F.HTTP_RESPONSE_TOO_LARGE if case in ('header-limit','count-limit','trailer-limit','body-over','wire-over')
                    else F.HTTP_CONNECTION_CLOSED if case=='no-response'
                    else F.HTTP_WRITE_FAILED if case=='write-failure' else F.HTTP_RESPONSE_INVALID)
                assert value is expected
                assert CANARY not in str(value)
                result=value.value
        elapsed=time.monotonic()-started
        if case in ('stall-header','stall-body'):assert elapsed<0.6 and time.monotonic()-deadline<0.6
        assert written.count(b'GET ') == (0 if case in ('expired','write-failure') else 1)
        if case in NO_DRAIN:
            assert connection._socket is None and stream.fileno() == -1
            assert all(selector.finished for selector in selectors_seen)
            assert elapsed < 1.0 and time.monotonic() < deadline
            assert value.body == b'' and CANARY not in repr(value) + str(value)
        if case=='partial':assert stream.sends>2
        if case=='want-read':assert selectors.EVENT_READ in waits
        if case=='want-write':assert selectors.EVENT_WRITE in waits
finally:
    guarded=False
    if connection is not None:connection.close();assert connection._socket is None
    if stream is not None:assert stream.fileno()==-1
    stop.set()
    for thread in threads:thread.join(6);assert not thread.is_alive(),'HTTP listener leaked'
    for listener in listeners:listener.close()
    assert not server_errors,'Synthetic HTTP server failed'
    assert not any(received_tail),'HTTP request retried/pipelined'
    assert all(selector.finished for selector in selectors_seen)
    if context is not None:assert policy()==policy_before
    assert fds()==baseline,'HTTP descriptor leak'
assert not violations,'HTTP side-effect guard rejected attempt'
if case not in ('import','expired','write-failure','control') and not case.startswith('canary-'):
    assert len(requests_seen)==1
print(json.dumps({'case':case,'result':result,'requests':len(requests_seen),'closed':True,'no_dns':True,'no_connect':True,'no_sdk':True,'no_retry':True,'no_redirect':True}))
"""

CASES = (
    "import",
    "length",
    "chunked",
    "empty",
    "multi-chunk",
    "interim",
    "redirect",
    "denied",
    "server-error",
    "error-length",
    "error-chunked",
    "error-stall",
    "error-same-chunk",
    "error-interim",
    "redirect-stall",
    "close",
    "malformed",
    "incomplete",
    "conflicting",
    "compressed",
    "no-response",
    "header-limit",
    "count-limit",
    "trailer-limit",
    "body-exact",
    "body-over",
    "wire-exact",
    "wire-over",
    "stall-header",
    "stall-body",
    "expired",
    "partial",
    "want-read",
    "want-write",
    "control",
    "write-failure",
    "retry-closed",
)
CANARIES = (
    "dns",
    "resolved",
    "socket",
    "connect",
    "context",
    "trust",
    "credentials",
    "handshake",
    "kubernetes",
    "urllib3",
    "requests",
    "http-client",
    "thread",
    "process",
    "environment",
    "file",
)


def run(case: str, tmp_path: Path, *, canary: bool = False) -> dict[str, object]:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", HTTP_SCRIPT, case, str(fixtures)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if canary:
        assert process.returncode != 0
        assert "HTTP side-effect guard rejected attempt" in process.stderr
        assert not process.stdout
        return {}
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    value: object = json.loads(process.stdout)
    assert isinstance(value, dict)
    assert all(
        value[k]
        for k in ("closed", "no_dns", "no_connect", "no_sdk", "no_retry", "no_redirect")
    )
    return value


@pytest.mark.parametrize("case", CASES)
def test_real_single_request_http(tmp_path: Path, case: str) -> None:
    run(case, tmp_path)


@pytest.mark.parametrize("canary", CANARIES)
def test_negative_http_guards(tmp_path: Path, canary: str) -> None:
    run("canary-" + canary, tmp_path, canary=True)
