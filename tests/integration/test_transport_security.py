"""M3.4D: compose unchanged private boundaries under strict test-only guards.

Native Varlink runs independently. Composed tests inject only resolver results
(and explicitly identified clocks/faults), then use actual loopback TCP/TLS/HTTP.
No production orchestrator, fixture material or behavior is added by this gate.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

TRANSPORT_SCRIPT = r"""
import _thread
import copy
import dataclasses
import errno
import gc
import importlib.abc
import ipaddress
import json
import os
import pickle
import selectors
import socket
import ssl
import sys
import threading
import time
import weakref
from pathlib import Path

case, fixture = sys.argv[1:]
fixture = Path(fixture)
main = threading.get_ident()
active = False
phase = 'setup'
violations = []
attempts = []
raws = []
streams = []
selectors_seen = []
closed_owners = []
trace = []
sni = []
requests_seen = []
written = bytearray()
server_errors = []
server_tail = []
stop = threading.Event()
connection = None
selected = None
result = None
deadline = 0.0
http_calls = 0
resolve_calls = 0
fatal_identity = False
parser_refs = []
HOST = 'API.Test.invalid'
CANARY = 'transport-host-header-body-openssl-h11-errno-canary'
TOKEN = 'opaque-transport-token-canary~+/=%!'
REDIRECT = 'Redirect.Transport-Canary.invalid'
PATH = '/api/v1/namespaces/synthetic/pods'
real_monotonic = time.monotonic
original_socket = socket.socket
original_selector = selectors.DefaultSelector
original_ssl_new = ssl.SSLContext.__new__
authority_keys = {'KUBECONFIG','HOME','SSL_CERT_FILE','SSL_CERT_DIR',
    'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy',
    'all_proxy','no_proxy','LOCALDOMAIN','RES_OPTIONS','HOSTALIASES','SSLKEYLOGFILE'}

def caller():return threading.get_ident() == main

def deny(label):
    violations.append(label)
    raise AssertionError('Forbidden composed transport action')

def fds():return set(os.listdir('/proc/self/fd' if sys.platform=='linux' else '/dev/fd'))
baseline = fds()
before_threads = tuple(threading.enumerate())

def safe(value):
    secrets=(HOST,TOKEN,TOKEN.split('~')[0],CANARY,REDIRECT,'127.0.0.1','::1',str(port))
    assert not isinstance(value,BaseException)
    assert all(getattr(value,name,None) is None for name in ('__cause__','__context__','__traceback__'))
    for text in (repr(value),str(value)):
        assert not any(x.lower() in text.lower() for x in secrets)
    for operation in (lambda:value.__getstate__(),lambda:value.__reduce__(),
        lambda:value.__reduce_ex__(4),lambda:pickle.dumps(value),lambda:copy.copy(value),
        lambda:copy.deepcopy(value),lambda:vars(value),lambda:dataclasses.asdict(value),
        lambda:json.dumps(value)):
        try:
            exposed=operation()
        except (TypeError,AttributeError) as error:
            assert not any(x.lower() in str(error).lower() for x in secrets)
        else:
            assert not any(x.lower() in str(exposed).lower() for x in secrets)

class Abort(BaseException):pass
control_kind = KeyboardInterrupt if case.endswith('keyboard') else SystemExit if case.endswith('system') else Abort

def interrupt(stage):
    if case == 'control-'+stage+'-keyboard' or case == 'control-'+stage+'-system' or case == 'control-'+stage+'-base':
        raise control_kind()

clocked = case.startswith(('budget-','expired-','cap-')) or case=='canary-cap'
clock = [100.0]
def now():return clock[0] if clocked else real_monotonic()
def spend(stage):
    if not clocked:return
    successful={'resolve':0.10,'first-tcp':0.10,'tls':0.15,'write':0.10,'headers':0.10,'body':0.10}
    exhausting={'resolve':0.20,'first-tcp':0.20,'tls':0.20,'write':0.20,'headers':0.25,'body':0.25}
    table=successful if case=='budget-success' else exhausting if case.startswith('budget-') else {}
    if case=='budget-body':table=dict(exhausting,headers=0.05)
    clock[0]+=table.get(stage,0)

def check_deadline(stage,value):
    if value != deadline:deny('deadline-reset')
    trace.append((stage,value,now()))

def guard_method(original,label):
    def call(*args,**kwargs):
        if active and caller():deny(label)
        return original(*args,**kwargs)
    return call

from openkube_optimizer.collection import connection as cn, http as ht, preflight as pf, resolver as rs
from openkube_optimizer.collection.credentials import _CredentialMaterial
from openkube_optimizer.collection.kubeconfig import _Failure as F
from openkube_optimizer.collection.tls import _TlsContext,_build_tls_context
import h11
assert h11.__version__=='0.16.0'
with _CredentialMaterial(ca_snapshot=(fixture/'server-ca.pem').read_bytes(),certificate_fd=None,key_fd=None) as material:
    context=_build_tls_context(material)
assert isinstance(context,_TlsContext)
def policy():
    c=context._context
    return (c.check_hostname,c.verify_mode,c.minimum_version,c.maximum_version,c.verify_flags,c.options,c.cert_store_stats(),c.get_ciphers())
policy_before=policy()
server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_context.load_cert_chain(fixture/('wrong-host.pem' if case in ('verification','canary-verification') else 'ip-only.pem' if case=='ip-identity' else 'server.pem'),fixture/'server-key.pem')
server_context.set_servername_callback(lambda stream,name,ctx:sni.append(name))
listener=original_socket(socket.AF_INET,socket.SOCK_STREAM)
listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(0.1)
port=listener.getsockname()[1]
prefix={'root':'/','prefix':'/fixed','prefix-trailing':'/fixed/'}.get(case,'/proxy/')
authority=HOST+':000'+str(port)
parts=pf._endpoint('https://'+authority+prefix)
assert isinstance(parts,tuple)
auth=pf._authentication({'token':TOKEN},Path('/unused-credential-origin'))
assert isinstance(auth,pf._BearerToken) and auth.token==TOKEN
endpoint=pf._Preflight(hostname=parts[0],port=parts[1],authority=parts[2],base_path=parts[3],ca_path=Path('/unused-credential-canary'),auth=auth)
query=(('limit','200'),('continue','opaque+/=%&#?'))
request=ht._HttpRequest(path=PATH,query=query,headers=() if case=='no-auth-header' else (('Authorization','Bearer '+auth.token),))
if case=='invalid-header':request=ht._HttpRequest(path=PATH,headers=(('Authorization','Bearer '+TOKEN+'\r\nHost: '+REDIRECT),))
expected_target=(prefix+(PATH[1:] if prefix.endswith('/') else PATH)+'?limit=200&continue=opaque%2B%2F%3D%25%26%23%3F').encode()

# Linux wire families/indices are projected by the actual M3.4A parser. Exact
# duplicates are deliberately presented before the TCP candidate boundary.
def record(address,index=1):
    ip=ipaddress.ip_address(address)
    return {'family':2 if ip.version==4 else 10,'address':list(ip.packed),'ifindex':index}
records=[record('::1'),record('::1'),record('127.0.0.1'),record('127.0.0.1')]
if case=='first-success':records=[record('127.0.0.1'),record('::1')]
if case in ('verification','ip-identity','protocol','canary-verification'):
    records=[record('127.0.0.1'),record('::1')]
if case=='raw-limit':records=[record('::1')]*65
if case=='raw-sixtyfour':records=[record('::1')]*63+[record('127.0.0.1')]
resolution_wire=json.dumps({'parameters':{'addresses':records,'name':'Canonical.Transport-Canary.invalid','flags':1}}).encode()+b'\0'
expected_addresses=[]
for r in records:
    address=str(ipaddress.ip_address(bytes(r['address'])))
    target=(address,port) if r['family']==2 else (address,port,0,0)
    if target not in expected_addresses:expected_addresses.append(target)

expected_status=200
expected_size=len(CANARY)
def response_parts():
    global expected_status,expected_size
    body=CANARY.encode()
    if case in ('redirect302','redirect307','redirect308','denied','server-error'):
        expected_status={'redirect302':302,'redirect307':307,'redirect308':308,'denied':403,'server-error':503}[case];expected_size=0
    if case=='malformed':yield b'HTTP/1.1 '+body+b'\r\n\r\n';return
    if case=='incomplete':yield b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc';return
    if case=='switch':yield b'HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: canary\r\n\r\n';return
    if case.startswith('compressed-'):
        yield b'HTTP/1.1 200 OK\r\nContent-Encoding: '+case.removeprefix('compressed-').encode()+b'\r\nContent-Length: 0\r\n\r\n';return
    if case=='metadata-over':yield b'HTTP/1.1 200 OK\r\nX: '+b'x'*16384+b'\r\nContent-Length: 0\r\n\r\n';return
    if case=='fields-over':yield b'HTTP/1.1 200 OK\r\n'+b'Content-Length: 0\r\n'*129+b'\r\n';return
    if case in ('chunked','body-exact','body-over','canary-body','wire-exact','wire-over','canary-wire'):
        initial=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n';yield initial
        if case in ('body-exact','body-over','canary-body'):
            expected_size=16*1024*1024+(case!='body-exact')
            for _ in range(256):yield b'10000\r\n'+b'x'*65536+b'\r\n'
            if case!='body-exact':yield b'1\r\nx\r\n'
        elif case in ('wire-exact','wire-over','canary-wire'):
            limit=32*1024*1024+(case!='wire-exact');remaining=limit-len(initial)-5;sizes=[]
            while remaining:
                size=min(8192,remaining)
                if 0<remaining-size<9:size-=9-(remaining-size)
                assert size>=9;sizes.append(size);remaining-=size
            expected_size=len(sizes)
            for size in sizes:yield b'1;x='+b'a'*(size-9)+b'\r\nx\r\n'
        else:
            yield hex(len(body))[2:].encode()+b';x=canary\r\n'+body+b'\r\n'
        yield b'0\r\nX-Trailer: discarded\r\n\r\n' if case=='chunked' else b'0\r\n\r\n'
        return
    if case=='interim':
        for _ in range(10):yield b'HTTP/1.1 103 Early Hints\r\nLink: ignored\r\n\r\n'
    yield f'HTTP/1.1 {expected_status} Synthetic\r\n'.encode()+b'Location: https://'+REDIRECT.encode()+b'/different\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'
    if case=='real-budget':
        time.sleep(0.03);assert stop.wait(3);return
    yield body

def serve():
    peer=None;stream=None
    try:
        while not stop.is_set():
            try:peer,_=listener.accept();break
            except TimeoutError:continue
            except OSError:
                if stop.is_set():return
                raise
        if peer is None:return
        peer.settimeout(3)
        if case=='protocol':peer.sendall(b'\x00'*5);return
        if case=='real-budget':time.sleep(0.04)
        stream=server_context.wrap_socket(peer,server_side=True)
        parser=h11.Connection(h11.SERVER,max_incomplete_event_size=16385)
        total=bytearray()
        while True:
            event=parser.next_event()
            if event is h11.NEED_DATA:
                data=stream.recv(4096)
                if not data:return
                total.extend(data);assert len(total)<=16384
                parser.receive_data(data)
            elif isinstance(event,h11.Request):
                assert event.method==b'GET' and event.target==expected_target
                fields=dict(event.headers)
                assert fields[b'host']==authority.encode() and fields[b'connection']==b'close'
                assert b'accept-encoding' not in fields and b'proxy-authorization' not in fields
                if case=='no-auth-header':assert b'authorization' not in fields
                else:assert fields[b'authorization']==b'Bearer '+TOKEN.encode()
                requests_seen.append(bytes(total))
            elif isinstance(event,h11.EndOfMessage):break
            else:raise AssertionError('Unexpected request body/event')
        for part in response_parts():stream.sendall(part)
        if case!='incomplete':server_tail.append(stream.recv(1))
    except (ssl.SSLError,ConnectionError):pass
    except BaseException as error:server_errors.append(type(error).__name__)
    finally:
        if stream is not None:stream.close()
        if peer is not None and peer.fileno()>=0:peer.close()
        listener.close()
thread=threading.Thread(target=serve,daemon=False);thread.start()

class Raw(original_socket):
    def __init__(self,*args,**kwargs):
        if active and caller():
            if phase=='http' or fatal_identity:deny('extra-candidate')
            if len(raws)>=len(expected_addresses):deny('extra-candidate')
        super().__init__(*args,**kwargs)
        if active and caller():self.index=len(raws);self.connect_start=now();raws.append(self)
    def connect_ex(self,target):
        if active and caller():
            if len(attempts)>=len(expected_addresses) or target!=expected_addresses[len(attempts)]:deny('candidate-order')
            assert self.gettimeout()==0
            attempts.append(target);trace.append(('tcp',deadline,now()))
            if len(attempts)==1:
                spend('first-tcp')
                if case=='real-budget':time.sleep(0.03)
            interrupt('tcp')
            if case=='expired-tcp':clock[0]=deadline
        return super().connect_ex(target)
    def getsockopt(self,level,option,*args):
        value=super().getsockopt(level,option,*args)
        if active and caller() and option==socket.SO_ERROR and value==0:
            if case=='expired-before-tls':clock[0]=deadline
        return value
    def close(self):
        if active and caller() and self.fileno()>=0:closed_owners.append(id(self))
        return super().close()

class TLS(ssl.SSLSocket):
    send_count=0
    def do_handshake(self,*args,**kwargs):
        global fatal_identity
        interrupt('tls')
        if case=='expired-tls':clock[0]=deadline;raise ssl.SSLWantReadError()
        try:value=super().do_handshake(*args,**kwargs)
        except ssl.SSLCertVerificationError:
            fatal_identity=True;raise
        else:
            if active and caller():spend('tls')
            return value
    def send(self,data,*args,**kwargs):
        if active and caller():
            if phase!='http':deny('application-before-http')
            self.send_count+=1
            interrupt('write')
            if case in ('partial','expired-write'):data=data[:7]
            if case=='expired-write' and self.send_count==2:clock[0]=deadline;raise ssl.SSLWantWriteError()
        count=super().send(data,*args,**kwargs)
        if active and caller():
            written.extend(data[:count])
            if written.count(b'GET ')>1:deny('http-retry')
        return count
    def recv(self,*args,**kwargs):
        if active and caller():
            interrupt('read')
            if case=='reset' and getattr(self,'got_response_data',False):raise ConnectionResetError(errno.ECONNRESET,CANARY)
        value=super().recv(*args,**kwargs)
        if active and caller() and value:self.got_response_data=True
        return value
    def _real_close(self):
        if active and caller() and self.fileno()>=0:closed_owners.append(id(self))
        return super()._real_close()
context._context.sslsocket_class=TLS
original_wrap=context._context.wrap_socket

def wrap(raw,*,server_hostname,do_handshake_on_connect):
    assert server_hostname==HOST and do_handshake_on_connect is False
    trace.append(('wrap',deadline,now()))
    interrupt('wrap')
    value=original_wrap(raw,server_hostname=server_hostname,do_handshake_on_connect=do_handshake_on_connect)
    streams.append(value);return value
context._context.wrap_socket=wrap
original_handshake=cn._handshake

def handshake(stream,value):
    check_deadline('tls',value)
    return original_handshake(stream,value)
cn._handshake=handshake

class Selector(original_selector):
    def __init__(self):
        super().__init__();self.finished=False;self.registered=None;self.events=None
        if caller():selectors_seen.append(self)
    def register(self,stream,events,*args):
        self.registered=stream;self.events=events
        return super().register(stream,events,*args)
    def select(self,timeout=None):
        assert timeout is not None and timeout>0 and timeout<=deadline-now()+0.01
        if isinstance(self.registered,Raw):
            if timeout>5.001:deny('candidate-cap')
            if self.registered.index==0 and case in ('cap-five','cap-global','canary-cap'):
                assert timeout==(5 if case!='cap-global' else 2)
                clock[0]+=timeout;return []
        interrupt('selector')
        return super().select(timeout)
    def close(self):
        self.finished=True;return super().close()

original_connect=cn._connect

def connect(endpoint,resolution,context,*,deadline):
    check_deadline('connect',deadline)
    return original_connect(endpoint,resolution,context,deadline=deadline)
cn._connect=connect

def resolve(endpoint,*,deadline):
    global resolve_calls
    check_deadline('resolve',deadline);resolve_calls+=1
    if resolve_calls!=1 or endpoint.hostname!=HOST:deny('resolver-authority')
    interrupt('resolve');spend('resolve')
    if case=='real-budget':time.sleep(0.03)
    if case=='expired-resolver':return F.RESOLUTION_TIMEOUT
    value=rs._parse_reply(resolution_wire)
    if isinstance(value,rs._Resolution):
        actual=[(x.family,x.packed,x.ifindex) for x in value.addresses]
        expected=list(dict.fromkeys((x['family'],bytes(x['address']),x['ifindex']) for x in records))
        assert actual==expected and all(x.ifindex==1 for x in value.addresses)
    if case=='expired-after-resolver':clock[0]=deadline
    safe(value)
    return value
rs._resolve=resolve
original_send=ht._send
original_receive=ht._receive
original_parser=ht._parser
original_exchange=ht._exchange
receive_phase=['headers']

def send(stream,data,value):
    check_deadline('write',value);spend('write')
    return original_send(stream,data,value)

def receive(stream,size,value):
    check_deadline(receive_phase[0],value);spend(receive_phase[0])
    return original_receive(stream,size,value)

def parser(budget):
    value=original_parser(budget);parser_refs.append(weakref.ref(value))
    reference=weakref.ref(value)
    original=type(value).next_event
    def event():
        target=reference();assert target is not None
        item=original(target)
        if isinstance(item,h11.Response):receive_phase[0]='body'
        return item
    value.next_event=event
    return value
ht._send=send;ht._receive=receive
# The optional event observer holds only a weak reference to the parser.
if case.startswith('budget-'):ht._parser=parser

def exchange(endpoint,holder,request,*,deadline):
    global http_calls
    check_deadline('http',deadline);http_calls+=1
    if http_calls>1:deny('http-retry')
    return original_exchange(endpoint,holder,request,deadline=deadline)
ht._exchange=exchange

socket.socket=Raw
selectors.DefaultSelector=Selector
if clocked:time.monotonic=now
if case=='canary-cap':cn._CONNECT_CAP_SECONDS=15
if case=='canary-body':ht._MAX_BODY_BYTES+=1
if case=='canary-wire':ht._MAX_WIRE_BYTES+=1

def new_context(cls,*args,**kwargs):
    if active and caller():deny('context')
    return original_ssl_new(cls,*args,**kwargs)
ssl.SSLContext.__new__=staticmethod(new_context)
for name in ('set_ciphers','set_alpn_protocols','load_default_certs','set_default_verify_paths','load_verify_locations','load_cert_chain'):
    setattr(ssl.SSLContext,name,guard_method(getattr(ssl.SSLContext,name),'tls-policy'))
threading.Thread.start=guard_method(threading.Thread.start,'worker')
_thread.start_new_thread=guard_method(_thread.start_new_thread,'worker')
for name in ('getaddrinfo','gethostbyname','gethostbyname_ex','getnameinfo'):
    setattr(socket,name,lambda *a,**k:deny('dns'))
original_env_get=os._Environ.__getitem__
def env_get(self,key):
    normalized=key.decode('ascii') if isinstance(key,bytes) else key
    if active and caller() and normalized in authority_keys:deny('environment-authority')
    return original_env_get(self,key)
os._Environ.__getitem__=env_get
class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        top=fullname.partition('.')[0]
        if fullname in ('http.client','urllib.request') or (top not in sys.stdlib_module_names and top not in ('openkube_optimizer','h11')):deny('external-transport')
sys.meta_path.insert(0,Imports())
def audit(event,args):
    if not active or not caller():return
    if event=='socket.__new__':
        if phase=='http' or args[1] not in (socket.AF_INET,socket.AF_INET6) or args[2]!=socket.SOCK_STREAM:deny('socket')
    elif event.startswith('socket.'):
        if event!='socket.connect' or args[1] not in expected_addresses:deny('socket-operation')
    elif event=='open':
        if not isinstance(args[0],str) or not args[0].endswith(('.py','.pyc')) or args[1] not in ('r',None):deny('file')
    elif event.startswith(('subprocess.','os.exec','os.spawn')) or event in ('os.system','os.fork','os.posix_spawn'):deny('helper')
sys.addaudithook(audit)

active=True;phase='resolve'
deadline=now()+(20 if case in ('cap-five','canary-cap') else 2 if case=='cap-global' else 1 if case.startswith('budget-') else 0.5 if case=='real-budget' else 4)
if case=='expired-resolver':clock[0]=deadline
started=real_monotonic()
control=False
try:
    resolution=rs._resolve(endpoint,deadline=deadline)
    if isinstance(resolution,F):result=resolution
    else:
        phase='tcp'
        if case=='canary-deadline':
            try:cn._connect(endpoint,resolution,context,deadline=deadline+1)
            except AssertionError:pass
            result=F.TRANSPORT_DEADLINE_EXPIRED
        else:connection=cn._connect(endpoint,resolution,context,deadline=deadline)
        if connection is not None:
            if isinstance(connection,F):result=connection
            else:
                selected=connection._socket
                assert selected is not None and selected.gettimeout()==0
                phase='http'
                if case=='expired-http':clock[0]=deadline
                result=ht._exchange(endpoint,connection,request,deadline=deadline+(1 if case=='canary-http-deadline' else 0))
                assert connection._socket is None
                if case=='canary-retry':
                    try:ht._exchange(endpoint,connection,request,deadline=deadline)
                    except AssertionError:pass
    if case=='canary-verification':
        try:Raw(socket.AF_INET,socket.SOCK_STREAM)
        except AssertionError:pass
    if case=='canary-extra-candidate':
        try:Raw(socket.AF_INET,socket.SOCK_STREAM)
        except AssertionError:pass
    if case=='canary-leak':Selector()
    if case.startswith('canary-env-'):
        try:os.environ[case.removeprefix('canary-env-')]
        except AssertionError:pass
    if case.startswith('canary-envb-'):
        try:os.getenvb(case.removeprefix('canary-envb-').encode())
        except AssertionError:pass
    if case in ('canary-dns','canary-sdk','canary-proxy','canary-context','canary-worker','canary-helper'):
        try:
            if case=='canary-dns':socket.getaddrinfo(REDIRECT,443)
            elif case=='canary-sdk':__import__('kubernetes')
            elif case=='canary-proxy':__import__('urllib3')
            elif case=='canary-context':ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            elif case=='canary-worker':threading.Thread(target=lambda:None).start()
            elif case=='canary-helper':os.system('false')
        except AssertionError:pass
    if case in ('canary-body','canary-wire') and isinstance(result,ht._HttpResponse):
        violations.append('removed-response-cap')
    if isinstance(result,ht._HttpResponse):
        assert result.status==expected_status and len(result.body)==expected_size
        if case not in ('body-exact','body-over','canary-body','wire-exact','wire-over','canary-wire'):
            assert result.body==(CANARY.encode() if 200 <= expected_status <= 299 else b'')
    else:
        expected=(F.TLS_VERIFICATION_FAILED if case in ('verification','ip-identity','canary-verification') else
            F.TLS_HANDSHAKE_FAILED if case=='protocol' else F.RESOLUTION_TOO_MANY_RESULTS if case=='raw-limit' else
            F.RESOLUTION_TIMEOUT if case=='expired-resolver' else F.HTTP_REQUEST_INVALID if case=='invalid-header' else
            F.HTTP_CONNECTION_CLOSED if case=='reset' else F.HTTP_RESPONSE_TOO_LARGE if case in ('body-over','wire-over','metadata-over','fields-over') else
            F.TRANSPORT_DEADLINE_EXPIRED if case.startswith(('expired-','budget-','cap-global')) or case in ('real-budget','canary-deadline') else F.HTTP_RESPONSE_INVALID)
        assert result is expected
    if result is not None:safe(result)
except AssertionError:
    if not case.startswith('canary-') or not violations:raise
except (KeyboardInterrupt,SystemExit,Abort) as error:
    assert case.startswith('control-') and type(error) is control_kind
    control=True
finally:
    # Snapshot production ownership before any defensive harness cleanup.
    if isinstance(connection,cn._TlsConnection) and http_calls and connection._socket is not None:violations.append('holder-leak')
    if any(raw.fileno()>=0 for raw in raws) or any(stream.fileno()>=0 for stream in streams) or any(not s.finished for s in selectors_seen):violations.append('resource-leak')
    active=False;stop.set()
    if isinstance(connection,cn._TlsConnection):connection.close()
    for stream in streams:stream.close()
    for raw in raws:
        if raw.fileno()>=0:raw.close()
    for selector in selectors_seen:
        if not selector.finished:selector.close()
    listener.close();thread.join(4)
    assert not thread.is_alive() and tuple(threading.enumerate())==before_threads
    assert not server_errors,'Synthetic composed server failed'
    assert not any(server_tail),'Extra HTTP request bytes observed'
    assert fds()==baseline,'Composed descriptor leak'
    assert policy()==policy_before
    assert len(closed_owners)==len(set(closed_owners)),'Descriptor owner closed twice'
    assert all(reference() is None for reference in parser_refs),'Parser observer retained raw buffers'
    time.monotonic=real_monotonic
assert not violations,'Composed transport guard rejected attempt'
assert not {'kubernetes','urllib3','requests','yaml'} & sys.modules.keys()
assert resolve_calls==1 and all(item[1]==deadline for item in trace)
if not control:
    if case in ('verification','ip-identity','protocol'):assert len(attempts)==1 and not written and not http_calls
    elif case in ('expired-resolver','raw-limit','expired-after-resolver'):assert not attempts and not http_calls
    elif case not in ('canary-deadline',):assert attempts==expected_addresses[:len(attempts)]
    if isinstance(result,ht._HttpResponse) or case in ('malformed','incomplete','reset','switch','metadata-over','fields-over','body-over','wire-over','real-budget') or case.startswith('compressed-'):
        assert http_calls==1
        assert len(requests_seen)==1
    if case=='first-success':assert len(attempts)==1
    if case in ('budget-success','budget-header','budget-body'):
        assert {'resolve','tcp','tls','write','headers'} <= {x[0] for x in trace}
        if case=='budget-body':assert 'body' in {x[0] for x in trace}
    if case=='cap-five':assert trace and isinstance(result,ht._HttpResponse) and clock[0]==105
    if case=='real-budget':assert real_monotonic()-started<1.0 and real_monotonic()-deadline<0.5
    if sni:assert sni==[HOST]
print(json.dumps({'case':case,'result':'control' if control else 'response' if isinstance(result,ht._HttpResponse) else result.value,
    'resolve_calls':resolve_calls,'tcp_attempts':len(attempts),'http_requests':len(requests_seen),'closed':True,
    'shared_deadline':True,'original_identity':True,'no_proxy_dns_sdk_retry':True}))
"""

CASES = (
    "success",
    "first-success",
    "raw-sixtyfour",
    "raw-limit",
    "root",
    "prefix",
    "prefix-trailing",
    "no-auth-header",
    "invalid-header",
    "verification",
    "ip-identity",
    "protocol",
    "partial",
    "reset",
    "redirect302",
    "redirect307",
    "redirect308",
    "denied",
    "server-error",
    "malformed",
    "incomplete",
    "switch",
    "interim",
    "compressed-gzip",
    "compressed-br",
    "compressed-deflate",
    "chunked",
    "metadata-over",
    "fields-over",
    "body-exact",
    "body-over",
    "wire-exact",
    "wire-over",
    "budget-success",
    "budget-header",
    "budget-body",
    "cap-five",
    "cap-global",
    "real-budget",
    "expired-resolver",
    "expired-after-resolver",
    "expired-tcp",
    "expired-before-tls",
    "expired-tls",
    "expired-http",
    "expired-write",
    "control-resolve-keyboard",
    "control-tcp-system",
    "control-wrap-base",
    "control-tls-keyboard",
    "control-selector-base",
    "control-write-system",
    "control-read-base",
)
CANARIES = (
    "extra-candidate",
    "verification",
    "deadline",
    "retry",
    "cap",
    "body",
    "wire",
    "leak",
    "dns",
    "sdk",
    "proxy",
    "context",
    "worker",
    "helper",
    "env-KUBECONFIG",
    "env-HOME",
    "env-SSL_CERT_FILE",
    "env-SSL_CERT_DIR",
    "env-HTTP_PROXY",
    "env-HTTPS_PROXY",
    "env-ALL_PROXY",
    "env-NO_PROXY",
    "env-http_proxy",
    "env-https_proxy",
    "env-all_proxy",
    "env-no_proxy",
    "env-LOCALDOMAIN",
    "env-RES_OPTIONS",
    "env-HOSTALIASES",
    "env-SSLKEYLOGFILE",
    "envb-HOME",
    "envb-HTTPS_PROXY",
    "http-deadline",
)
ENVIRONMENT = {
    "HOME": "/unused-home-canary",
    "KUBECONFIG": "/unused-kubeconfig-canary",
    "SSL_CERT_FILE": "/unused-ca-canary",
    "SSL_CERT_DIR": "/unused-ca-dir-canary",
    "SSLKEYLOGFILE": "/unused-keylog-canary",
    "LOCALDOMAIN": "override-canary.invalid",
    "RES_OPTIONS": "ndots:15",
    "HOSTALIASES": "/unused-alias-canary",
    **{
        k: "http://Proxy.Transport-Canary.invalid:32199"
        for k in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        )
    },
    "NO_PROXY": "bypass-canary.invalid",
    "no_proxy": "bypass-canary.invalid",
}


def literal(path: Path, name: str) -> str:
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            value: object = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError("Missing test script")


def run(
    script: str,
    case: str,
    tmp_path: Path,
    *,
    canary: bool = False,
    resolver: bool = False,
) -> dict[str, object]:
    args = [sys.executable, "-I", "-B", "-c", script, case]
    if not resolver:
        args.append(str(Path(__file__).resolve().parents[1] / "fixtures" / "tls"))
    process = subprocess.run(
        args,
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if canary:
        assert process.returncode != 0
        assert "Composed transport guard rejected attempt" in process.stderr
        assert not process.stdout
        return {}
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    value: object = json.loads(process.stdout)
    assert isinstance(value, dict) and value["closed"]
    return value


@pytest.mark.parametrize("case", CASES)
def test_composed_transport_security(tmp_path: Path, case: str) -> None:
    run(TRANSPORT_SCRIPT, case, tmp_path)


@pytest.mark.parametrize("canary", CANARIES)
def test_composed_negative_guards(tmp_path: Path, canary: str) -> None:
    run(TRANSPORT_SCRIPT, "canary-" + canary, tmp_path, canary=True)


@pytest.mark.parametrize(
    "case", ["success", "mixed", "failure", "stall", "partial", "malformed"]
)
def test_native_varlink_independent(tmp_path: Path, case: str) -> None:
    if sys.platform != "linux":
        pytest.skip("Real resolved IPC requires the authorized native Ubuntu profile")
    script = literal(
        Path(__file__).with_name("test_resolved_native.py"), "RESOLVER_SCRIPT"
    )
    assert run(script, case, tmp_path, resolver=True)["no_remote_tcp"]


IMPORT_SCRIPT = r"""
import _thread
import importlib.abc
import json
import os
import socket
import ssl
import sys
import threading
violations=[]
def deny(*args,**kwargs):
    violations.append('forbidden')
    raise AssertionError('Forbidden transport import action')
class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] not in sys.stdlib_module_names and not fullname.startswith('openkube_optimizer'):deny()
sys.meta_path.insert(0,Imports())
def audit(event,args):
    if event.startswith(('socket.','subprocess.','os.exec','os.spawn')) or event in ('os.system','os.fork'):deny()
    if event=='open' and (not isinstance(args[0],str) or not args[0].endswith(('.py','.pyc')) or args[1] not in ('r',None)):deny()
sys.addaudithook(audit)
for name in ('getaddrinfo','gethostbyname','gethostbyname_ex','getnameinfo'):setattr(socket,name,deny)
ssl.SSLContext.__new__=staticmethod(deny)
for name in ('do_handshake','send','sendall','recv','read','write'):setattr(ssl.SSLSocket,name,deny)
threading.Thread.start=deny
_thread.start_new_thread=deny
original_get=os._Environ.__getitem__
def get(self,key):
    key_text=key.decode('ascii') if isinstance(key,bytes) else key
    if key_text in ('HOME','KUBECONFIG','SSL_CERT_FILE','SSL_CERT_DIR','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','LOCALDOMAIN','RES_OPTIONS','HOSTALIASES'):deny()
    return original_get(self,key)
os._Environ.__getitem__=get
from openkube_optimizer.collection import resolver,connection,http
assert not {'h11','kubernetes','yaml','urllib3','requests'} & sys.modules.keys()
try:
    if sys.argv[1]=='socket':socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    elif sys.argv[1]=='tls':ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    elif sys.argv[1]=='h11':__import__('h11')
except AssertionError:pass
assert not violations,'Transport import guard rejected attempt'
print(json.dumps({'closed':True,'inert':True}))
"""

METER_SCRIPT = r"""
import json
import socket
import sys
import h11
import h11._events as events
from h11._receivebuffer import ReceiveBuffer
from openkube_optimizer.collection import http as ht
assert h11.__version__=='0.16.0'
kind,over,step=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
budget=ht._Budget();parser=ht._parser(budget)
parser.send(h11.Request(method='GET',target='/',headers=[('Host','API.Test.invalid'),('Connection','close')]))
parser.send(h11.EndOfMessage())
info=b'HTTP/1.1 103 Early Hints\r\nX-Info: a\r\n\r\n'
if kind=='infos':info=b'HTTP/1.1 103 Early Hints\r\n\r\n'*128
if kind=='fields':
    final=b'HTTP/1.1 200 OK\r\n'+b'Content-Length: 0\r\n'*(127+over)+b'\r\n'
    wire=info+final;expected_bytes=len(wire);expected_fields=128
elif kind=='trailers':
    final=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
    trailer=b'X: '+b'a'*(16384-len(info)-len(final)-len(b'X: \r\n\r\n')+over)+b'\r\n\r\n'
    wire=info+final+b'1;extension=not-metadata\r\nx\r\n0\r\n'+trailer
    expected_bytes=16384;expected_fields=3
else:
    final=b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: \r\n\r\n'
    padding=b'a'*(16384-len(info)-len(final)+over)
    final=final.replace(b'X: \r\n',b'X: '+padding+b'\r\n')
    wire=info+final;expected_bytes=16384;expected_fields=2 if kind=='infos' else 3
original=events.normalize_and_validate
normalizations=[]
expected_totals=([len(info),len(info)+len(final),len(info)+len(final)+len(trailer)] if kind=='trailers' else
    [len(wire)] if kind=='infos' else [len(info),len(wire)])
def checked(headers,*args,**kwargs):
    if headers:
        index=len(normalizations)
        assert index<len(expected_totals) and budget.metadata==expected_totals[index] and budget.metadata<=16384 and budget.fields<=128,'Metadata meter did not precede normalization'
        normalizations.append(budget.metadata)
    return original(headers,*args,**kwargs)
events.normalize_and_validate=checked
if kind=='unmetered':parser._receive_buffer=ReceiveBuffer()
def no_socket(*args,**kwargs):raise AssertionError('Parser characterization attempted socket activity')
socket.socket=no_socket
cursor=0;rejected=False
try:
    while True:
        event=parser.next_event()
        if event is h11.NEED_DATA:
            assert cursor<len(wire),'Unexpected incomplete characterization input'
            chunk=wire[cursor:cursor+step];cursor+=len(chunk)
            budget.received(len(chunk));parser.receive_data(chunk)
        elif isinstance(event,h11.Response):budget.final_response=True
        elif isinstance(event,h11.EndOfMessage):break
except ht._TooLarge:rejected=True
assert rejected==bool(over)
if over:
    # Only the informational block(s) can reach h11 normalization; the final
    # oversized metadata/duplicate fields/trailers are stopped beforehand.
    assert budget.metadata<=16384 and budget.fields<=128
    assert normalizations==expected_totals[:-1]
else:
    assert budget.metadata==expected_bytes and budget.fields==expected_fields
    assert budget.wire==len(wire)
    assert normalizations==expected_totals
assert normalizations or kind=='infos'
print(json.dumps({'closed':True,'pin':'0.16.0','bounded':True,'before_normalization':True}))
"""


@pytest.mark.parametrize("canary", ["none", "socket", "tls", "h11"])
def test_all_transport_imports_are_inert(tmp_path: Path, canary: str) -> None:
    if canary == "none":
        assert run(IMPORT_SCRIPT, canary, tmp_path)["inert"]
        return
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", IMPORT_SCRIPT, canary],
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (
        process.returncode != 0
        and "Transport import guard rejected attempt" in process.stderr
    )
    assert not process.stdout


@pytest.mark.parametrize("kind", ["metadata", "fields", "trailers", "infos"])
@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("step", [1, 8192, 65536])
def test_pinned_h11_meter_before_normalization(
    tmp_path: Path, kind: str, over: bool, step: int
) -> None:
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            METER_SCRIPT,
            kind,
            str(int(over)),
            str(step),
        ],
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert not process.stderr
    value = json.loads(process.stdout)
    assert value["bounded"] and value["before_normalization"]


def test_removing_meter_is_detected(tmp_path: Path) -> None:
    process = subprocess.run(
        [sys.executable, "-I", "-B", "-c", METER_SCRIPT, "unmetered", "0", "65536"],
        cwd=tmp_path,
        env=ENVIRONMENT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (
        process.returncode != 0
        and "Metadata meter did not precede normalization" in process.stderr
    )
    assert not process.stdout
