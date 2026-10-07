"""Synthetic, isolated full-pipeline security gate; no network or handshake."""

import json
import ssl
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parents[1] / "fixtures" / "tls"
TOKEN = "pipeline-token-secret-canary"
CONTEXT = "pipeline-context-secret-canary"
CLUSTER = "pipeline-cluster-secret-canary"
USER = "pipeline-user-secret-canary"
RAW = "pipeline-raw-kubeconfig-secret-canary"
NAMES = (
    "pipeline-ca-path-canary",
    "pipeline-cert-path-canary",
    "pipeline-key-path-canary",
)

EXPECTED = {
    "missing-context": "requested_context_not_found",
    "invalid-token": "unsupported_or_invalid_selected_authentication",
    "unsupported-auth": "unsupported_or_invalid_selected_authentication",
    "malformed-yaml": "malformed_yaml",
    "empty-ca": "invalid_ca_material",
    "text-ca": "invalid_ca_material",
    "unsupported-ca": "invalid_ca_material",
    "der-ca": "invalid_ca_material",
    "base64-ca": "invalid_ca_material",
    "framing-ca": "invalid_ca_material",
    "directory-ca": "nonregular_credential_input",
    "oversize-ca": "credential_input_too_large",
    "overflow-ca": "credential_input_too_large",
    "oversize-cert": "credential_input_too_large",
    "oversize-key": "credential_input_too_large",
    "partial-key": "credential_input_unavailable",
    "malformed-cert": "invalid_client_identity",
    "malformed-key": "invalid_client_identity",
    "mismatch": "invalid_client_identity",
    "encrypted": "unsupported_encrypted_private_key",
    "traditional": "unsupported_encrypted_private_key",
    "malformed-chain": "invalid_client_identity",
    "injected-ca": "invalid_ca_material",
    "injected-identity": "invalid_client_identity",
}


def prepare(root: Path, *, certificate: bool, case: str) -> None:
    selected = root / "selected"
    physical = root / "physical"
    elsewhere = root / "elsewhere"
    for directory in (
        selected,
        physical,
        elsewhere,
        root / "poison-home" / ".kube",
        root / "poison-trust",
    ):
        directory.mkdir(parents=True)
    ca = (FIXTURES / "ca1.pem").read_bytes()
    cert = (
        FIXTURES / ("client-chain.pem" if case == "chain" else "client.pem")
    ).read_bytes()
    key = (FIXTURES / "client-key.pem").read_bytes()
    if case == "multi-ca":
        ca += (FIXTURES / "ca2.pem").read_bytes()
    elif case == "whitespace-ca":
        ca = b" \t\r\n\v\f" + ca + b" \t\r\n\v\f"
    elif case == "limit-ca":
        ca += b" " * (1048576 - len(ca))
    elif case in {"oversize-ca", "overflow-ca"}:
        ca = b"x" * 1048577
    elif case == "empty-ca":
        ca = b""
    elif case == "text-ca":
        ca = b"pipeline-CA-content-secret-canary"
    elif case == "unsupported-ca":
        ca += key
    elif case == "der-ca":
        ca = ssl.PEM_cert_to_DER_cert(ca.decode("ascii"))
    elif case == "base64-ca":
        ca = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"
    elif case == "framing-ca":
        ca = ca.replace(b"END CERTIFICATE", b"END CERTIFICATE-incorrect")
    if case == "malformed-cert":
        cert = b"pipeline-certificate-content-secret-canary"
    elif case == "malformed-chain":
        cert += b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
    elif case == "oversize-cert":
        cert = b"x" * 1048577
    if case == "malformed-key":
        key = b"pipeline-key-content-secret-canary"
    elif case == "mismatch":
        key = (FIXTURES / "mismatch-key.pem").read_bytes()
    elif case in {"encrypted", "traditional"}:
        key = (
            FIXTURES
            / (
                "encrypted-key.pem"
                if case == "encrypted"
                else "encrypted-traditional-key.pem"
            )
        ).read_bytes()
    elif case == "oversize-key":
        key = b"x" * 1048577
    for name, data in zip(NAMES, (ca, cert, key), strict=True):
        path = selected / name
        if case == "directory-ca" and name == NAMES[0]:
            path.mkdir()
        else:
            path.write_bytes(data)
        # Poison every alternative origin and precreate mutation targets.
        (physical / name).write_bytes(b"pipeline-wrong-origin-canary")
        (elsewhere / name).write_bytes(b"pipeline-wrong-cwd-canary")
        (selected / (name + ".replacement")).write_bytes(b"pipeline-replacement-canary")
    if case in {"credential-symlinks", "combined", "retarget"}:
        for name in NAMES:
            path = selected / name
            path.rename(selected / (name + ".target"))
            path.symlink_to(name + ".target")
    auth = (
        f"client-certificate: {NAMES[1]}, client-key: {NAMES[2]}"
        if certificate
        else f"token: {TOKEN}"
    )
    if case == "invalid-token":
        auth = 'token: "pipeline-token-secret-canary\\n"'
    elif case == "unsupported-auth":
        auth = "exec: {command: never-execute-pipeline-helper-canary}"
    config = f"""apiVersion: v1
kind: Config
current-context: never-select-default-context-canary
synthetic-private-field: {RAW}
contexts: [{{name: {CONTEXT}, context: {{cluster: {CLUSTER}, user: {USER}}}}}]
clusters: [{{name: {CLUSTER}, cluster: {{server: https://api.example.invalid, certificate-authority: {NAMES[0]}}}}}]
users: [{{name: {USER}, user: {{{auth}}}}}]
"""
    if case == "malformed-yaml":
        config = "apiVersion: [pipeline-malformed-YAML-canary"
    (physical / "config").write_text(config, encoding="utf-8")
    if case in {"config-symlink", "combined"}:
        (selected / "config").symlink_to(physical / "config")
    else:
        (selected / "config").write_text(config, encoding="utf-8")
    (root / "poison-home" / ".kube" / "config").write_text(
        "forbidden-default-config-canary"
    )
    (root / "poison-config").write_text("forbidden-environment-config-canary")
    unrelated = (FIXTURES / "ca2.pem").read_bytes()
    (root / "poison-trust" / "ca.pem").write_bytes(unrelated)
    (root / "poison-trust" / "unrelated.0").write_bytes(unrelated)
    metadata = {
        "certificate": certificate,
        "case": case,
        "names": NAMES,
        "context": CONTEXT,
        "canaries": [
            TOKEN,
            CONTEXT,
            CLUSTER,
            USER,
            RAW,
            *NAMES,
            "pipeline-CA-content-secret-canary",
            "pipeline-certificate-content-secret-canary",
            "pipeline-key-content-secret-canary",
            "OpenSSL-diagnostic-canary",
            "OSError-diagnostic-canary",
        ],
        "expected": EXPECTED.get(case),
        "trust": [
            ssl.PEM_cert_to_DER_cert((FIXTURES / name).read_text("ascii")).hex()
            for name in ("ca1.pem", "ca2.pem")
            if name == "ca1.pem" or case == "multi-ca"
        ],
    }
    (root / "test-metadata.json").write_text(json.dumps(metadata))


PIPELINE_SCRIPT = r"""
import os,sys,ssl,socket,subprocess,threading,_thread,asyncio,getpass,builtins,base64,re,typing,json,copy,pickle,dataclasses
from pathlib import Path
from importlib.util import find_spec
import yaml  # Test setup preloads the locked parser; no OpenKube input read yet.
root=Path(sys.argv[1])
mode=sys.argv[2]
metadata=json.loads((root/'test-metadata.json').read_text())
case=metadata['case']
certificate=metadata['certificate']
selected=root/'selected'
config=selected/'config'
paths=tuple(selected/name for name in metadata['names'])
canaries=metadata['canaries']
expected=metadata['expected']
trust=[bytes.fromhex(value) for value in metadata['trust']]
package_root=str(Path(find_spec('openkube_optimizer').origin).parent)
initial_fds=set(os.listdir('/proc/self/fd')) if sys.platform=='linux' else None
phase='imports'
violations=[]
owned={}
pins=set()
opens=[]
closes=[]
read_totals=[]
contexts=[]
chains=[]
class GuardViolation(RuntimeError):
    pass
def reject(*args,**kwargs):
    violations.append('forbidden')
    raise GuardViolation('Prohibited combined pipeline activity')
class Imports:
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in {'kubernetes','h11'}:
            reject()
def allowed_open(name,flags):
    if isinstance(name,int):
        reject()
    name=os.fspath(name)
    module=phase=='imports' and name.startswith(package_root+'/') and name.endswith(('.py','.pyc'))
    config_read=phase=='document' and name==str(config)
    selected_read=phase=='credentials' and name in tuple(map(str,paths))
    pinned_read=phase=='credentials' and name in {f'/proc/self/fd/{fd}' for fd in pins}
    if not (module or config_read or selected_read or pinned_read):
        reject()
    if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC):
        reject()
def audit(event,args):
    if event.startswith(('socket.','subprocess.','os.spawn','os.exec')) or event in {'os.system','os.fork','os.forkpty'}:
        reject()
    if event=='open':
        allowed_open(args[0],args[2])
sys.meta_path.insert(0,Imports())
sys.addaudithook(audit)
os._Environ.__getitem__=os._Environ.__iter__=reject
threading.Thread.start=_thread.start_new_thread=reject
if hasattr(_thread,'start_joinable_thread'):
    _thread.start_joinable_thread=reject
asyncio.BaseEventLoop.create_task=asyncio.new_event_loop=reject
socket.socket=socket.getaddrinfo=socket.gethostbyname=reject
builtins.input=getpass.getpass=reject
os.path.realpath=Path.resolve=os.readlink=reject
if hasattr(os,'fork'):
    os.fork=reject
original_stat,original_fstat=os.stat,os.fstat
original_open,original_close,original_read=os.open,os.close,os.read
original_new=ssl.SSLContext.__new__
original_ca=ssl.SSLContext.load_verify_locations
original_chain=ssl.SSLContext.load_cert_chain

def stat(path,*args,**kwargs):
    if phase!='document' or os.fspath(path)!=str(config):
        reject()
    return original_stat(path,*args,**kwargs)
os.stat=os.lstat=stat

def open_fd(path,flags,*args):
    allowed_open(path,flags)
    assert flags & os.O_CLOEXEC
    fd=original_open(path,flags,*args)
    assert fd not in owned
    owned[fd]={'path':os.fspath(path),'read':0,'phase':phase}
    opens.append((fd,phase))
    if flags & getattr(os,'O_PATH',0):
        pins.add(fd)
    return fd

def close_fd(fd):
    assert fd in owned,'Close without ownership'
    read_totals.append(owned[fd]['read'])
    original_close(fd)
    del owned[fd]
    pins.discard(fd)
    closes.append(fd)

def read_fd(fd,size):
    assert fd in owned and 0<size<=1048577-owned[fd]['read']
    if case=='partial-key' and owned[fd]['path'].startswith('/proc/self/fd/') and original_fstat(fd).st_ino==key_inode:
        raise OSError('OSError-diagnostic-canary')
    chunk=original_read(fd,min(size,37))  # Exercise actual bounded short reads.
    owned[fd]['read']+=len(chunk)
    return chunk

def fstat(fd):
    info=original_fstat(fd)
    if case=='overflow-ca' and info.st_ino==ca_inode:
        fields=list(info); fields[6]=0
        return os.stat_result(fields)
    return info
os.open,os.close,os.read,os.fstat=open_fd,close_fd,read_fd,fstat

def new_context(cls,protocol=None,*args,**kwargs):
    if phase!='tls' or protocol!=ssl.PROTOCOL_TLS_CLIENT:
        reject()
    context=original_new(cls,protocol,*args,**kwargs)
    assert context.cert_store_stats()['x509']==0
    contexts.append((context.security_level,context.get_ciphers()))
    return context
ssl.SSLContext.__new__=staticmethod(new_context)
ssl.create_default_context=reject
for name in ('load_default_certs','set_default_verify_paths','set_ciphers','set_alpn_protocols','wrap_socket','wrap_bio'):
    setattr(ssl.SSLContext,name,reject)
ssl.SSLSocket.do_handshake=reject

def load_ca(self,cafile=None,capath=None,cadata=None):
    if phase!='tls' or cafile is not None or capath is not None or not isinstance(cadata,bytes):
        reject()
    if case=='injected-ca':
        raise ssl.SSLError('OpenSSL-diagnostic-canary')
    return original_ca(self,cadata=cadata)

def load_chain(self,certfile,keyfile=None,password=None):
    if phase!='tls' or (certfile,keyfile)!=proc_paths or password is not tls._reject_password:
        reject()
    assert all(fd in owned for fd in descriptors)
    chains.append('pinned')
    if case=='injected-identity':
        raise ssl.SSLError('OpenSSL-diagnostic-canary')
    return original_chain(self,certfile,keyfile,password=password)
ssl.SSLContext.load_verify_locations=load_ca
ssl.SSLContext.load_cert_chain=load_chain

def safe(value):
    output=value if isinstance(value,str) else repr(value)
    assert all(canary not in output for canary in canaries),'Confinement canary detected disclosure'
    assert '/proc/self/fd/' not in output
    assert 'OpenSSL-diagnostic' not in output and 'OSError-diagnostic' not in output

def confined(record):
    safe(repr(record)); safe(str(record))
    operations=[vars,dataclasses.asdict,json.dumps,copy.copy,copy.deepcopy,lambda value:value.__getstate__(),lambda value:value.__reduce__(),lambda value:value.__reduce_ex__(4)]
    operations.extend(lambda value,protocol=protocol:pickle.dumps(value,protocol=protocol) for protocol in range(pickle.HIGHEST_PROTOCOL+1))
    for operation in operations:
        try:
            extracted=operation(record)
        except (TypeError,AttributeError) as exc:
            safe(str(exc)); safe(repr(exc))
            assert exc.__cause__ is None and exc.__context__ is None
        else:
            raise AssertionError('Private material allowed generic extraction')

from openkube_optimizer.collection import kubeconfig as kc,preflight as pf,credentials as cr,tls
assert not contexts and not owned and not opens and not violations
if mode=='import':
    assert not any(name.split('.')[0] in {'kubernetes','h11'} for name in sys.modules)
    print('PASS')
    sys.exit(0)
if mode=='import-context':
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
if mode=='confinement':
    class Unprotected:
        def __repr__(self):
            return canaries[0]
    confined(Unprotected())
assert sys.platform=='linux' and hasattr(os,'O_PATH')
# Descriptor-based setup metadata is obtained by the test harness before calls.
ca_inode=original_stat(paths[0]).st_ino
key_inode=original_stat(paths[2]).st_ino
os.chdir(selected)
input_path=Path('config') if case in {'relative','cwd-before','combined'} else config

def inject(stage):
    if not mode.startswith(stage+':'):
        return
    action=mode.partition(':')[2]
    actions={
        'environment':lambda:os.getenv('KUBECONFIG'),
        'default-config':lambda:open(root/'poison-home/.kube/config'),
        'sdk':lambda:__import__('kubernetes'),
        'http':lambda:__import__('h11'),
        'socket':lambda:socket.socket(),
        'dns':lambda:socket.getaddrinfo('api.example.invalid',443),
        'helper':lambda:subprocess.run(['never-execute']),
        'thread':lambda:threading.Thread(target=lambda:None).start(),
        'task':lambda:asyncio.BaseEventLoop.create_task(None,None),
        'password':lambda:builtins.input(),
        'getpass':lambda:getpass.getpass(),
        'ca-reopen':lambda:open(paths[0]),
        'identity-reopen':lambda:result._context.load_cert_chain(str(paths[1]),str(paths[2]),password=tls._reject_password),
        'trust':lambda:result._context.load_default_certs(),
        'verify-paths':lambda:result._context.set_default_verify_paths(),
        'default-context':lambda:ssl.create_default_context(),
        'handshake':lambda:result._context.wrap_socket(None),
    }
    actions[action]()

phase='document'
inject('before')
document=kc._load_document(input_path)
assert not owned and not pins
assert sum(open_phase=='document' for _,open_phase in opens)==1
if isinstance(document,kc._Failure):
    result=document
else:
    confined(document)
    assert document._origin==selected
    if case in {'cwd-before','combined','config-symlink'}:
        os.chdir(root/'elsewhere')
    phase='preflight'
    preflight=pf._preflight(document,context_name='pipeline-missing-context-canary' if case=='missing-context' else metadata['context'])
    del document
    if isinstance(preflight,kc._Failure):
        result=preflight
    else:
        confined(preflight); confined(preflight.auth)
        assert preflight.ca_path==paths[0]
        if certificate:
            assert isinstance(preflight.auth,pf._ClientCertificate)
            assert preflight.auth.certificate_path==paths[1] and preflight.auth.key_path==paths[2]
        else:
            assert isinstance(preflight.auth,pf._BearerToken) and preflight.auth.token==canaries[0]
        if case in {'cwd-after','combined','config-symlink'}:
            os.chdir(root/'elsewhere')
        phase='credentials'
        material=cr._load_credentials(preflight)
        if isinstance(material,kc._Failure):
            result=material
        else:
            confined(material)
            assert cr._CredentialMaterial.__slots__==('_ca_snapshot','_certificate_fd','_key_fd','_closed')
            descriptors=tuple(fd for fd in (material._certificate_fd,material._key_fd) if fd is not None)
            proc_paths=tuple(f'/proc/self/fd/{fd}' for fd in descriptors)
            assert len(descriptors)==(2 if certificate else 0)
            assert set(owned)==set(descriptors) and not pins
            # CA snapshot stays authoritative; original CA is always unlinked.
            phase='mutation'
            os.unlink(paths[0])
            if case in {'replace','retarget','unlink','combined'}:
                for path in paths[1:]:
                    if case=='replace':
                        os.replace(str(path)+'.replacement',path)
                    else:
                        os.unlink(path)
                        if case in {'retarget','combined'}:
                            os.symlink(str(path)+'.replacement',path)
            closes_before=len(closes)
            phase='tls'
            try:
                with material:
                    result=tls._build_tls_context(material)
                    assert len(closes)==closes_before
                    assert set(owned)==set(descriptors)
                    if isinstance(result,tls._TlsContext):
                        confined(result)
                        assert tls._TlsContext.__slots__==('_context',)
                        context=result._context
                        assert context.protocol==ssl.PROTOCOL_TLS_CLIENT
                        assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
                        assert context.minimum_version==ssl.TLSVersion.TLSv1_2
                        assert context.maximum_version==ssl.TLSVersion.MAXIMUM_SUPPORTED
                        assert context.keylog_filename is None
                        assert context.security_level==contexts[0][0]
                        assert context.get_ciphers()==contexts[0][1]
                        assert set(context.get_ca_certs(binary_form=True))==set(trust)
                        assert not hasattr(result,'token') and not hasattr(material,'token')
                    inject('after')
            finally:
                material.close()
            assert closes[closes_before:]==list(descriptors)
            material.close()
            assert closes[closes_before:]==list(descriptors)
            for fd in descriptors:
                try:
                    original_fstat(fd)
                except OSError:
                    pass
                else:
                    raise AssertionError('Credential owner left descriptor open')
            if isinstance(result,tls._TlsContext):
                assert result._context.get_ciphers()
assert not owned and not pins
assert initial_fds==set(os.listdir('/proc/self/fd'))
assert len(opens)==len(closes)
assert all(total<=1048577 for total in read_totals)
if case=='overflow-ca':
    assert 1048577 in read_totals
if case=='limit-ca':
    assert 1048576 in read_totals
if expected is None:
    assert isinstance(result,tls._TlsContext)
else:
    assert isinstance(result,kc._Failure) and result.value==expected
    safe(repr(result)); safe(str(result)); safe(result.value)
    assert not any(str(fd) in result.value for fd,_ in opens)
    for protocol in range(pickle.HIGHEST_PROTOCOL+1):
        serialized=pickle.dumps(result,protocol=protocol)
        assert all(canary.encode() not in serialized for canary in canaries)
    assert copy.copy(result) is copy.deepcopy(result) is result
assert not violations
assert len(threading.enumerate())==1
assert not any(name.startswith(('openkube_optimizer.domain','openkube_optimizer.report')) for name in sys.modules)
assert not any(name.split('.')[0] in {'kubernetes','h11'} for name in sys.modules)
print('PASS')
"""


def execute(root: Path, mode: str = "clean") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", PIPELINE_SCRIPT, str(root), mode],
        cwd=root,
        env={
            "HOME": str(root / "poison-home"),
            "KUBECONFIG": str(root / "poison-config"),
            "KUBERNETES_SERVICE_HOST": "pipeline-incluster-host-canary",
            "KUBERNETES_SERVICE_PORT": "443",
            "SSL_CERT_FILE": str(root / "poison-trust/ca.pem"),
            "SSL_CERT_DIR": str(root / "poison-trust"),
            "SSLKEYLOGFILE": str(root / "forbidden-keylog"),
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def linux() -> None:
    if sys.platform != "linux":
        pytest.skip("Combined O_PATH/procfs pipeline requires native Linux")


@pytest.mark.parametrize("certificate", [False, True])
@pytest.mark.parametrize(
    "case",
    [
        "relative",
        "absolute",
        "cwd-before",
        "cwd-after",
        "config-symlink",
        "credential-symlinks",
        "combined",
        "replace",
        "retarget",
        "unlink",
        "multi-ca",
        "whitespace-ca",
        "limit-ca",
        "chain",
    ],
)
def test_native_complete_pipeline(
    linux: None, tmp_path: Path, certificate: bool, case: str
) -> None:
    prepare(tmp_path, certificate=certificate, case=case)
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    result = execute(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS\n" and result.stderr == ""
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} <= before


@pytest.mark.parametrize("case", list(EXPECTED))
def test_native_complete_failure_cleanup(
    linux: None, tmp_path: Path, case: str
) -> None:
    prepare(tmp_path, certificate=case != "invalid-token", case=case)
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    result = execute(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS\n" and result.stderr == ""
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} <= before


@pytest.mark.parametrize(
    "mode",
    [
        "before:environment",
        "before:default-config",
        "before:sdk",
        "before:http",
        "before:socket",
        "before:dns",
        "before:helper",
        "before:thread",
        "before:task",
        "before:password",
        "before:getpass",
        "after:ca-reopen",
        "after:identity-reopen",
        "after:trust",
        "after:verify-paths",
        "after:default-context",
        "after:handshake",
    ],
)
def test_native_full_flow_negative_guards(
    linux: None, tmp_path: Path, mode: str
) -> None:
    prepare(tmp_path, certificate=True, case="absolute")
    result = execute(tmp_path, mode)
    assert result.returncode != 0
    assert "Prohibited combined pipeline activity" in result.stderr


@pytest.mark.parametrize("mode", ["import", "import-context", "confinement"])
def test_combined_import_and_confinement_canaries(tmp_path: Path, mode: str) -> None:
    prepare(tmp_path, certificate=False, case="absolute")
    result = execute(tmp_path, mode)
    if mode == "import":
        assert result.returncode == 0, result.stderr
        assert result.stdout == "PASS\n" and result.stderr == ""
    else:
        assert result.returncode != 0
        assert (
            "Prohibited combined pipeline activity"
            if mode == "import-context"
            else "Confinement canary detected disclosure"
        ) in result.stderr
