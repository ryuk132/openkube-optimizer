"""Offline synthetic TLS construction; procfs cases require native Linux."""

import copy
import dataclasses
import json
import os
import pickle
import ssl
import subprocess
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from openkube_optimizer.collection import credentials as cr
from openkube_optimizer.collection import kubeconfig as kc
from openkube_optimizer.collection import preflight as pf
from openkube_optimizer.collection import tls

FIXTURES = Path(__file__).parents[1] / "fixtures" / "tls"
TOKEN = "synthetic-tls-token-canary"
PATHS = (
    "selected-ca-path-canary",
    "selected-cert-path-canary",
    "selected-key-path-canary",
)


def pem(name: str = "ca1.pem") -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def linux() -> None:
    if sys.platform != "linux":
        pytest.skip("Real OpenSSL procfs loading requires native Linux")
    assert hasattr(os, "O_PATH")


def selected(
    tmp_path: Path,
    *,
    certificate: bool = True,
    ca: bytes | None = None,
    cert: bytes | None = None,
    key: bytes | None = None,
) -> pf._Preflight:
    (tmp_path / PATHS[0]).write_bytes(pem() if ca is None else ca)
    if certificate:
        (tmp_path / PATHS[1]).write_bytes(pem("client.pem") if cert is None else cert)
        (tmp_path / PATHS[2]).write_bytes(pem("client-key.pem") if key is None else key)
    auth = (
        f"client-certificate: {PATHS[1]}, client-key: {PATHS[2]}"
        if certificate
        else f"token: {TOKEN}"
    )
    config = tmp_path / "explicit-synthetic-config"
    config.write_text(
        f"""apiVersion: v1
kind: Config
contexts: [{{name: chosen, context: {{cluster: cluster, user: user}}}}]
clusters: [{{name: cluster, cluster: {{server: https://api.example.invalid, certificate-authority: {PATHS[0]}}}}}]
users: [{{name: user, user: {{{auth}}}}}]
""",
        encoding="utf-8",
    )
    document = kc._load_document(config)
    assert isinstance(document, kc._Document)
    preflight = pf._preflight(document, context_name="chosen")
    assert isinstance(preflight, pf._Preflight)
    return preflight


def ca_material(snapshot: bytes) -> cr._CredentialMaterial:
    return cr._CredentialMaterial(
        ca_snapshot=snapshot, certificate_fd=None, key_fd=None
    )


def assert_policy(holder: tls._TlsContext) -> None:
    context = holder._context
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.keylog_filename is None


@pytest.mark.parametrize("bundle", ["one", "multi", "whitespace", "duplicate", "crlf"])
def test_ca_bundle_policy_and_only_selected_trust(
    bundle: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = pem(), pem("ca2.pem")
    inputs = {
        "one": first,
        "multi": first + second,
        "whitespace": b" \t\r\n\v\f" + first + b" \t\r\n\v\f" + second + b" \t\r\n\v\f",
        "duplicate": first + second + first,
        "crlf": first.replace(b"\n", b"\r\n"),
    }
    calls: list[bytes] = []
    original_load = ssl.SSLContext.load_verify_locations

    def load(
        self: ssl.SSLContext,
        cafile: str | None = None,
        capath: str | None = None,
        cadata: str | bytes | None = None,
    ) -> None:
        assert cafile is capath is None
        assert isinstance(cadata, bytes)
        calls.append(cadata)
        original_load(self, cadata=cadata)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Unapproved TLS trust/cipher/ALPN/input mechanism")

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", load)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    for name in (
        "load_default_certs",
        "set_default_verify_paths",
        "set_ciphers",
        "set_alpn_protocols",
        "load_cert_chain",
    ):
        monkeypatch.setattr(ssl.SSLContext, name, forbidden)
    monkeypatch.setattr(os._Environ, "__getitem__", forbidden)
    with ca_material(inputs[bundle]) as material:
        result = tls._build_tls_context(material)
    assert isinstance(result, tls._TlsContext)
    assert_policy(result)
    expected = 1 if bundle in {"one", "crlf"} else 2
    assert result._context.cert_store_stats()["x509"] == expected
    assert result._context.cert_store_stats()["x509_ca"] == expected
    assert len(calls) == (3 if bundle == "duplicate" else expected)
    assert calls[0] == ssl.PEM_cert_to_DER_cert(first.decode("ascii"))


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "whitespace",
        "ascii",
        "nonascii",
        "begin",
        "end",
        "lowercase",
        "base64",
        "padding",
        "truncated",
        "der",
        "private-key",
        "request",
        "crl",
        "trusted",
        "mixed",
        "prefix",
        "suffix",
        "adjacent",
        "control",
    ],
)
def test_invalid_ca_profile_is_fixed_and_sanitized(kind: str) -> None:
    certificate = pem()
    inputs = {
        "empty": b"",
        "whitespace": b" \t\n\r\v\f",
        "ascii": b"CA-content-canary",
        "nonascii": b"\xff" + certificate,
        "begin": certificate.replace(b"BEGIN CERTIFICATE", b"BEGIN  CERTIFICATE"),
        "end": certificate.replace(b"END CERTIFICATE", b"END CERTIFICATE-"),
        "lowercase": certificate.replace(b"CERTIFICATE", b"certificate"),
        "base64": b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----",
        "padding": b"-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----",
        "truncated": b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----",
        "der": ssl.PEM_cert_to_DER_cert(certificate.decode("ascii")),
        "private-key": pem("client-key.pem"),
        "request": certificate.replace(b"CERTIFICATE", b"CERTIFICATE REQUEST"),
        "crl": certificate.replace(b"CERTIFICATE", b"X509 CRL"),
        "trusted": certificate.replace(b"CERTIFICATE", b"TRUSTED CERTIFICATE"),
        "mixed": certificate + pem("client-key.pem"),
        "prefix": b"# CA-comment-canary\n" + certificate,
        "suffix": certificate + b"CA-suffix-canary",
        "adjacent": certificate.rstrip() + certificate,
        "control": b"\x1c" + certificate,
    }
    with ca_material(inputs[kind]) as material:
        result = tls._build_tls_context(material)
    assert result is kc._Failure.INVALID_CA_MATERIAL
    assert "canary" not in str(result) + repr(result)


@pytest.mark.parametrize("chain", [False, True])
@pytest.mark.parametrize("change", ["none", "replace", "retarget", "unlink"])
def test_native_pinned_identity_and_borrowed_ownership(
    linux: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain: bool,
    change: str,
) -> None:
    preflight = selected(
        tmp_path, cert=pem("client-chain.pem" if chain else "client.pem")
    )
    if change == "retarget":
        for name in PATHS[1:]:
            path = tmp_path / name
            target = path.with_suffix(".original")
            path.rename(target)
            path.symlink_to(target)
    material = cr._load_credentials(preflight)
    assert isinstance(material, cr._CredentialMaterial)
    assert material._certificate_fd is not None and material._key_fd is not None
    descriptors = (material._certificate_fd, material._key_fd)
    for name in PATHS:
        path = tmp_path / name
        if change == "unlink":
            path.unlink()
        elif change in {"replace", "retarget"}:
            path.unlink()
            if change == "replace":
                path.write_bytes(b"replacement-content-canary")
            else:
                replacement = path.with_suffix(".replacement")
                replacement.write_bytes(b"symlink-retarget-content-canary")
                path.symlink_to(replacement)
    # OpenSSL reopens the pinned objects, independently of the borrowed offset.
    offsets = [os.lseek(fd, 0, os.SEEK_END) for fd in descriptors]
    closes: list[int] = []
    chain_paths: list[tuple[str, str]] = []
    original_close, original_chain = os.close, ssl.SSLContext.load_cert_chain

    def close(fd: int) -> None:
        closes.append(fd)
        original_close(fd)

    def load(
        self: ssl.SSLContext, certfile: str, keyfile: str, password: Callable[[], str]
    ) -> None:
        assert (certfile, keyfile) == tuple(f"/proc/self/fd/{fd}" for fd in descriptors)
        assert password is tls._reject_password
        chain_paths.append((certfile, keyfile))
        original_chain(self, certfile, keyfile, password=password)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("TLS construction reopened a path or changed an offset")

    with material:
        with monkeypatch.context() as guard:
            guard.setattr(os, "close", close)
            guard.setattr(os, "open", forbidden)
            guard.setattr(os, "lseek", forbidden)
            guard.setattr(ssl.SSLContext, "load_cert_chain", load)
            result = tls._build_tls_context(material)
            assert closes == []
            assert isinstance(result, tls._TlsContext)
        assert [os.lseek(fd, 0, os.SEEK_CUR) for fd in descriptors] == offsets
        # Keep the close spy through the owner's exit, not through the builder.
        monkeypatch.setattr(os, "close", close)
    assert closes == list(descriptors)
    material.close()
    assert closes == list(descriptors)
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert len(chain_paths) == 1
    assert_policy(result)
    assert result._context.cert_store_stats()["x509"] == 1
    assert result._context.get_ciphers()


@pytest.mark.parametrize(
    "kind",
    [
        "certificate",
        "key",
        "mismatch",
        "encrypted",
        "encrypted-traditional",
        "chain",
        "unsupported-key",
        "ca",
    ],
)
def test_native_identity_failure_does_not_take_descriptor_ownership(
    linux: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    cert, key, ca = pem("client.pem"), pem("client-key.pem"), pem()
    if kind == "certificate":
        cert = b"invalid-client-certificate-canary"
    elif kind in {"key", "unsupported-key"}:
        key = (
            b"invalid-private-key-canary"
            if kind == "key"
            else b"-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----"
        )
    elif kind == "mismatch":
        key = pem("mismatch-key.pem")
    elif kind in {"encrypted", "encrypted-traditional"}:
        key = pem(
            "encrypted-traditional-key.pem"
            if kind == "encrypted-traditional"
            else "encrypted-key.pem"
        )
    elif kind == "chain":
        cert += b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
    elif kind == "ca":
        ca = b"invalid-ca-canary"
    preflight = selected(tmp_path, cert=cert, key=key, ca=ca)
    material = cr._load_credentials(preflight)
    assert isinstance(material, cr._CredentialMaterial)
    assert material._certificate_fd is not None and material._key_fd is not None
    descriptors = (material._certificate_fd, material._key_fd)
    closes: list[int] = []
    original_close = os.close

    def close(fd: int) -> None:
        closes.append(fd)
        original_close(fd)

    monkeypatch.setattr(os, "close", close)
    with material:
        result = tls._build_tls_context(material)
        expected = (
            kc._Failure.INVALID_CA_MATERIAL
            if kind == "ca"
            else kc._Failure.UNSUPPORTED_ENCRYPTED_PRIVATE_KEY
            if kind.startswith("encrypted")
            else kc._Failure.INVALID_CLIENT_IDENTITY
        )
        assert result is expected
        assert closes == []
        for fd in descriptors:
            os.fstat(fd)
        exposed = repr(result) + str(result) + result.value
        assert all(
            name not in exposed
            for name in (*PATHS, TOKEN, "canary", "/proc/self/fd/", "PEM", "SSL")
        )
    material.close()
    assert closes == list(descriptors)
    assert capfd.readouterr() == ("", "")
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_password_callback_rejects_without_returning_a_password() -> None:
    with pytest.raises(tls._PasswordRequired):
        tls._reject_password()


@pytest.mark.parametrize(
    "exception",
    [KeyboardInterrupt, SystemExit, RuntimeError, TypeError, AttributeError],
)
@pytest.mark.parametrize("stage", ["construct", "ca", "identity"])
def test_unexpected_and_control_flow_exceptions_are_not_converted(
    exception: type[BaseException], stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Context:
        def __init__(self, protocol: object) -> None:
            if stage == "construct":
                raise exception("synthetic-control-flow")

        def load_verify_locations(self, **kwargs: object) -> None:
            if stage == "ca":
                raise exception("synthetic-control-flow")

        def load_cert_chain(self, **kwargs: object) -> None:
            raise exception("synthetic-control-flow")

    monkeypatch.setattr(ssl, "SSLContext", Context)
    with cr._CredentialMaterial(
        ca_snapshot=pem(), certificate_fd=None, key_fd=None
    ) as material:
        if stage == "identity":
            # Synthetic descriptor numbers only; do not transfer OS ownership.
            object.__setattr__(material, "_certificate_fd", -1)
            object.__setattr__(material, "_key_fd", -2)
        try:
            with pytest.raises(exception, match="synthetic-control-flow"):
                tls._build_tls_context(material)
        finally:
            object.__setattr__(material, "_certificate_fd", None)
            object.__setattr__(material, "_key_fd", None)


@pytest.mark.parametrize("stage", ["construct", "ca", "identity"])
@pytest.mark.parametrize("exception", [ssl.SSLError, OSError, ValueError])
def test_expected_native_failures_are_sanitized(
    stage: str, exception: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Context:
        def __init__(self, protocol: object) -> None:
            if stage == "construct":
                raise exception("OpenSSL-error-canary /proc/self/fd/999")

        def load_verify_locations(self, **kwargs: object) -> None:
            if stage == "ca":
                raise exception("CA-error-canary")

        def load_cert_chain(self, **kwargs: object) -> None:
            raise exception("key-error-canary")

    monkeypatch.setattr(ssl, "SSLContext", Context)
    material = ca_material(pem())
    if stage == "identity":
        object.__setattr__(material, "_certificate_fd", -1)
        object.__setattr__(material, "_key_fd", -2)
    try:
        result = tls._build_tls_context(material)
    finally:
        object.__setattr__(material, "_certificate_fd", None)
        object.__setattr__(material, "_key_fd", None)
        material.close()
    assert (
        result
        is {
            "construct": kc._Failure.TLS_CONTEXT_CONSTRUCTION_FAILED,
            "ca": kc._Failure.INVALID_CA_MATERIAL,
            "identity": kc._Failure.INVALID_CLIENT_IDENTITY,
        }[stage]
    )
    assert "canary" not in repr(result) + str(result)
    assert not hasattr(result, "__cause__")


def test_closed_material_fails_before_constructing_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = ca_material(pem())
    material.close()

    def forbidden(*args: object) -> None:
        pytest.fail("Closed credential material constructed a context")

    monkeypatch.setattr(ssl, "SSLContext", forbidden)
    assert (
        tls._build_tls_context(material) is kc._Failure.TLS_CONTEXT_CONSTRUCTION_FAILED
    )


def assert_confined(holder: object) -> None:
    assert "holder-secret-canary" not in repr(holder) + str(holder)
    operations: list[Callable[[object], object]] = [
        vars,
        json.dumps,
        cast(Callable[[object], object], dataclasses.asdict),
        copy.copy,
        copy.deepcopy,
        lambda value: getattr(value, "__getstate__")(),
        lambda value: getattr(value, "__reduce__")(),
        lambda value: getattr(value, "__reduce_ex__")(4),
    ]
    operations.extend(
        partial(pickle.dumps, protocol=protocol)
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1)
    )
    for operation in operations:
        with pytest.raises(TypeError):
            operation(holder)


def test_tls_holder_is_context_only_and_confined() -> None:
    with ca_material(pem()) as material:
        result = tls._build_tls_context(material)
    assert isinstance(result, tls._TlsContext)
    assert tls._TlsContext.__slots__ == ("_context",)
    assert_confined(result)
    with pytest.raises(AttributeError, match="Immutable TLS holder"):
        result._context = result._context
    with pytest.raises(AttributeError, match="Immutable TLS holder"):
        del result._context


def test_confinement_negative_canary_detects_unprotected_holder() -> None:
    class Unprotected:
        def __repr__(self) -> str:
            return "holder-secret-canary"

    with pytest.raises(AssertionError):
        assert_confined(Unprotected())


TLS_IMPORT_SCRIPT = r"""
import os,sys,ssl,base64,re,typing,threading,_thread,asyncio,socket,subprocess,getpass,builtins
from pathlib import Path
from importlib.util import find_spec
package_root = str(Path(find_spec('openkube_optimizer').origin).parent)
violations = []
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise AssertionError('Prohibited TLS import activity')
class Imports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'kubernetes','h11','yaml'}:
            reject()
def audit(event,args):
    if event.startswith(('socket.','subprocess.','os.spawn','os.exec')) or event in {'os.system','os.fork','os.forkpty'}:
        reject()
    if event == 'open':
        name, _, flags = args
        if not isinstance(name,str) or not name.startswith(package_root+'/') or not name.endswith(('.py','.pyc')):
            reject()
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC):
            reject()
sys.meta_path.insert(0,Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = os._Environ.__iter__ = reject
threading.Thread.start = _thread.start_new_thread = reject
if hasattr(_thread,'start_joinable_thread'):
    _thread.start_joinable_thread = reject
asyncio.BaseEventLoop.create_task = asyncio.new_event_loop = reject
ssl.create_default_context = ssl.SSLContext = reject
socket.socket = socket.getaddrinfo = reject
builtins.input = getpass.getpass = reject
from openkube_optimizer.collection import tls
assert not violations
assert not any(name.split('.')[0] in {'kubernetes','h11','yaml'} for name in sys.modules)
assert len(threading.enumerate()) == 1
"""


TLS_FLOW_SCRIPT = r"""
import os,sys,ssl,base64,re,typing,threading,_thread,asyncio,socket,subprocess,getpass,builtins
from pathlib import Path
from importlib.util import find_spec
root=Path(sys.argv[1])
certificate,mode=sys.argv[2]=='certificate',sys.argv[3]
assert sys.platform=='linux' and hasattr(os,'O_PATH')
package_root=str(Path(find_spec('openkube_optimizer').origin).parent)
from openkube_optimizer.collection import credentials as cr,kubeconfig as kc,preflight as pf
config=root/'explicit-synthetic-config'
document=kc._load_document(config)
assert isinstance(document,kc._Document)
preflight=pf._preflight(document,context_name='chosen')
assert isinstance(preflight,pf._Preflight)
del document
material=cr._load_credentials(preflight)
assert isinstance(material,cr._CredentialMaterial)
descriptors=tuple(fd for fd in (material._certificate_fd,material._key_fd) if fd is not None)
assert len(descriptors)==(2 if certificate else 0)
proc_paths=tuple(f'/proc/self/fd/{fd}' for fd in descriptors)
phase='imports'
violations=[]
class GuardViolation(RuntimeError):
    pass
def reject(*args,**kwargs):
    violations.append('forbidden')
    raise GuardViolation('Prohibited TLS construction activity')
class Imports:
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in {'kubernetes','h11','yaml'}:
            reject()
def audit(event,args):
    if event.startswith(('socket.','subprocess.','os.spawn','os.exec')) or event in {'os.system','os.fork','os.forkpty'}:
        reject()
    if event=='open':
        name,_,flags=args
        if not (phase=='imports' and isinstance(name,str) and name.startswith(package_root+'/') and name.endswith(('.py','.pyc'))):
            reject()
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC):
            reject()
sys.meta_path.insert(0,Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = os._Environ.__iter__ = reject
threading.Thread.start = _thread.start_new_thread = reject
if hasattr(_thread,'start_joinable_thread'):
    _thread.start_joinable_thread=reject
asyncio.BaseEventLoop.create_task = asyncio.new_event_loop = reject
socket.socket=socket.getaddrinfo=reject
builtins.input=getpass.getpass=reject
os.stat=os.lstat=os.readlink=os.access=reject
os.path.realpath=Path.resolve=Path.exists=reject
os.lseek=reject
ssl.create_default_context=reject
for name in ('load_default_certs','set_default_verify_paths','set_ciphers','set_alpn_protocols','wrap_socket','wrap_bio'):
    setattr(ssl.SSLContext,name,reject)
ssl.SSLSocket.do_handshake=reject
if hasattr(os,'fork'):
    os.fork=reject
original_ca=ssl.SSLContext.load_verify_locations
original_chain=ssl.SSLContext.load_cert_chain
original_close=os.close
ca_loads=[]
chain_loads=[]
closed=[]
def load_ca(self,cafile=None,capath=None,cadata=None):
    if cafile is not None or capath is not None or not isinstance(cadata,bytes):
        reject()
    ca_loads.append(len(cadata))
    return original_ca(self,cadata=cadata)
def load_chain(self,certfile,keyfile=None,password=None):
    if (certfile,keyfile)!=proc_paths or password is not tls._reject_password:
        reject()
    chain_loads.append('pinned')
    return original_chain(self,certfile,keyfile,password=password)
def close(fd):
    closed.append(fd)
    original_close(fd)
ssl.SSLContext.load_verify_locations=load_ca
ssl.SSLContext.load_cert_chain=load_chain
os.close=close
from openkube_optimizer.collection import tls
assert not violations
phase='flow'
with material:
    if mode not in {'clean','encrypted'}:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        actions={
            'ca-path':lambda: open(preflight.ca_path),
            'identity-path':lambda: context.load_cert_chain(root/'selected-cert-path-canary',root/'selected-key-path-canary',password=tls._reject_password),
            'config':lambda: open(config),
            'environment':lambda: os.getenv('SSL_CERT_FILE'),
            'trust':lambda: context.load_default_certs(),
            'verify-paths':lambda: context.set_default_verify_paths(),
            'default-context':lambda: ssl.create_default_context(),
            'sdk':lambda: __import__('kubernetes'),
            'socket':lambda: socket.socket(),
            'dns':lambda: socket.getaddrinfo('api.example.invalid',443),
            'handshake':lambda: context.wrap_socket(None),
            'helper':lambda: subprocess.run(['never-execute']),
            'password':lambda: builtins.input(),
            'getpass':lambda: getpass.getpass(),
            'thread':lambda: threading.Thread(target=lambda: None).start(),
            'task':lambda: asyncio.BaseEventLoop.create_task(None,None),
            'process':lambda: os.fork(),
            'ciphers':lambda: context.set_ciphers('ALL'),
            'alpn':lambda: context.set_alpn_protocols(['h2']),
        }
        try:
            actions[mode]()
        except GuardViolation:
            pass
    result=tls._build_tls_context(material)
    assert closed==[]
    for fd in descriptors:
        os.fstat(fd)
    if mode=='encrypted':
        assert result is kc._Failure.UNSUPPORTED_ENCRYPTED_PRIVATE_KEY
    else:
        assert isinstance(result,tls._TlsContext)
        context=result._context
        assert context.protocol==ssl.PROTOCOL_TLS_CLIENT
        assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
        assert context.minimum_version==ssl.TLSVersion.TLSv1_2
        assert context.maximum_version==ssl.TLSVersion.MAXIMUM_SUPPORTED
        assert context.keylog_filename is None
        assert context.cert_store_stats()['x509']==1
        assert tls._TlsContext.__slots__==('_context',)
    assert len(ca_loads)==1
    assert len(chain_loads)==(1 if certificate else 0)
assert closed==list(descriptors)
material.close()
assert closed==list(descriptors)
for fd in descriptors:
    try:
        os.fstat(fd)
    except OSError:
        pass
    else:
        raise AssertionError('Owner failed to close borrowed descriptor')
if isinstance(result,tls._TlsContext):
    assert result._context.get_ciphers()
assert len(threading.enumerate())==1
assert not any(name.split('.')[0] in {'kubernetes','h11'} for name in sys.modules)
assert not violations,'Guard detected prohibited activity'
"""


def test_tls_module_import_has_no_activation(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", TLS_IMPORT_SCRIPT],
        cwd=tmp_path,
        env={
            "HOME": str(tmp_path / "absent-home"),
            "KUBECONFIG": str(tmp_path / "forbidden"),
        },
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
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
        "ca-path",
        "identity-path",
        "config",
        "environment",
        "trust",
        "verify-paths",
        "default-context",
        "sdk",
        "socket",
        "dns",
        "handshake",
        "helper",
        "password",
        "getpass",
        "thread",
        "task",
        "process",
        "ciphers",
        "alpn",
    ],
)
def test_native_isolated_flow_and_negative_canaries(
    linux: None, tmp_path: Path, certificate: bool, mode: str
) -> None:
    selected(tmp_path, certificate=certificate)
    result = run_flow(tmp_path, certificate=certificate, mode=mode)
    if mode == "clean":
        assert result.returncode == 0, result.stderr
        assert result.stdout == result.stderr == ""
    else:
        assert result.returncode != 0
        assert "Guard detected prohibited activity" in result.stderr
        assert result.stdout == ""


def run_flow(
    tmp_path: Path, *, certificate: bool, mode: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            TLS_FLOW_SCRIPT,
            str(tmp_path),
            "certificate" if certificate else "token",
            mode,
        ],
        cwd=tmp_path,
        env={
            "HOME": str(tmp_path / "absent-home"),
            "KUBECONFIG": str(tmp_path / "forbidden"),
            "SSL_CERT_FILE": str(tmp_path / "forbidden-trust"),
            "SSL_CERT_DIR": str(tmp_path / "forbidden-trust-dir"),
            "SSLKEYLOGFILE": str(tmp_path / "forbidden-keylog"),
        },
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("name", ["encrypted-key.pem", "encrypted-traditional-key.pem"])
def test_native_isolated_encrypted_key_never_prompts(
    linux: None, tmp_path: Path, name: str
) -> None:
    selected(tmp_path, key=pem(name))
    result = run_flow(tmp_path, certificate=True, mode="encrypted")
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
