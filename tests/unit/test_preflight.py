"""Synthetic selection/preflight only; never real kubeconfig or credentials."""

import json
import pickle
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import cast

import pytest

from openkube_optimizer.collection import kubeconfig as kc
from openkube_optimizer.collection import preflight as pf

CANARY = "synthetic-private-token-and-path"
BASE = b"""apiVersion: v1
kind: Config
current-context: other
contexts:
- name: chosen
  context: {cluster: cluster-one, user: user-one, namespace: ignored}
clusters:
- name: cluster-one
  cluster: {server: 'https://API.Example.test:6443/prefix/', certificate-authority: ca.pem}
users:
- name: user-one
  user: {token: synthetic-private-token-and-path}
"""


@pytest.fixture
def document(tmp_path: Path) -> kc._Document:
    path = tmp_path / "config"
    path.write_bytes(BASE)
    result = kc._load_document(path)
    assert isinstance(result, kc._Document)
    return result


def entries(document: kc._Document, collection: str) -> list[kc._Value]:
    result = document._data[collection]
    assert isinstance(result, list)
    return result


def entry(document: kc._Document, collection: str) -> dict[str, kc._Value]:
    result = entries(document, collection)[0]
    assert isinstance(result, dict)
    return result


def payload(document: kc._Document, collection: str) -> dict[str, kc._Value]:
    result = entry(document, collection)[collection[:-1]]
    assert isinstance(result, dict)
    return result


def select(
    document: kc._Document, tmp_path: Path, context: str = "chosen"
) -> pf._Preflight | kc._Failure:
    return pf._preflight(
        document, context_name=context, kubeconfig_path=tmp_path / "config"
    )


def test_explicit_selection_and_ignored_scope(
    document: kc._Document, tmp_path: Path
) -> None:
    result = select(document, tmp_path)
    assert isinstance(result, pf._Preflight)
    assert result.hostname == "API.Example.test"
    assert result.port == 6443
    assert result.authority == "API.Example.test:6443"
    assert result.base_path == "/prefix/"
    assert result.ca_path == tmp_path / "ca.pem"
    assert isinstance(result.auth, pf._BearerToken)
    assert result.auth.token == CANARY
    assert not hasattr(result, "namespace")
    assert not hasattr(result, "context")
    assert not hasattr(result, "_data")
    assert select(document, tmp_path, "other") is kc._Failure.CONTEXT_NOT_FOUND
    assert select(document, tmp_path, "Chosen") is kc._Failure.CONTEXT_NOT_FOUND


@pytest.mark.parametrize("name", ["", "bad\nname", "bad\x00name"])
def test_invalid_requested_context(
    document: kc._Document, tmp_path: Path, name: str
) -> None:
    assert select(document, tmp_path, name) is kc._Failure.INVALID_CONTEXT


@pytest.mark.parametrize("collection", ["contexts", "clusters", "users"])
def test_duplicate_names_even_when_unselected(
    document: kc._Document, tmp_path: Path, collection: str
) -> None:
    entries(document, collection).extend([{"name": "unused"}, {"name": "unused"}])
    assert select(document, tmp_path) is kc._Failure.INVALID_NAMED_ENTRY


@pytest.mark.parametrize("collection", ["contexts", "clusters", "users"])
@pytest.mark.parametrize(
    "bad", ["scalar", [], {}, {"name": ""}, {"name": []}, {"name": "x\n"}]
)
def test_malformed_named_entry(
    document: kc._Document, tmp_path: Path, collection: str, bad: kc._Value
) -> None:
    entries(document, collection).append(bad)
    assert select(document, tmp_path) is kc._Failure.INVALID_NAMED_ENTRY


@pytest.mark.parametrize("field", ["cluster", "user"])
@pytest.mark.parametrize("value", [None, "", [], {}])
def test_invalid_context_reference(
    document: kc._Document, tmp_path: Path, field: str, value: kc._Value | None
) -> None:
    selected = payload(document, "contexts")
    if value is None:
        selected.pop(field)
    else:
        selected[field] = value
    assert select(document, tmp_path) is kc._Failure.INVALID_CONTEXT


@pytest.mark.parametrize(
    ("field", "failure"),
    [("cluster", kc._Failure.CLUSTER_NOT_FOUND), ("user", kc._Failure.USER_NOT_FOUND)],
)
def test_missing_referenced_entry(
    document: kc._Document, tmp_path: Path, field: str, failure: kc._Failure
) -> None:
    payload(document, "contexts")[field] = CANARY
    assert select(document, tmp_path) is failure


@pytest.mark.parametrize(
    ("collection", "failure"),
    [
        ("contexts", kc._Failure.INVALID_CONTEXT),
        ("clusters", kc._Failure.INVALID_CLUSTER),
        ("users", kc._Failure.INVALID_AUTH),
    ],
)
def test_missing_or_malformed_selected_payload(
    document: kc._Document, tmp_path: Path, collection: str, failure: kc._Failure
) -> None:
    entry(document, collection).pop(collection[:-1])
    assert select(document, tmp_path) is failure
    entry(document, collection)[collection[:-1]] = []
    assert select(document, tmp_path) is failure


@pytest.mark.parametrize(
    "field",
    [
        "certificate-authority-data",
        "insecure-skip-tls-verify",
        "tls-server-name",
        "proxy-url",
        "unknown-behavior",
    ],
)
def test_forbidden_cluster_settings(
    document: kc._Document, tmp_path: Path, field: str
) -> None:
    # Presence is rejected even when a YAML scalar looks false/empty.
    payload(document, "clusters")[field] = "false"
    assert select(document, tmp_path) is kc._Failure.INVALID_CLUSTER


@pytest.mark.parametrize("field", ["server", "certificate-authority"])
def test_required_cluster_settings(
    document: kc._Document, tmp_path: Path, field: str
) -> None:
    payload(document, "clusters").pop(field)
    assert select(document, tmp_path) is kc._Failure.INVALID_CLUSTER


@pytest.mark.parametrize("value", ["", "bad\x00path", [], {}])
def test_invalid_ca_reference(
    document: kc._Document, tmp_path: Path, value: kc._Value
) -> None:
    payload(document, "clusters")["certificate-authority"] = value
    assert select(document, tmp_path) is kc._Failure.INVALID_CLUSTER


@pytest.mark.parametrize(
    ("server", "port", "path"),
    [
        ("https://api.example", 443, ""),
        ("https://api.example/", 443, "/"),
        ("https://api.example:1/base/v1", 1, "/base/v1"),
        ("https://api.example:65535/base/", 65535, "/base/"),
        ("https://api.example:00443", 443, ""),
        ("https://" + "a" * 63 + ".example", 443, ""),
        ("https://" + ".".join(["a" * 63] * 3 + ["b" * 61]), 443, ""),
    ],
)
def test_valid_endpoints(
    document: kc._Document, tmp_path: Path, server: str, port: int, path: str
) -> None:
    payload(document, "clusters")["server"] = server
    result = select(document, tmp_path)
    assert isinstance(result, pf._Preflight)
    assert result.port == port
    assert result.base_path == path
    assert result.authority == server.removeprefix("https://").split("/")[0]


@pytest.mark.parametrize(
    "server",
    [
        "http://api.example",
        "ftp://api.example",
        "HTTPS://api.example",
        "https://user@api.example",
        "https://user:secret@api.example",
        "https://api.example?",
        "https://api.example?q=x",
        "https://api.example#",
        "https://api.example#fragment",
        "https://api.example\n",
        " https://api.example",
        "https://api.example/with space",
        "https://api.example\\path",
        "https://localhost",
        "https://127.0.0.1",
        "https://127.1",
        "https://0x7f.0.0.1",
        "https://[::1]",
        "https://api.example.",
        "https://api..example",
        "https://-api.example",
        "https://api-.example",
        "https://api_test.example",
        "https://é.example",
        "https://xn--abc.example",
        "https://" + "a" * 64 + ".example",
        "https://" + ".".join(["a" * 63] * 3 + ["b" * 62]),
        "https://api.example:",
        "https://api.example:0",
        "https://api.example:65536",
        "https://api.example:-1",
        "https://api.example:+443",
        "https://api.example:abc",
        "https://api.example:" + "9" * 5000,
        "https://api.example/../base",
        "https://api.example/a/./b",
        "https://api.example/a/..",
        "https://api.example//base",
        "https://api.example/base//",
        "https://api.example/%2e%2e",
        "https://api.example/a%2fb",
        "https://api.example/%41",
        "https://api.example/a/..;parameter",
        "https://api.example/a;b",
    ],
)
def test_invalid_endpoints(document: kc._Document, tmp_path: Path, server: str) -> None:
    payload(document, "clusters")["server"] = server
    assert select(document, tmp_path) is kc._Failure.INVALID_ENDPOINT


def test_certificate_references_and_no_path_expansion(
    document: kc._Document, tmp_path: Path
) -> None:
    entry(document, "users")["user"] = {
        "client-certificate": "client.pem",
        "client-key": "../keys/key.pem",
    }
    payload(document, "clusters")["certificate-authority"] = "~/$UNEXPANDED/ca.pem"
    result = select(document, tmp_path)
    assert isinstance(result, pf._Preflight)
    assert result.ca_path == tmp_path / "~/$UNEXPANDED/ca.pem"
    assert isinstance(result.auth, pf._ClientCertificate)
    assert result.auth.certificate_path == tmp_path / "client.pem"
    assert result.auth.key_path == tmp_path / "../keys/key.pem"
    payload(document, "clusters")["certificate-authority"] = str(
        tmp_path / "absolute.pem"
    )
    result = pf._preflight(
        document, context_name="chosen", kubeconfig_path=Path("relative/config")
    )
    assert isinstance(result, pf._Preflight)
    assert result.ca_path == tmp_path / "absolute.pem"
    assert isinstance(result.auth, pf._ClientCertificate)
    assert result.auth.certificate_path == Path.cwd() / "relative/client.pem"


@pytest.mark.parametrize(
    "token", [" leading-and-trailing ", "opaque.not-a-jwt", "not-normalized-é"]
)
def test_token_is_opaque(document: kc._Document, tmp_path: Path, token: str) -> None:
    payload(document, "users")["token"] = token
    result = select(document, tmp_path)
    assert isinstance(result, pf._Preflight) and isinstance(
        result.auth, pf._BearerToken
    )
    assert result.auth.token == token


@pytest.mark.parametrize(
    "token", ["", "x\r", "x\n", "x\x00", "x\t", "x\x7f", "x\x85", [], {}]
)
def test_invalid_tokens(
    document: kc._Document, tmp_path: Path, token: kc._Value
) -> None:
    payload(document, "users")["token"] = token
    assert select(document, tmp_path) is kc._Failure.INVALID_AUTH


@pytest.mark.parametrize(
    "field",
    [
        "exec",
        "auth-provider",
        "tokenFile",
        "username",
        "password",
        "client-certificate-data",
        "client-key-data",
        "as",
        "as-uid",
        "as-groups",
        "as-user-extra",
        "unknown-helper",
    ],
)
def test_unsupported_selected_auth(
    document: kc._Document, tmp_path: Path, field: str
) -> None:
    payload(document, "users")[field] = CANARY
    assert select(document, tmp_path) is kc._Failure.INVALID_AUTH


@pytest.mark.parametrize(
    "user",
    [
        {},
        {"token": CANARY, "client-certificate": CANARY},
        {"token": CANARY, "client-certificate": CANARY, "client-key": CANARY},
        {"client-certificate": CANARY},
        {"client-key": CANARY},
        {"client-certificate": "", "client-key": CANARY},
        {"client-certificate": CANARY, "client-key": "bad\npath"},
    ],
)
def test_incomplete_or_mixed_auth(
    document: kc._Document, tmp_path: Path, user: dict[str, kc._Value]
) -> None:
    entry(document, "users")["user"] = user
    assert select(document, tmp_path) is kc._Failure.INVALID_AUTH


def test_unselected_payloads_are_inert(document: kc._Document, tmp_path: Path) -> None:
    entries(document, "users").append(
        {
            "name": "other-user",
            "user": {
                "exec": {"command": "never-run"},
                "auth-provider": {"name": "unused"},
            },
        }
    )
    entries(document, "clusters").append(
        {
            "name": "other-cluster",
            "cluster": {"server": "http://invalid", "proxy-url": "never-used"},
        }
    )
    entries(document, "contexts").append(
        {"name": "other", "context": {"cluster": "other-cluster", "user": "other-user"}}
    )
    assert isinstance(select(document, tmp_path), pf._Preflight)


def test_records_are_immutable_redacted_and_not_generic_serializable(
    document: kc._Document, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    token_result = select(document, tmp_path)
    assert isinstance(token_result, pf._Preflight)
    entry(document, "users")["user"] = {
        "client-certificate": CANARY,
        "client-key": CANARY,
    }
    certificate_result = select(document, tmp_path)
    assert isinstance(certificate_result, pf._Preflight)
    for record in (
        token_result,
        token_result.auth,
        certificate_result,
        certificate_result.auth,
    ):
        assert CANARY not in repr(record)
        assert str(tmp_path) not in str(record)
        for field in record.__slots__:
            with pytest.raises(AttributeError) as caught:
                setattr(record, field, CANARY)
            assert CANARY not in str(caught.value)
            with pytest.raises(AttributeError):
                delattr(record, field)
        # Deliberately exercise the invalid asdict input, bypassing its static
        # dataclass-only signature to verify runtime rejection as well.
        serializers: tuple[Callable[[object], object], ...] = (
            json.dumps,
            pickle.dumps,
            cast(Callable[[object], object], asdict),
            vars,
        )
        for serialize in serializers:
            with pytest.raises(TypeError) as rejected:
                serialize(record)
            assert CANARY not in str(rejected.value)
        with pytest.raises(TypeError, match="Preflight records cannot be serialized"):
            record.__getstate__()
    for failure in kc._Failure:
        assert CANARY not in repr(failure)
        assert str(tmp_path) not in str(failure)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("certificate-authority", CANARY + "\x00", kc._Failure.INVALID_CLUSTER),
        ("server", "https://" + CANARY + "@api.example", kc._Failure.INVALID_ENDPOINT),
        ("token", CANARY + "\r\n", kc._Failure.INVALID_AUTH),
    ],
)
def test_actual_failure_outcomes_do_not_expose_input(
    document: kc._Document,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    field: str,
    value: str,
    failure: kc._Failure,
) -> None:
    payload(document, "users" if field == "token" else "clusters")[field] = value
    result = select(document, tmp_path)
    assert result is failure
    assert CANARY not in repr(result)
    assert CANARY not in str(result)
    assert str(tmp_path) not in repr(result)
    assert capsys.readouterr() == ("", "")


def test_preflight_has_no_credential_sdk_or_network_side_effects(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-config"
    path.write_bytes(BASE + b"# synthetic only\n")
    script = r"""
import os, sys, threading, _thread
from pathlib import Path
from openkube_optimizer.collection import kubeconfig as kc
path = Path(sys.argv[1])
document = kc._load_document(path)
assert isinstance(document, kc._Document)
document._data['users'].append({'name': 'unused', 'user': {'exec': {'command': 'never-run'}}})
violations = []
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise AssertionError('Unexpected preflight side effect')
class Imports:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'kubernetes', 'h11', 'ssl', 'socket'}:
            reject()
def audit(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.spawn', 'os.exec')):
        reject()
    if event in {'os.system', 'os.fork', 'os.forkpty'}:
        reject()
    if event == 'open':
        name = args[0]
        if not isinstance(name, str) or not name.endswith(('.py', '.pyc')):
            reject()
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = reject
threading.Thread.start = reject
_thread.start_new_thread = reject
from openkube_optimizer.collection import preflight as pf
# Once imports complete, reject ALL file opens (even credential names ending .py).
def no_open(event, args):
    if event == 'open':
        reject()
sys.addaudithook(no_open)
os.stat = reject
os.lstat = reject
os.readlink = reject
assert isinstance(pf._preflight(document, context_name='chosen', kubeconfig_path=path), pf._Preflight)
document._data['users'][0]['user'] = {'client-certificate': 'never-open.py', 'client-key': 'never-open.key'}
assert isinstance(pf._preflight(document, context_name='chosen', kubeconfig_path=path), pf._Preflight)
assert not violations
assert not any(n.split('.')[0] in {'kubernetes', 'h11', 'ssl', 'socket'} for n in sys.modules)
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
