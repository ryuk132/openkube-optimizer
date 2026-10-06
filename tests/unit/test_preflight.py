"""Synthetic selection/preflight only; never real kubeconfig or credentials."""

import copy
import dataclasses
import json
import os
import pickle
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from openkube_optimizer.collection import kubeconfig as kc
from openkube_optimizer.collection import preflight as pf
from openkube_optimizer.domain import models

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


@pytest.mark.parametrize("certificate_auth", [False, True])
@pytest.mark.parametrize("location", ["relative", "absolute", "symlink"])
def test_load_time_origin_and_cwd_stability_without_credential_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    certificate_auth: bool,
    location: str,
) -> None:
    first, second, target = (tmp_path / name for name in ("first", "second", "target"))
    for directory in (first, second, target):
        directory.mkdir()
    data = BASE
    if certificate_auth:
        data = data.replace(
            b"token: synthetic-private-token-and-path",
            b"client-certificate: client.pem, client-key: ../keys/key.pem",
        )
    selected = first / "config"
    if location == "symlink":
        actual = target / "config"
        actual.write_bytes(data)
        selected.symlink_to(actual)
    else:
        selected.write_bytes(data)
    monkeypatch.chdir(tmp_path)
    selected_input = selected if location == "absolute" else Path("first/config")
    original_stat, original_open = os.stat, os.open
    accesses: list[str] = []

    def allowed(path: object) -> None:
        assert path == selected
        accesses.append("config")

    def guarded_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        allowed(path)
        return original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def guarded_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int
    ) -> int:
        allowed(path)
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
        return original_open(path, flags)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Unexpected credential or origin filesystem access")

    with monkeypatch.context() as guards:
        guards.setattr(os, "stat", guarded_stat)
        guards.setattr(os, "open", guarded_open)
        for name in ("lstat", "readlink", "access"):
            guards.setattr(os, name, forbidden)
        guards.setattr(Path, "resolve", forbidden)
        guards.setattr(os.path, "realpath", forbidden)
        guards.setattr(Path, "exists", forbidden)
        guards.setattr(Path, "open", forbidden)
        document = kc._load_document(selected_input)
        assert isinstance(document, kc._Document)
        os.chdir(second)
        result = pf._preflight(document, context_name="chosen")
        assert isinstance(result, pf._Preflight)
        assert result.ca_path == first / "ca.pem"
        if certificate_auth:
            assert isinstance(result.auth, pf._ClientCertificate)
            assert result.auth.certificate_path == first / "client.pem"
            assert result.auth.key_path == first / "../keys/key.pem"
        else:
            assert isinstance(result.auth, pf._BearerToken)
        os.chdir(target)
        assert result.ca_path == first / "ca.pem"
        if isinstance(result.auth, pf._ClientCertificate):
            assert result.auth.certificate_path == first / "client.pem"
            assert result.auth.key_path == first / "../keys/key.pem"
    assert accesses == ["config", "config"]


@pytest.mark.parametrize("token", ["synthetic-opaque ", " "])
def test_rejected_trailing_space_token_would_fail_future_h11_header(
    document: kc._Document, tmp_path: Path, token: str
) -> None:
    # Characterize the previous blocker without constructing transport.
    import h11

    payload(document, "users")["token"] = token
    result = select(document, tmp_path)
    assert result is kc._Failure.INVALID_AUTH
    with pytest.raises(h11.LocalProtocolError):
        h11.Request(
            method=b"GET",
            target=b"/",
            headers=[
                (b"Host", b"api.example.invalid"),
                (b"Authorization", ("Bearer " + token).encode("utf-8")),
            ],
        )


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
    return pf._preflight(document, context_name=context)


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
    result = pf._preflight(document, context_name="chosen")
    assert isinstance(result, pf._Preflight)
    assert result.ca_path == tmp_path / "absolute.pem"
    assert isinstance(result.auth, pf._ClientCertificate)
    assert result.auth.certificate_path == tmp_path / "client.pem"


@pytest.mark.parametrize(
    "token",
    [
        "simple123",
        "eyJhbGciOiJIUzI1NiJ9.opaque.signature",
        "opaque.not-a-jwt",
        "!~",
        "".join(chr(code) for code in range(33, 127)),
    ],
)
def test_token_is_opaque(document: kc._Document, tmp_path: Path, token: str) -> None:
    payload(document, "users")["token"] = token
    result = select(document, tmp_path)
    assert isinstance(result, pf._Preflight) and isinstance(
        result.auth, pf._BearerToken
    )
    assert result.auth.token == token
    import h11

    value = ("Bearer " + result.auth.token).encode("ascii")
    request = h11.Request(
        method=b"GET",
        target=b"/",
        headers=[(b"Host", b"api.example.invalid"), (b"Authorization", value)],
    )
    assert dict(request.headers)[b"authorization"] == value


@pytest.mark.parametrize(
    "token",
    [
        "",
        " leading",
        "internal space",
        "trailing ",
        "  ",
        "x\r",
        "x\n",
        "x\x00",
        "x\t",
        "x\x01",
        "x\x1f",
        "x\x7f",
        "x\x80",
        "x\x85",
        "x\x9f",
        "xé",
        "x漢",
        "x😀",
        "x\u00a0",
        "x\u2003",
        "x\u2028",
        [],
        {},
    ],
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
assert isinstance(pf._preflight(document, context_name='chosen'), pf._Preflight)
document._data['users'][0]['user'] = {'client-certificate': 'never-open.py', 'client-key': 'never-open.key'}
assert isinstance(pf._preflight(document, context_name='chosen'), pf._Preflight)
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


@pytest.mark.parametrize("code", list(range(33)) + list(range(127, 160)))
def test_token_and_endpoint_control_boundaries(
    document: kc._Document, tmp_path: Path, code: int
) -> None:
    payload(document, "users")["token"] = "opaque" + chr(code)
    assert select(document, tmp_path) is kc._Failure.INVALID_AUTH
    payload(document, "users")["token"] = CANARY
    payload(document, "clusters")["server"] = "https://api.example" + chr(code)
    assert select(document, tmp_path) is kc._Failure.INVALID_ENDPOINT


@pytest.mark.parametrize(
    "server",
    [
        "https://.api.example",
        "https://api.example..",
        "https://2130706433",
        "https://0177.0.0.1",
        "https://0x7f.0x00.0x00.0x01",
        "https://[2001:db8::1]:443",
        "https://api.example:00000",
        "https://api.example:443:443",
        "https://api.example/%2F",
        "https://api.example/%5c",
        "https://api.example/%2E/",
        "https://api.example/.%2e/",
        "https://api.example/%252e%252e",
        "https://api.example/a;b/c",
        "https://api.example/a/;parameter",
        "https:////api.example",
        "\x00https://api.example",
        "\t\nhttps://api.example",
        "https://api.\texample",
        "https://api.example/\nbase",
        "https://api.example:４４３",
    ],
)
def test_endpoint_normalization_ambiguities(
    document: kc._Document, tmp_path: Path, server: str
) -> None:
    from urllib.parse import urlsplit

    # A stdlib parser can strip some rejected characters. The boundary must
    # evaluate the supplied text independently, not its normalized equivalent.
    try:
        urlsplit(server)
    except ValueError:
        pass
    payload(document, "clusters")["server"] = server
    assert select(document, tmp_path) is kc._Failure.INVALID_ENDPOINT


def test_combined_eight_canary_confinement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    canaries = tuple(
        "combined-synthetic-" + category + "-canary"
        for category in (
            "token",
            "raw",
            "context",
            "cluster",
            "user",
            "ca",
            "certificate",
            "key",
        )
    )
    token, raw, context, cluster, user, ca, certificate, key = canaries
    path = tmp_path / "synthetic-origin-canary" / "config"
    path.parent.mkdir()
    data = f"""apiVersion: v1
kind: Config
current-context: unrelated
contexts: [{{name: {context}, context: {{cluster: {cluster}, user: {user}}}}}]
clusters: [{{name: {cluster}, cluster: {{server: https://api.example.invalid, certificate-authority: {ca}}}}}]
users: [{{name: {user}, user: {{token: {token}}}}}]
extra: {raw}
"""
    records: list[object] = []
    for auth in (
        f"token: {token}",
        f"client-certificate: {certificate}, client-key: {key}",
    ):
        path.write_text(data.replace(f"token: {token}", auth), encoding="utf-8")
        document = kc._load_document(path)
        assert isinstance(document, kc._Document)
        result = pf._preflight(document, context_name=context)
        assert isinstance(result, pf._Preflight)
        records.extend((document, result, result.auth))
        assert not hasattr(result, "_data")
        # Unknown selected fields fail closed without retaining source errors.
        payload(document, "users")["unsupported"] = raw
        failure = pf._preflight(document, context_name=context)
        assert failure is kc._Failure.INVALID_AUTH
        assert all(canary not in str(failure) + repr(failure) for canary in canaries)
    for record in records:
        assert all(canary not in str(record) + repr(record) for canary in canaries)
        assert str(path.parent) not in str(record) + repr(record)
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
            with pytest.raises(TypeError) as caught:
                operation(record)
            outward = str(caught.value) + repr(caught.value)
            assert all(canary not in outward for canary in canaries)
            assert str(path.parent) not in outward
            assert caught.value.__cause__ is None
            assert caught.value.__context__ is None
    # Closed M2 record validation rejects a raw mapping rather than retaining it.
    with pytest.raises(ValueError):
        models.ResourceAllocation(
            cpu_request_cores=cast(Decimal, {"raw": raw}),
            cpu_limit_cores=models.FieldState.ABSENT,
            memory_request_bytes=models.FieldState.ABSENT,
            memory_limit_bytes=models.FieldState.ABSENT,
        )
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("suffix", [" ", "\n", "\x85", "é", "\u2028"])
def test_rejected_token_canary_has_fixed_outward_failure(
    document: kc._Document,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    suffix: str,
) -> None:
    payload(document, "users")["token"] = CANARY + suffix
    result = select(document, tmp_path)
    assert result is kc._Failure.INVALID_AUTH
    assert CANARY not in str(result) + repr(result)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "outcome",
    [
        "success",
        "metadata-error",
        "read-error",
        "oversize",
        "utf8",
        "yaml",
        "preflight",
    ],
)
def test_combined_descriptor_cleanup_and_no_file_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    path = tmp_path / "explicit"
    data = BASE
    if outcome == "oversize":
        data += b" " * kc._MAX_BYTES
    elif outcome == "utf8":
        data += b"\xff"
    elif outcome == "yaml":
        data += b"broken: ["
    elif outcome == "preflight":
        data = data.replace(CANARY.encode(), (CANARY + " ").encode())
        # Quote the token to preserve its trailing SPACE through YAML parsing.
        data = data.replace((CANARY + " ").encode(), ("'" + CANARY + " '").encode())
    path.write_bytes(data)
    before = set(tmp_path.iterdir())
    original_open, original_fstat = os.open, os.fstat
    opened: list[int] = []

    def tracked_open(path: Path, flags: int) -> int:
        fd = original_open(path, flags)
        opened.append(fd)
        return fd

    def failed(*args: object) -> bytes:
        raise OSError(CANARY)

    with monkeypatch.context() as guards:
        guards.setattr(os, "open", tracked_open)
        if outcome == "metadata-error":
            guards.setattr(os, "fstat", failed)
        elif outcome == "read-error":
            guards.setattr(os, "read", failed)
        document = kc._load_document(path)
        if outcome in {"success", "preflight"}:
            assert isinstance(document, kc._Document)
            result = pf._preflight(document, context_name="chosen")
            if outcome == "preflight":
                assert result is kc._Failure.INVALID_AUTH
            else:
                assert isinstance(result, pf._Preflight)
        else:
            assert isinstance(document, kc._Failure)
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            original_fstat(fd)
    assert set(tmp_path.iterdir()) == before


# Reused verbatim by the installed-wheel gate, without importing pytest there.
COMBINED_GATE_SCRIPT = r"""
import os, sys, threading, _thread, asyncio, ssl, socket, subprocess, re
from pathlib import Path
from importlib.util import find_spec
import yaml  # Runtime parser import is harness setup, outside the guarded flow.
path = Path(sys.argv[1])
mode = sys.argv[2]
package_root = str(Path(find_spec('openkube_optimizer').origin).parent)
phase = 'imports'
violations = []
descriptors = set()
class GuardViolation(RuntimeError):
    pass
def reject(*args, **kwargs):
    violations.append('forbidden')
    raise GuardViolation('Prohibited gate activity')
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
        config_read = phase == 'loading' and name == str(path)
        if not (module_read or config_read):
            reject()
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            reject()
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
os._Environ.__getitem__ = reject
os._Environ.__iter__ = reject
threading.Thread.start = reject
_thread.start_new_thread = reject
if hasattr(_thread, 'start_joinable_thread'):
    _thread.start_joinable_thread = reject
asyncio.BaseEventLoop.create_task = reject
asyncio.new_event_loop = reject
ssl.SSLContext = reject
socket.socket = reject
socket.getaddrinfo = reject
socket.gethostbyname = reject
from openkube_optimizer.collection import kubeconfig as kc, preflight as pf
assert not violations
phase = 'loading'
original_stat, original_open, original_close, original_fstat = os.stat, os.open, os.close, os.fstat
def guarded_stat(name, *args, **kwargs):
    if phase != 'loading' or name != path:
        reject()
    return original_stat(name, *args, **kwargs)
def guarded_open(name, flags, *args, **kwargs):
    if phase != 'loading' or name != path:
        reject()
    fd = original_open(name, flags, *args, **kwargs)
    descriptors.add(fd)
    return fd
def guarded_close(fd):
    original_close(fd)
    descriptors.remove(fd)
    try:
        original_fstat(fd)
    except OSError:
        return
    raise AssertionError('Descriptor remained open')
os.stat, os.open, os.close = guarded_stat, guarded_open, guarded_close
os.lstat = os.readlink = os.access = reject
os.path.realpath = reject
Path.resolve = Path.exists = reject
if mode != 'clean':
    actions = {
        'credential-open': lambda: open(path.parent / 'never-open.py'),
        'credential-stat': lambda: os.stat(path.parent / 'never-open.pem'),
        'resolve': lambda: path.resolve(),
        'environment': lambda: os.getenv('KUBECONFIG'),
        'sdk': lambda: __import__('kubernetes'),
        'ssl': lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        'socket': lambda: socket.socket(),
        'dns': lambda: socket.getaddrinfo('api.example.invalid', 443),
        'helper': lambda: subprocess.run(['never-execute']),
        'thread': lambda: threading.Thread(target=lambda: None).start(),
        'task': lambda: asyncio.BaseEventLoop.create_task(None, None),
    }
    try:
        actions[mode]()
    except GuardViolation:
        pass  # The final violation assertion must detect even swallowed errors.
document = kc._load_document(path)
assert isinstance(document, kc._Document)
assert not descriptors
phase = 'preflight'
first = pf._preflight(document, context_name='chosen')
assert isinstance(first, pf._Preflight)
assert isinstance(first.auth, pf._BearerToken)
assert first.ca_path == path.parent / 'ca.pem'
assert pf._preflight(document, context_name='other') == kc._Failure.INVALID_AUTH
document._data['users'][0]['user'] = {
    'client-certificate': 'never-open.py', 'client-key': '../keys/never-open.key'
}
second = pf._preflight(document, context_name='chosen')
assert isinstance(second, pf._Preflight)
assert isinstance(second.auth, pf._ClientCertificate)
assert second.auth.certificate_path == path.parent / 'never-open.py'
assert second.auth.key_path == path.parent / '../keys/never-open.key'
assert not descriptors
assert len(threading.enumerate()) == 1
assert not any(name.split('.')[0] in {'kubernetes', 'h11'} for name in sys.modules)
assert not violations, 'Guard detected prohibited activity'
"""

COMBINED_GATE_DATA = (
    BASE
    + b"""
- name: unused
  user: {exec: {command: never-run}, auth-provider: {name: never-refresh}}
"""
)


@pytest.mark.parametrize(
    "mode",
    [
        "clean",
        "credential-open",
        "credential-stat",
        "resolve",
        "environment",
        "sdk",
        "ssl",
        "socket",
        "dns",
        "helper",
        "thread",
        "task",
    ],
)
def test_guarded_combined_flow_and_negative_canaries(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "explicit-synthetic"
    # A valid alternate context selects excluded helpers; current-context is
    # powerless when the explicit chosen context names the supported identity.
    path.write_bytes(
        COMBINED_GATE_DATA.replace(
            b"clusters:\n",
            b"- name: other\n  context: {cluster: cluster-one, user: unused}\nclusters:\n",
        )
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", COMBINED_GATE_SCRIPT, str(path), mode],
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
