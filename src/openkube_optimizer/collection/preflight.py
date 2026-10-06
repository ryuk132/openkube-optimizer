"""Private, local preflight facts; no credential-file or network I/O.

These records are transport-only, never domain/report data. Their guarded
representations/serialization prevent ordinary accidental disclosure, not
deliberate reflection or access by compromised code in this process.
"""

import re
from pathlib import Path
from typing import Never, SupportsIndex

from openkube_optimizer.collection.kubeconfig import _Document, _Failure, _Value

_ENDPOINT_POLICY_VERSION = "endpoint-preflight-v1"
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_URL = re.compile(r"https://([^/:?#]+)(?::([0-9]+))?(/[^?#]*)?")
# Initial prefixes use unreserved ASCII segments only: no encoded separators
# or path-parameter delimiters with proxy-dependent interpretations.
_BASE_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*/?")


class _PrivateRecord:
    """Shared safeguards for the three adapter-local preflight records only."""

    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Immutable preflight record")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Immutable preflight record")

    def __repr__(self) -> str:
        return "<preflight record: redacted>"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()

    def __getstate__(self) -> Never:
        raise TypeError("Preflight records cannot be serialized")


class _BearerToken(_PrivateRecord):
    __slots__ = ("token",)
    token: str

    def __init__(self, *, token: str) -> None:
        object.__setattr__(self, "token", token)


class _ClientCertificate(_PrivateRecord):
    __slots__ = ("certificate_path", "key_path")
    certificate_path: Path
    key_path: Path

    def __init__(self, *, certificate_path: Path, key_path: Path) -> None:
        object.__setattr__(self, "certificate_path", certificate_path)
        object.__setattr__(self, "key_path", key_path)


class _Preflight(_PrivateRecord):
    __slots__ = ("hostname", "port", "authority", "base_path", "ca_path", "auth")
    hostname: str
    port: int
    authority: str
    base_path: str
    ca_path: Path
    auth: _BearerToken | _ClientCertificate

    def __init__(
        self,
        *,
        hostname: str,
        port: int,
        authority: str,
        base_path: str,
        ca_path: Path,
        auth: _BearerToken | _ClientCertificate,
    ) -> None:
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "authority", authority)
        object.__setattr__(self, "base_path", base_path)
        object.__setattr__(self, "ca_path", ca_path)
        object.__setattr__(self, "auth", auth)


def _text(value: object) -> bool:
    # Preserve all remaining text, including whitespace in opaque tokens/names.
    return (
        isinstance(value, str)
        and bool(value)
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    )


def _index(value: _Value | None) -> dict[str, dict[str, _Value]] | _Failure:
    if not isinstance(value, list):
        return _Failure.INVALID_NAMED_ENTRY
    indexed: dict[str, dict[str, _Value]] = {}
    for entry in value:
        if not isinstance(entry, dict):
            return _Failure.INVALID_NAMED_ENTRY
        name = entry.get("name")
        if not isinstance(name, str) or not _text(name) or name in indexed:
            return _Failure.INVALID_NAMED_ENTRY
        indexed[name] = entry
    return indexed


def _endpoint(server: _Value | None) -> tuple[str, int, str, str] | _Failure:
    # Match the restricted syntax directly: general URL parsers may strip
    # controls or lowercase the hostname before we can reject/preserve them.
    if not isinstance(server, str) or any(not 33 <= ord(c) <= 126 for c in server):
        return _Failure.INVALID_ENDPOINT
    match = _URL.fullmatch(server)
    if match is None:
        return _Failure.INVALID_ENDPOINT
    hostname, port_text, path = match.groups()
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(
            _LABEL.fullmatch(label) is None or label.lower().startswith("xn--")
            for label in labels
        )
        # Exclude dotted numeric/legacy hexadecimal IP spellings as well as
        # ordinary IPv4. Bracketed IPv6 cannot match the hostname grammar.
        or all(
            label.isdigit() or re.fullmatch(r"0[xX][0-9A-Fa-f]+", label)
            for label in labels
        )
    ):
        return _Failure.INVALID_ENDPOINT
    port = 443
    if port_text is not None:
        significant = port_text.lstrip("0")
        if not significant or len(significant) > 5:
            return _Failure.INVALID_ENDPOINT
        port = int(significant)
        if port > 65535:
            return _Failure.INVALID_ENDPOINT
    base_path = path or ""
    if _BASE_PATH.fullmatch(base_path) is None or any(
        part in {".", ".."} for part in base_path.split("/")
    ):
        return _Failure.INVALID_ENDPOINT
    authority = hostname if port_text is None else f"{hostname}:{port_text}"
    return hostname, port, authority, base_path


def _path(value: _Value | None, directory: Path) -> Path | None:
    if not isinstance(value, str) or not _text(value):
        return None
    # Pure lexical join: no resolve/stat/open, symlink following or expansion
    # of ~/$VARIABLE. Reference identity/content checks belong to later loading.
    return directory / value


def _authentication(
    user: _Value | None, directory: Path
) -> _BearerToken | _ClientCertificate | _Failure:
    if not isinstance(user, dict) or set(user) - {
        "token",
        "client-certificate",
        "client-key",
    }:
        return _Failure.INVALID_AUTH
    if "token" in user:
        token = user["token"]
        if len(user) != 1 or not isinstance(token, str) or not _text(token):
            return _Failure.INVALID_AUTH
        return _BearerToken(token=token)
    certificate = _path(user.get("client-certificate"), directory)
    key = _path(user.get("client-key"), directory)
    if certificate is None or key is None:
        return _Failure.INVALID_AUTH
    return _ClientCertificate(certificate_path=certificate, key_path=key)


def _preflight(
    document: _Document, *, context_name: str, kubeconfig_path: Path
) -> _Preflight | _Failure:
    """Select explicitly; caller must supply the original document's file path."""
    contexts = _index(document._data.get("contexts"))
    if isinstance(contexts, _Failure):
        return contexts
    clusters = _index(document._data.get("clusters"))
    if isinstance(clusters, _Failure):
        return clusters
    users = _index(document._data.get("users"))
    if isinstance(users, _Failure):
        return users
    if not _text(context_name):
        return _Failure.INVALID_CONTEXT
    if context_name not in contexts:
        return _Failure.CONTEXT_NOT_FOUND
    context = contexts[context_name].get("context")
    if not isinstance(context, dict) or set(context) - {"cluster", "user", "namespace"}:
        return _Failure.INVALID_CONTEXT
    cluster_name, user_name = context.get("cluster"), context.get("user")
    if (
        not isinstance(cluster_name, str)
        or not _text(cluster_name)
        or not isinstance(user_name, str)
        or not _text(user_name)
    ):
        return _Failure.INVALID_CONTEXT
    if cluster_name not in clusters:
        return _Failure.CLUSTER_NOT_FOUND
    if user_name not in users:
        return _Failure.USER_NOT_FOUND
    cluster = clusters[cluster_name].get("cluster")
    if not isinstance(cluster, dict) or set(cluster) != {
        "server",
        "certificate-authority",
    }:
        return _Failure.INVALID_CLUSTER
    endpoint = _endpoint(cluster["server"])
    if isinstance(endpoint, _Failure):
        return endpoint
    try:
        # Anchor relative kubeconfig locations without resolving symlinks or
        # consulting environment/default kubeconfig paths.
        directory = kubeconfig_path.absolute().parent
        ca = _path(cluster["certificate-authority"], directory)
        if ca is None:
            return _Failure.INVALID_CLUSTER
        auth = _authentication(users[user_name].get("user"), directory)
    except (OSError, ValueError):
        return _Failure.INVALID_INPUT
    if isinstance(auth, _Failure):
        return auth
    hostname, port, authority, base_path = endpoint
    return _Preflight(
        hostname=hostname,
        port=port,
        authority=authority,
        base_path=base_path,
        ca_path=ca,
        auth=auth,
    )
