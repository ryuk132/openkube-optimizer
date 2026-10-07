"""Private local TLS construction; no sockets, handshake or authentication.

Borrow the M3.3A owner's inspected descriptors. Files must remain stable during
OpenSSL's reread; pinning does not prevent in-place mutation. Local native setup
is synchronous, not hard-cancellable, and reference release is not zeroization.
"""

import base64
import re
import ssl
from collections.abc import Iterator
from typing import Never, SupportsIndex

from openkube_optimizer.collection.credentials import _CredentialMaterial
from openkube_optimizer.collection.kubeconfig import _Failure

_TLS_MATERIAL_POLICY_VERSION = "tls-material-v1"
_ASCII_WHITESPACE = " \t\r\n\v\f"
_CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n"
    r"([A-Za-z0-9+/= \t\r\n\v\f]+)"
    r"\r?\n-----END CERTIFICATE-----"
)


class _TlsContext:
    """Collection-private context only; never domain/report/serialization data."""

    __slots__ = ("_context",)
    _context: ssl.SSLContext

    def __init__(self, context: ssl.SSLContext) -> None:
        object.__setattr__(self, "_context", context)

    def __setattr__(self, name: str, value: object) -> Never:
        raise AttributeError("Immutable TLS holder")

    def __delattr__(self, name: str) -> Never:
        raise AttributeError("Immutable TLS holder")

    def __repr__(self) -> str:
        return "<TLS context: redacted>"

    def __getstate__(self) -> Never:
        raise TypeError("TLS contexts cannot be serialized")

    def __reduce__(self) -> Never:
        self.__getstate__()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        self.__getstate__()


class _PasswordRequired(Exception):
    """Internal callback signal; no password or OpenSSL diagnostic is retained."""


def _reject_password() -> Never:
    raise _PasswordRequired


def _ca_blocks(snapshot: bytes) -> Iterator[str]:
    # Framing/Base64 only. OpenSSL owns all DER/X.509 interpretation.
    text = snapshot.decode("ascii")
    offset = 0
    found = False
    while True:
        while offset < len(text) and text[offset] in _ASCII_WHITESPACE:
            offset += 1
        if offset == len(text):
            if not found:
                raise ValueError("Invalid CA framing")
            return
        match = _CERTIFICATE.match(text, offset)
        if match is None:
            raise ValueError("Invalid CA framing")
        encoded = "".join(match[1].split())
        decoded = base64.b64decode(encoded, validate=True)
        if not decoded or base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("Invalid CA Base64")
        del decoded, encoded
        found = True
        offset = match.end()
        if offset < len(text) and text[offset] not in _ASCII_WHITESPACE:
            raise ValueError("Invalid CA framing")
        yield match[0]


def _build_tls_context(material: _CredentialMaterial) -> _TlsContext | _Failure:
    """Construct with selected trust only; caller retains credential ownership.

    Expected material/native setup errors become fixed outcomes. Programming
    errors and control-flow exceptions propagate; no raw exception is returned.
    """
    if material._closed:
        return _Failure.TLS_CONTEXT_CONSTRUCTION_FAILED
    certificate, key = material._certificate_fd, material._key_fd
    if (certificate is None) != (key is None):
        raise ValueError("Incomplete credential descriptor pair")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    except (OSError, ValueError):
        return _Failure.TLS_CONTEXT_CONSTRUCTION_FAILED
    try:
        for block in _ca_blocks(material._ca_snapshot):
            der = ssl.PEM_cert_to_DER_cert(block)
            context.load_verify_locations(cadata=der)
            del der, block
    except (OSError, ValueError):
        return _Failure.INVALID_CA_MATERIAL
    if certificate is not None:
        try:
            context.load_cert_chain(
                certfile=f"/proc/self/fd/{certificate}",
                keyfile=f"/proc/self/fd/{key}",
                password=_reject_password,
            )
        except _PasswordRequired:
            return _Failure.UNSUPPORTED_ENCRYPTED_PRIVATE_KEY
        except (OSError, ValueError):
            return _Failure.INVALID_CLIENT_IDENTITY
    return _TlsContext(context)
