"""Private trusted-file/document boundary; no selection or authentication.

The caller supplies a trusted local path. Regular-file checks do not establish
filesystem trust or hard cancellation of native file reads. Parsed contents
remain private to this adapter, are potentially secret, and must not be logged.
"""

import os
import stat
from enum import Enum
from pathlib import Path

_INPUT_POLICY_VERSION = "kubeconfig-input-v1"
_MAX_BYTES = 1024 * 1024
_MAX_DEPTH = 32

type _Value = str | list[_Value] | dict[str, _Value]


class _Failure(Enum):
    INVALID_INPUT = "invalid_local_input"
    TOO_LARGE = "input_too_large"
    INVALID_UTF8 = "invalid_utf8"
    MALFORMED_YAML = "malformed_yaml"
    UNSUPPORTED_YAML = "unsupported_yaml_feature"
    INVALID_STRUCTURE = "invalid_kubeconfig_structure"


class _Document:
    """Adapter-private holder, deliberately without a public mapping API."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, _Value]) -> None:
        self._data = data

    def __repr__(self) -> str:
        return "<kubeconfig document: redacted>"


class _Rejected(Exception):
    """Private parser control flow, consumed before returning to the caller."""


def _read_file(path: Path) -> bytes | _Failure:
    try:
        # Avoid opening known devices/FIFOs; the descriptor check is authoritative.
        # Trusted symlinks are followed. Host/filesystem compromise is out of scope.
        if not stat.S_ISREG(path.stat().st_mode):
            return _Failure.INVALID_INPUT
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                return _Failure.INVALID_INPUT
            if metadata.st_size > _MAX_BYTES:
                return _Failure.TOO_LARGE
            data = bytearray()
            while len(data) <= _MAX_BYTES:
                chunk = os.read(fd, _MAX_BYTES + 1 - len(data))
                if not chunk:
                    return bytes(data)
                data.extend(chunk)
            return _Failure.TOO_LARGE
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return _Failure.INVALID_INPUT


def _parse(text: str) -> _Document | _Failure:
    # PyYAML 6.0.3 ships no typing metadata. Keep the exception at this import;
    # our graph/return types are checked, without adding a stub dependency.
    import yaml  # type: ignore[import-untyped]

    # Only scanner/parser events are used, never YAML constructors or resolvers.
    # Scalars retain text (including yes, null, numbers and dates); interpreting
    # selected fields belongs to later preflight, not implicit YAML coercion.
    events = yaml.parse(text, Loader=yaml.BaseLoader)

    def read_value(event: object, depth: int) -> _Value:
        if isinstance(event, yaml.AliasEvent):
            raise _Rejected
        if getattr(event, "anchor", None) is not None:
            raise _Rejected
        if getattr(event, "tag", None) is not None:
            raise _Rejected
        if isinstance(event, yaml.ScalarEvent):
            value: str = event.value
            return value
        if depth > _MAX_DEPTH:
            raise _Rejected
        if isinstance(event, yaml.SequenceStartEvent):
            items: list[_Value] = []
            item = next(events)
            while not isinstance(item, yaml.SequenceEndEvent):
                items.append(read_value(item, depth + 1))
                item = next(events)
            return items
        if isinstance(event, yaml.MappingStartEvent):
            mapping: dict[str, _Value] = {}
            key_event = next(events)
            while not isinstance(key_event, yaml.MappingEndEvent):
                if not isinstance(key_event, yaml.ScalarEvent):
                    raise _Rejected
                key = read_value(key_event, depth + 1)
                if not isinstance(key, str) or key == "<<" or key in mapping:
                    raise _Rejected
                mapping[key] = read_value(next(events), depth + 1)
                key_event = next(events)
            return mapping
        raise _Rejected

    try:
        if not isinstance(next(events), yaml.StreamStartEvent):
            return _Failure.MALFORMED_YAML
        start = next(events)
        if not isinstance(start, yaml.DocumentStartEvent):
            return _Failure.MALFORMED_YAML
        if start.tags:
            return _Failure.UNSUPPORTED_YAML
        root = read_value(next(events), 1)
        if not isinstance(next(events), yaml.DocumentEndEvent):
            return _Failure.MALFORMED_YAML
        if not isinstance(next(events), yaml.StreamEndEvent):
            return _Failure.UNSUPPORTED_YAML
        if (
            not isinstance(root, dict)
            or root.get("apiVersion") != "v1"
            or root.get("kind") != "Config"
            or not all(
                isinstance(root.get(key), list)
                for key in ("clusters", "contexts", "users")
            )
        ):
            return _Failure.INVALID_STRUCTURE
        return _Document(root)
    except _Rejected:
        return _Failure.UNSUPPORTED_YAML
    # PyYAML also raises ValueError for out-of-range Unicode escape values.
    except (yaml.YAMLError, ValueError, StopIteration):
        return _Failure.MALFORMED_YAML
    finally:
        events.close()


def _load_document(path: Path) -> _Document | _Failure:
    """Read only the supplied path; return a closed failure, never source errors."""
    data = _read_file(path)
    if isinstance(data, _Failure):
        return data
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _Failure.INVALID_UTF8
    del data
    return _parse(text)
