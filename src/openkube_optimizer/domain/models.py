"""Closed in-memory facts, independent of SDKs, analysis, and reporting.

UIDs and names are deliberately omitted from automatic representations. These
records must never be passed to generic serializers or logged. Frozen records
and annotations are not a security boundary; future adapters must project the
documented allowlist and future reporting must construct separate safe records.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Final, Literal, NewType

from openkube_optimizer.domain.quantities import validate_cpu, validate_memory

UID = NewType("UID", str)
UtcNs = NewType("UtcNs", int)
MonotonicNs = NewType("MonotonicNs", int)
DurationNs = NewType("DurationNs", int)

DATA_POLICY_VERSION: Final = "data-v1"
EVIDENCE_POLICY_VERSION: Final = "evidence-v1"
RULE_VERSIONS: Final = (
    ("REQUEST_MISSING", "1.0.0"),
    ("MEMORY_LIMIT_MISSING", "1.0.0"),
    ("CPU_REQUEST_OVERPROVISIONING_CANDIDATE", "1.0.0"),
    ("MEMORY_REQUEST_OVERPROVISIONING_CANDIDATE", "1.0.0"),
    ("REQUEST_BELOW_OBSERVED_USAGE", "1.0.0"),
    ("MEMORY_LIMIT_HEADROOM_LOW", "1.0.0"),
)
MAX_IDENTIFIER_BYTES = 1024
_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_SUBDOMAIN = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?")


class FieldState(Enum):
    ABSENT = "absent"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


type Field[T] = T | FieldState


class OwnershipState(Enum):
    RESOLVED = "resolved"
    UNSUPPORTED = "unsupported"
    UNRESOLVED = "unresolved"


class PodPhase(Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    UNKNOWN = "Unknown"


class ConditionStatus(Enum):
    TRUE = "True"
    FALSE = "False"
    UNKNOWN = "Unknown"


class ContainerState(Enum):
    RUNNING = "running"
    WAITING = "waiting"
    TERMINATED = "terminated"


class ResizeStatus(Enum):
    IN_PROGRESS = "InProgress"
    DEFERRED = "Deferred"
    INFEASIBLE = "Infeasible"


def _text(value: object) -> None:
    if type(value) is not str or not value or len(value) > MAX_IDENTIFIER_BYTES:
        raise ValueError("Invalid identifier")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Invalid identifier") from None
    if size > MAX_IDENTIFIER_BYTES:
        raise ValueError("Invalid identifier")


def _label(value: object) -> None:
    _text(value)
    if not isinstance(value, str) or len(value) > 63 or not _LABEL.fullmatch(value):
        raise ValueError("Invalid name")


def _name(value: object) -> None:
    _text(value)
    if (
        not isinstance(value, str)
        or len(value) > 253
        or not _SUBDOMAIN.fullmatch(value)
        or any(not _LABEL.fullmatch(part) for part in value.split("."))
    ):
        raise ValueError("Invalid name")


def _integer(value: object) -> None:
    if type(value) is not int:
        raise ValueError("Invalid integer")


def _count(value: object) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("Invalid nonnegative integer")


def _utc(value: object) -> None:
    # UTC years 1 through 9999; no float conversion or timestamp parser here.
    if (
        type(value) is not int
        or not -62135596800000000000 <= value < 253402300800000000000
    ):
        raise ValueError("Invalid UTC timestamp")


def _bool(value: object) -> None:
    if type(value) is not bool:
        raise ValueError("Invalid boolean")


def _field(value: object, validate: Callable[[object], None]) -> None:
    if type(value) is not FieldState:
        validate(value)


def _record(value: object, expected: type[object]) -> None:
    if type(value) is not expected:
        raise ValueError("Invalid record type")


def _enum_field(value: object, expected: type[Enum]) -> None:
    if type(value) is not FieldState:
        _record(value, expected)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ContainerIdentity:
    namespace: str
    pod_uid: UID
    container_name: str

    def __post_init__(self) -> None:
        _label(self.namespace)
        _text(self.pod_uid)
        _label(self.container_name)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class DeploymentIdentity:
    namespace: str
    uid: UID

    def __post_init__(self) -> None:
        _label(self.namespace)
        _text(self.uid)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class Ownership:
    state: OwnershipState
    replicaset_uid: UID | None
    deployment: DeploymentIdentity | None

    def __post_init__(self) -> None:
        _record(self.state, OwnershipState)
        if self.replicaset_uid is not None:
            _text(self.replicaset_uid)
        if self.deployment is not None:
            _record(self.deployment, DeploymentIdentity)
        if self.state is OwnershipState.RESOLVED:
            if self.replicaset_uid is None or self.deployment is None:
                raise ValueError("Resolved ownership requires both identities")
        elif self.deployment is not None:
            raise ValueError("Unverified ownership cannot claim a Deployment")


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ResourceAllocation:
    cpu_request_cores: Field[Decimal]
    cpu_limit_cores: Field[Decimal]
    memory_request_bytes: Field[int]
    memory_limit_bytes: Field[int]

    def __post_init__(self) -> None:
        _field(self.cpu_request_cores, validate_cpu)
        _field(self.cpu_limit_cores, validate_cpu)
        _field(self.memory_request_bytes, validate_memory)
        _field(self.memory_limit_bytes, validate_memory)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class SupportFacts:
    pod_resources_present: Field[bool]
    init_container_count: Field[int]
    ephemeral_container_count: Field[int]
    restartable_init_present: Field[bool]
    overhead_present: Field[bool]

    def __post_init__(self) -> None:
        _field(self.pod_resources_present, _bool)
        _field(self.init_container_count, _count)
        _field(self.ephemeral_container_count, _count)
        _field(self.restartable_init_present, _bool)
        _field(self.overhead_present, _bool)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ContainerLifecycle:
    pod_phase: Field[PodPhase]
    pod_deleting: Field[bool]
    pod_ready: Field[ConditionStatus]
    pod_ready_transition_at: Field[UtcNs]
    container_ready: Field[bool]
    container_started: Field[bool]
    container_state: Field[ContainerState]
    restart_count: Field[int]
    running_started_at: Field[UtcNs]

    def __post_init__(self) -> None:
        _enum_field(self.pod_phase, PodPhase)
        _field(self.pod_deleting, _bool)
        _enum_field(self.pod_ready, ConditionStatus)
        _field(self.pod_ready_transition_at, _utc)
        _field(self.container_ready, _bool)
        _field(self.container_started, _bool)
        _enum_field(self.container_state, ContainerState)
        _field(self.restart_count, _count)
        _field(self.running_started_at, _utc)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class AllocationStatus:
    allocated_cpu_cores: Field[Decimal]
    allocated_memory_bytes: Field[int]
    reported_allocation: Field[ResourceAllocation]
    resize_status: Field[ResizeStatus]
    resize_pending: Field[ConditionStatus]
    resize_in_progress: Field[ConditionStatus]
    resource_status_present: Field[bool]

    def __post_init__(self) -> None:
        _field(self.allocated_cpu_cores, validate_cpu)
        _field(self.allocated_memory_bytes, validate_memory)
        if type(self.reported_allocation) is not FieldState:
            _record(self.reported_allocation, ResourceAllocation)
        _enum_field(self.resize_status, ResizeStatus)
        _enum_field(self.resize_pending, ConditionStatus)
        _enum_field(self.resize_in_progress, ConditionStatus)
        _field(self.resource_status_present, _bool)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ContainerInventory:
    identity: ContainerIdentity
    pod_name: str
    pod_created_at: UtcNs
    pod_resource_version: Field[str]
    observed_at: UtcNs
    ownership: Ownership
    pod_allocation: ResourceAllocation
    lifecycle: ContainerLifecycle
    support: SupportFacts
    allocation_status: AllocationStatus

    def __post_init__(self) -> None:
        _record(self.identity, ContainerIdentity)
        _name(self.pod_name)
        _utc(self.pod_created_at)
        _field(self.pod_resource_version, _text)
        _utc(self.observed_at)
        _record(self.ownership, Ownership)
        _record(self.pod_allocation, ResourceAllocation)
        _record(self.lifecycle, ContainerLifecycle)
        _record(self.support, SupportFacts)
        _record(self.allocation_status, AllocationStatus)
        if (
            self.ownership.deployment is not None
            and self.ownership.deployment.namespace != self.identity.namespace
        ):
            raise ValueError("Ownership namespace mismatch")


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class TemplateContainer:
    name: str
    allocation: ResourceAllocation

    def __post_init__(self) -> None:
        _label(self.name)
        _record(self.allocation, ResourceAllocation)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class DeploymentInventory:
    identity: DeploymentIdentity
    name: str
    created_at: UtcNs
    resource_version: Field[str]
    observed_at: UtcNs
    deleting: Field[bool]
    generation: Field[int]
    observed_generation: Field[int]
    desired_replicas: Field[int]
    status_replicas: Field[int]
    updated_replicas: Field[int]
    available_replicas: Field[int]
    unavailable_replicas: Field[int]
    template_containers: Field[tuple[TemplateContainer, ...]]
    template_support: SupportFacts

    def __post_init__(self) -> None:
        _record(self.identity, DeploymentIdentity)
        _name(self.name)
        _utc(self.created_at)
        _field(self.resource_version, _text)
        _utc(self.observed_at)
        _field(self.deleting, _bool)
        for value in (
            self.generation,
            self.observed_generation,
            self.desired_replicas,
            self.status_replicas,
            self.updated_replicas,
            self.available_replicas,
            self.unavailable_replicas,
        ):
            _field(value, _count)
        if not isinstance(self.template_containers, FieldState):
            _record(self.template_containers, tuple)
            names: set[str] = set()
            for container in self.template_containers:
                _record(container, TemplateContainer)
                if container.name in names:
                    raise ValueError("Duplicate template container")
                names.add(container.name)
        _record(self.template_support, SupportFacts)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class MetricObservation:
    namespace: str
    pod_name: str
    container_name: str
    corroborating_pod_uid: Field[UID]
    source: Literal["pod_metrics"]
    source_timestamp: Field[UtcNs]
    cpu_window: Field[DurationNs]
    received_at: UtcNs
    received_monotonic_at: MonotonicNs
    cpu_cores: Field[Decimal]
    memory_bytes: Field[int]

    def __post_init__(self) -> None:
        _label(self.namespace)
        _name(self.pod_name)
        _label(self.container_name)
        _field(self.corroborating_pod_uid, _text)
        if type(self.source) is not str or self.source != "pod_metrics":
            raise ValueError("Invalid metric source")
        _field(self.source_timestamp, _utc)
        _field(self.cpu_window, _count)
        _utc(self.received_at)
        _integer(self.received_monotonic_at)
        _field(self.cpu_cores, validate_cpu)
        _field(self.memory_bytes, validate_memory)
