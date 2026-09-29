"""Synthetic invariant tests; no collection, eligibility, or reporting logic."""

import ast
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, replace
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from openkube_optimizer.domain import models
from openkube_optimizer.domain.models import (
    UID,
    AllocationStatus,
    ConditionStatus,
    ContainerIdentity,
    ContainerInventory,
    ContainerLifecycle,
    ContainerState,
    DeploymentIdentity,
    DeploymentInventory,
    DurationNs,
    FieldState,
    MetricObservation,
    MonotonicNs,
    Ownership,
    OwnershipState,
    PodPhase,
    ResourceAllocation,
    SupportFacts,
    TemplateContainer,
    UtcNs,
)
from openkube_optimizer.domain.quantities import MAX_CPU_CORES, MAX_MEMORY_BYTES

ABSENT = FieldState.ABSENT
INVALID = FieldState.INVALID
UNAVAILABLE = FieldState.UNAVAILABLE
UID_CANARY = "synthetic-private-uid-canary"
NAME_CANARY = "synthetic-private-name-canary"
TIME = UtcNs(1_700_000_000_000_000_000)


def allocation() -> ResourceAllocation:
    return ResourceAllocation(
        cpu_request_cores=Decimal("0.25"),
        cpu_limit_cores=ABSENT,
        memory_request_bytes=128 * 2**20,
        memory_limit_bytes=ABSENT,
    )


def support() -> SupportFacts:
    return SupportFacts(
        pod_resources_present=False,
        init_container_count=0,
        ephemeral_container_count=0,
        restartable_init_present=False,
        overhead_present=False,
    )


def lifecycle() -> ContainerLifecycle:
    return ContainerLifecycle(
        pod_phase=PodPhase.RUNNING,
        pod_deleting=False,
        pod_ready=ConditionStatus.TRUE,
        pod_ready_transition_at=TIME,
        container_ready=True,
        container_started=True,
        container_state=ContainerState.RUNNING,
        restart_count=0,
        running_started_at=TIME,
    )


def inventory() -> ContainerInventory:
    return ContainerInventory(
        identity=ContainerIdentity(
            namespace=NAME_CANARY,
            pod_uid=UID(UID_CANARY),
            container_name=NAME_CANARY,
        ),
        pod_name=NAME_CANARY,
        pod_created_at=TIME,
        pod_resource_version="opaque-version",
        observed_at=TIME,
        ownership=Ownership(
            state=OwnershipState.RESOLVED,
            replicaset_uid=UID(UID_CANARY),
            deployment=DeploymentIdentity(namespace=NAME_CANARY, uid=UID(UID_CANARY)),
        ),
        pod_allocation=allocation(),
        lifecycle=lifecycle(),
        support=support(),
        allocation_status=AllocationStatus(
            allocated_cpu_cores=ABSENT,
            allocated_memory_bytes=ABSENT,
            reported_allocation=ABSENT,
            resize_status=ABSENT,
            resize_pending=ABSENT,
            resize_in_progress=ABSENT,
            resource_status_present=False,
        ),
    )


def deployment() -> DeploymentInventory:
    return DeploymentInventory(
        identity=DeploymentIdentity(namespace=NAME_CANARY, uid=UID(UID_CANARY)),
        name=NAME_CANARY,
        created_at=TIME,
        resource_version="opaque-version",
        observed_at=TIME,
        deleting=False,
        generation=1,
        observed_generation=1,
        desired_replicas=1,
        status_replicas=1,
        updated_replicas=1,
        available_replicas=1,
        unavailable_replicas=ABSENT,
        template_containers=(
            TemplateContainer(name=NAME_CANARY, allocation=allocation()),
        ),
        template_support=support(),
    )


def observation() -> MetricObservation:
    return MetricObservation(
        namespace=NAME_CANARY,
        pod_name=NAME_CANARY,
        container_name=NAME_CANARY,
        corroborating_pod_uid=UID(UID_CANARY),
        source="pod_metrics",
        source_timestamp=TIME,
        cpu_window=DurationNs(60_000_000_000),
        received_at=TIME,
        received_monotonic_at=MonotonicNs(100),
        cpu_cores=Decimal("0.1"),
        memory_bytes=128,
    )


def test_absence_zero_invalid_and_unavailable_are_distinct() -> None:
    values = (Decimal(0), ABSENT, INVALID, UNAVAILABLE)
    records = [replace(allocation(), cpu_request_cores=value) for value in values]
    assert len(set(records)) == 4
    for record, value in zip(records, values, strict=True):
        assert record.cpu_request_cores == value
    assert replace(allocation(), memory_request_bytes=0).memory_request_bytes == 0
    assert support().pod_resources_present is False
    assert (
        replace(support(), pod_resources_present=ABSENT).pod_resources_present is ABSENT
    )


@pytest.mark.parametrize(
    "value",
    [
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        Decimal("-1"),
        Decimal("1000000.1"),
        1,
        True,
        0.5,
        None,
    ],
)
def test_cpu_constructor_rejects_invalid_numbers_and_types(value: object) -> None:
    with pytest.raises(ValueError, match="^Invalid CPU quantity$"):
        replace(allocation(), cpu_request_cores=cast(Decimal, value))


@pytest.mark.parametrize(
    "value", [-1, MAX_MEMORY_BYTES + 1, True, Decimal(1), 1.0, None]
)
def test_memory_constructor_rejects_invalid_numbers_and_types(value: object) -> None:
    with pytest.raises(ValueError, match="^Invalid memory quantity$"):
        replace(allocation(), memory_limit_bytes=cast(int, value))


def test_normalized_upper_bounds_are_inclusive() -> None:
    result = replace(
        allocation(), cpu_limit_cores=MAX_CPU_CORES, memory_limit_bytes=MAX_MEMORY_BYTES
    )
    assert result.cpu_limit_cores == MAX_CPU_CORES
    assert result.memory_limit_bytes == MAX_MEMORY_BYTES


def test_name_reuse_changes_identity_but_inventory_updates_do_not() -> None:
    first = inventory()
    replacement = replace(
        first, identity=replace(first.identity, pod_uid=UID("replacement"))
    )
    changed = replace(
        first,
        pod_resource_version="later",
        lifecycle=replace(
            first.lifecycle, restart_count=1, running_started_at=UtcNs(int(TIME) + 1)
        ),
    )
    assert replacement.pod_name == first.pod_name
    assert replacement.identity != first.identity
    assert changed.identity == first.identity
    assert changed.lifecycle != first.lifecycle
    assert len({first.identity, replacement.identity, changed.identity}) == 2
    dep = deployment()
    assert replace(dep, resource_version="later").identity == dep.identity
    assert (
        replace(dep, identity=replace(dep.identity, uid=UID("replacement"))).identity
        != dep.identity
    )


@pytest.mark.parametrize(
    "state", [OwnershipState.UNSUPPORTED, OwnershipState.UNRESOLVED]
)
def test_unverified_owner_cannot_claim_deployment(state: OwnershipState) -> None:
    with pytest.raises(ValueError, match="^Unverified ownership"):
        Ownership(state=state, replicaset_uid=None, deployment=deployment().identity)
    assert Ownership(state=state, replicaset_uid=None, deployment=None).state is state


def test_resolved_owner_requires_both_identities_and_same_namespace() -> None:
    for rs, dep in ((None, None), (UID("rs"), None), (None, deployment().identity)):
        with pytest.raises(ValueError, match="^Resolved ownership"):
            Ownership(state=OwnershipState.RESOLVED, replicaset_uid=rs, deployment=dep)
    foreign_owner = replace(
        inventory().ownership,
        deployment=DeploymentIdentity(namespace="elsewhere", uid=UID("dep")),
    )
    with pytest.raises(ValueError, match="^Ownership namespace mismatch$"):
        replace(inventory(), ownership=foreign_owner)


@pytest.mark.parametrize("started", [True, False, ABSENT, INVALID, UNAVAILABLE])
def test_lifecycle_preserves_startup_uncertainty(started: bool | FieldState) -> None:
    facts = replace(
        lifecycle(),
        container_started=started,
        pod_ready=ConditionStatus.UNKNOWN,
        running_started_at=UNAVAILABLE,
    )
    assert facts.container_started is started
    assert facts.pod_ready is ConditionStatus.UNKNOWN
    assert facts.running_started_at is UNAVAILABLE


def test_lifecycle_rejects_wrong_types_without_inventing_health() -> None:
    with pytest.raises(ValueError):
        replace(lifecycle(), restart_count=True)
    with pytest.raises(ValueError):
        replace(lifecycle(), restart_count=-1)
    with pytest.raises(ValueError):
        replace(lifecycle(), container_ready=cast(bool, 1))
    with pytest.raises(ValueError):
        replace(lifecycle(), pod_phase=cast(PodPhase, "Running"))


def test_metric_resource_validity_is_independent() -> None:
    memory_only = replace(observation(), cpu_cores=INVALID, cpu_window=INVALID)
    cpu_only = replace(
        observation(), memory_bytes=UNAVAILABLE, corroborating_pod_uid=ABSENT
    )
    assert memory_only.memory_bytes == 128
    assert memory_only.cpu_window is INVALID
    assert cpu_only.cpu_cores == Decimal("0.1")
    assert cpu_only.corroborating_pod_uid is ABSENT
    # A representable window is not a claim that it passes the future 120s gate.
    assert replace(observation(), cpu_window=DurationNs(0)).cpu_window == 0


def test_time_units_reject_wrong_runtime_types_and_invalid_values() -> None:
    for value in (True, 1.5, "timestamp", 253402300800000000000):
        with pytest.raises(ValueError):
            replace(observation(), received_at=cast(UtcNs, value))
    with pytest.raises(ValueError):
        replace(observation(), cpu_window=DurationNs(-1))
    with pytest.raises(ValueError):
        replace(observation(), received_monotonic_at=cast(MonotonicNs, 1.5))


def test_templates_require_unique_names_and_immutable_typed_members() -> None:
    container = TemplateContainer(name=NAME_CANARY, allocation=allocation())
    with pytest.raises(ValueError, match="^Duplicate template container$"):
        replace(deployment(), template_containers=(container, container))
    with pytest.raises(ValueError, match="^Invalid record type$"):
        replace(
            deployment(),
            template_containers=cast(tuple[TemplateContainer, ...], [container]),
        )
    with pytest.raises(ValueError, match="^Invalid record type$"):
        replace(deployment(), template_containers=(cast(TemplateContainer, object()),))
    assert deployment().unavailable_replicas is ABSENT
    assert replace(deployment(), available_replicas=0).available_replicas == 0


def test_no_sdk_or_arbitrary_mapping_can_replace_nested_records() -> None:
    with pytest.raises(ValueError, match="^Invalid record type$"):
        replace(
            inventory(), pod_allocation=cast(ResourceAllocation, {"secret": "canary"})
        )
    with pytest.raises(ValueError, match="^Invalid record type$"):
        replace(
            inventory().allocation_status,
            reported_allocation=cast(ResourceAllocation, object()),
        )


def test_records_are_frozen_slotted_and_do_not_print_sensitive_fields() -> None:
    sample = inventory()
    records = (
        sample.identity,
        deployment().identity,
        sample.ownership,
        sample.pod_allocation,
        sample.support,
        sample.lifecycle,
        sample.allocation_status,
        sample,
        TemplateContainer(name=NAME_CANARY, allocation=allocation()),
        deployment(),
        observation(),
    )
    for record in records:
        assert not hasattr(record, "__dict__")
        assert UID_CANARY not in repr(record)
        assert NAME_CANARY not in repr(record)
        with pytest.raises(FrozenInstanceError):
            setattr(record, fields(record)[0].name, None)
        with pytest.raises((AttributeError, TypeError)):
            setattr(record, "raw_object", object())


@pytest.mark.parametrize(
    "value", ["", "bad..name", "Uppercase", "x" * 254, NAME_CANARY + "/"]
)
def test_invalid_names_fail_without_echo(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        replace(inventory(), pod_name=value)
    assert NAME_CANARY not in str(caught.value)
    assert UID_CANARY not in str(caught.value)


def test_identifier_bytes_and_invalid_unicode_are_bounded_safely() -> None:
    identity = inventory().identity
    assert replace(identity, pod_uid=UID("é" * 512)).pod_uid == "é" * 512
    for value in (UID_CANARY + "x" * 1024, "é" * 513, "\ud800" + UID_CANARY):
        with pytest.raises(ValueError) as caught:
            replace(identity, pod_uid=UID(value))
        assert UID_CANARY not in str(caught.value)
        assert UID_CANARY not in repr(caught.value)
        assert caught.value.__suppress_context__ or caught.value.__context__ is None


def test_duplicate_template_error_does_not_print_name() -> None:
    template = TemplateContainer(name=NAME_CANARY, allocation=allocation())
    with pytest.raises(ValueError) as caught:
        replace(deployment(), template_containers=(template, template))
    assert NAME_CANARY not in str(caught.value)


def test_domain_has_only_standard_library_and_domain_dependencies() -> None:
    domain_path = Path(models.__file__).parent
    for path in domain_path.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert module.split(".")[
                    0
                ] in sys.stdlib_module_names or module.startswith(
                    "openkube_optimizer.domain."
                )
    script = """
import sys
class DomainOnly:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in sys.stdlib_module_names:
            return None
        if fullname == 'openkube_optimizer' or fullname == 'openkube_optimizer.domain' or fullname.startswith('openkube_optimizer.domain.'):
            return None
        raise ImportError('Non-domain dependency blocked')
sys.meta_path.insert(0, DomainOnly())
import openkube_optimizer.domain.models
import openkube_optimizer.domain.quantities
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
