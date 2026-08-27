"""Bounded, deterministic, read-only canonical OperatorSolution inventory."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.operator_solution_artifact_persistence import (
    _ID_RE,
    OPERATOR_SOLUTIONS_DIRNAME,
    load_persisted_operator_solution_artifact,
)
from shellforgeai.core.persistence_primitives import (
    _is_reparse_stat,
    _validate_data_dir,
)

MAX_OPERATOR_SOLUTION_INVENTORY_ENTRIES = 1024

InventoryStatus = Literal[
    "operator_solution_inventory_empty",
    "operator_solution_inventory_loaded",
    "operator_solution_inventory_loaded_with_anomalies",
    "operator_solution_inventory_blocked",
    "operator_solution_inventory_limit_exceeded",
]
AnomalyCategory = Literal[
    "unexpected_name",
    "symlink_or_reparse_entry",
    "non_directory_entry",
    "entry_not_inspectable",
    "entry_disappeared",
    "invalid_operator_solution_artifact",
]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class OperatorSolutionInventoryEntry(_FrozenModel):
    artifact_id: str
    solution_id: str
    platform_system: str
    target: str
    target_type: str
    total_bytes_read: int


class OperatorSolutionInventoryAnomaly(_FrozenModel):
    entry_name: str
    category: AnomalyCategory
    loader_status: str = ""
    reason: str


class OperatorSolutionInventoryResult(_FrozenModel):
    status: InventoryStatus
    inventory_complete: bool = False
    inventory_root_present: bool = False
    relative_inventory_root: str = OPERATOR_SOLUTIONS_DIRNAME
    max_inventory_entries: int = MAX_OPERATOR_SOLUTION_INVENTORY_ENTRIES
    scanned_entry_count: int = 0
    valid_entry_count: int = 0
    anomaly_count: int = 0
    entries: tuple[OperatorSolutionInventoryEntry, ...] = ()
    anomalies: tuple[OperatorSolutionInventoryAnomaly, ...] = ()
    reason: str = ""
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: bool = False
    inventory_performed: bool = False
    artifact_write_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    artifact_selected: Literal[False] = False
    approval_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def _result(
    status: InventoryStatus,
    *,
    complete: bool = False,
    root_present: bool = False,
    scanned: int = 0,
    entries: tuple[OperatorSolutionInventoryEntry, ...] = (),
    anomalies: tuple[OperatorSolutionInventoryAnomaly, ...] = (),
    reason: str = "",
    filesystem_accessed: bool = False,
    inventory_performed: bool = False,
) -> OperatorSolutionInventoryResult:
    return OperatorSolutionInventoryResult(
        status=status,
        inventory_complete=complete,
        inventory_root_present=root_present,
        scanned_entry_count=scanned,
        valid_entry_count=len(entries),
        anomaly_count=len(anomalies),
        entries=entries,
        anomalies=anomalies,
        reason=reason,
        filesystem_accessed=filesystem_accessed,
        inventory_performed=inventory_performed,
    )


def inventory_persisted_operator_solution_artifacts(
    data_dir: Path | str,
) -> OperatorSolutionInventoryResult:
    """Inventory valid direct children of the fixed owned persistence root."""
    checked = _validate_data_dir(data_dir)
    if checked.path is None:
        return _result(
            "operator_solution_inventory_blocked",
            reason="configured data root is unavailable or unsafe",
            filesystem_accessed=checked.filesystem_accessed,
        )
    root = checked.path / OPERATOR_SOLUTIONS_DIRNAME
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        return _result(
            "operator_solution_inventory_empty",
            complete=True,
            filesystem_accessed=True,
            inventory_performed=True,
        )
    except OSError:
        return _result(
            "operator_solution_inventory_blocked",
            reason="inventory root is not inspectable",
            filesystem_accessed=True,
        )
    try:
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse_stat(root_info, root):
            return _result(
                "operator_solution_inventory_blocked",
                root_present=True,
                reason="inventory root must be a real directory",
                filesystem_accessed=True,
            )
        names: list[str] = []
        with os.scandir(root) as iterator:
            for child in iterator:
                names.append(child.name)
                if len(names) > MAX_OPERATOR_SOLUTION_INVENTORY_ENTRIES:
                    return _result(
                        "operator_solution_inventory_limit_exceeded",
                        root_present=True,
                        scanned=len(names),
                        reason="fixed direct-child inventory bound exceeded",
                        filesystem_accessed=True,
                        inventory_performed=True,
                    )
    except OSError:
        return _result(
            "operator_solution_inventory_blocked",
            root_present=True,
            reason="inventory root is not inspectable",
            filesystem_accessed=True,
        )

    entries: list[OperatorSolutionInventoryEntry] = []
    anomalies: list[OperatorSolutionInventoryAnomaly] = []
    for name in sorted(names):
        path = root / name
        if not _ID_RE.fullmatch(name):
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category="unexpected_name",
                    reason="direct child name is not an exact canonical artifact ID",
                )
            )
            continue
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category="entry_disappeared",
                    reason="candidate disappeared during inventory",
                )
            )
            continue
        except OSError:
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category="entry_not_inspectable",
                    reason="candidate is not inspectable",
                )
            )
            continue
        if _is_reparse_stat(info, path):
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category="symlink_or_reparse_entry",
                    reason="candidate must not be a symlink or reparse point",
                )
            )
            continue
        if not stat.S_ISDIR(info.st_mode):
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category="non_directory_entry",
                    reason="candidate must be a real directory",
                )
            )
            continue
        loaded = load_persisted_operator_solution_artifact(checked.path, name)
        if loaded.status != "loaded" or loaded.solution is None:
            category: AnomalyCategory = (
                "entry_disappeared"
                if loaded.status == "not_found"
                else "invalid_operator_solution_artifact"
            )
            anomalies.append(
                OperatorSolutionInventoryAnomaly(
                    entry_name=name,
                    category=category,
                    loader_status=loaded.status,
                    reason="maintained exact-ID loader did not load this candidate",
                )
            )
            continue
        solution = loaded.solution
        entries.append(
            OperatorSolutionInventoryEntry(
                artifact_id=name,
                solution_id=solution.solution_id,
                platform_system=str(solution.platform_system),
                target=solution.target,
                target_type=str(solution.target_type),
                total_bytes_read=loaded.total_bytes_read,
            )
        )
    entry_values = tuple(sorted(entries, key=lambda item: item.artifact_id))
    anomaly_values = tuple(sorted(anomalies, key=lambda item: (item.entry_name, item.category)))
    if anomaly_values:
        status: InventoryStatus = "operator_solution_inventory_loaded_with_anomalies"
    elif entry_values:
        status = "operator_solution_inventory_loaded"
    else:
        status = "operator_solution_inventory_empty"
    return _result(
        status,
        complete=not anomaly_values,
        root_present=True,
        scanned=len(names),
        entries=entry_values,
        anomalies=anomaly_values,
        filesystem_accessed=True,
        inventory_performed=True,
    )
