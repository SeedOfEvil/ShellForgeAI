"""Shared read-only safety metadata for reporting surfaces.

This module centralizes standardized safety field names so narrowly guarded
command modules can reuse the metadata without spelling every field locally.
It constructs data only; it does not perform I/O, model calls, shell calls, or
runtime actions.
"""

from __future__ import annotations


def read_only_safety_metadata(*, model_call_performed: bool = False) -> dict[str, bool]:
    """Return the standard read-only/no-action safety metadata block."""

    return {
        "read_only": True,
        "mutation_performed": False,
        "model_call_performed": model_call_performed,
        "tools_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "docker_image_removed": False,
        "file_deleted": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "cloud_apply_merge_push": False,
        "model_called": model_call_performed,
    }
