"""Deterministic persistence for validated canonical OperatorSolution objects.

This filesystem boundary does not produce solutions, authorize their use, or
execute their advisory procedure.  It persists only the two PR358 canonical
representations beneath one fixed subtree.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_approval_persistence import (
    PERSISTED_DIRECTORY_MODE,
    PERSISTED_FILE_MODE,
    _check_child_containment,
    _fsync_directory,
    _is_reparse_stat,
    _is_symlink_or_reparse,
    _path_exists_without_following,
    _read_bounded,
    _validate_data_dir,
    atomic_no_replace_approval_directory_publish,
)
from shellforgeai.core.operator_solution import (
    OperatorSolution,
    canonical_operator_solution_json,
    render_operator_solution_markdown,
    validate_operator_solution,
)

OPERATOR_SOLUTIONS_DIRNAME = "operator_solutions"
OPERATOR_SOLUTION_JSON_FILENAME = "operator-solution.json"
OPERATOR_SOLUTION_MARKDOWN_FILENAME = "operator-solution.md"
OPERATOR_SOLUTION_ARTIFACT_ID_PREFIX = "osol_"
MAX_OPERATOR_SOLUTION_FILE_BYTES = 1_048_576
_ID_RE = re.compile(r"^osol_[0-9a-f]{64}$")
_FILENAMES = sorted((OPERATOR_SOLUTION_JSON_FILENAME, OPERATOR_SOLUTION_MARKDOWN_FILENAME))


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PreparedOperatorSolutionArtifact(_FrozenModel):
    artifact_id: str
    content_sha256: str
    solution: OperatorSolution
    canonical_json: str
    canonical_markdown: str


class OperatorSolutionPublicationResult(_FrozenModel):
    status: Literal["published", "already_present", "conflict", "publication_blocked"]
    artifact_id: str = ""
    artifact: PreparedOperatorSolutionArtifact | None = None
    errors: tuple[str, ...] = ()
    atomic_publish_outcome: str = "not_attempted"
    existing_identical_no_op: bool = False


class OperatorSolutionLoadResult(_FrozenModel):
    status: Literal["loaded", "not_found", "invalid_id", "invalid", "load_blocked"]
    artifact_id: str = ""
    solution: OperatorSolution | None = None
    errors: tuple[str, ...] = ()
    total_bytes_read: int = 0
    filesystem_accessed: bool = False


def prepare_operator_solution_artifact(
    solution: OperatorSolution,
) -> PreparedOperatorSolutionArtifact:
    """Build the exact, non-circular durable representation in memory."""
    value = OperatorSolution.model_validate(solution)
    validation = validate_operator_solution(value)
    if not validation.valid:  # defensive: model construction currently proves this
        raise ValueError("OperatorSolution validation failed")
    canonical_json = canonical_operator_solution_json(value)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return PreparedOperatorSolutionArtifact(
        artifact_id=f"{OPERATOR_SOLUTION_ARTIFACT_ID_PREFIX}{digest}",
        content_sha256=digest,
        solution=value,
        canonical_json=canonical_json,
        canonical_markdown=render_operator_solution_markdown(value),
    )


def _result(status: str, **values: Any) -> OperatorSolutionLoadResult:
    if "errors" in values:
        values["errors"] = tuple(sorted(set(values["errors"])))
    return OperatorSolutionLoadResult(status=status, **values)  # type: ignore[arg-type]


def load_persisted_operator_solution_artifact(
    data_dir: Path | str, artifact_id: str
) -> OperatorSolutionLoadResult:
    """Load and completely revalidate one exact persisted content identity."""
    if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
        return _result(
            "invalid_id",
            errors=["artifact ID must be osol_ plus 64 lowercase hexadecimal characters"],
        )
    checked = _validate_data_dir(data_dir)
    if checked.path is None:
        return _result(
            "load_blocked",
            artifact_id=artifact_id,
            errors=list(checked.errors),
            filesystem_accessed=checked.filesystem_accessed,
        )
    root = checked.path / OPERATOR_SOLUTIONS_DIRNAME
    if not _path_exists_without_following(root):
        return _result("not_found", artifact_id=artifact_id, filesystem_accessed=True)
    if _is_symlink_or_reparse(root) or not stat.S_ISDIR(os.lstat(root).st_mode):
        return _result(
            "load_blocked",
            artifact_id=artifact_id,
            errors=["persistence root must be a real directory"],
            filesystem_accessed=True,
        )
    directory = root / artifact_id
    if _check_child_containment(root, directory, "operator-solution artifact directory"):
        return _result(
            "load_blocked",
            artifact_id=artifact_id,
            errors=["unsafe artifact directory"],
            filesystem_accessed=True,
        )
    if not _path_exists_without_following(directory):
        return _result("not_found", artifact_id=artifact_id, filesystem_accessed=True)
    if _is_symlink_or_reparse(directory) or not stat.S_ISDIR(os.lstat(directory).st_mode):
        return _result(
            "invalid",
            artifact_id=artifact_id,
            errors=["artifact directory must be a real directory"],
            filesystem_accessed=True,
        )
    try:
        if sorted(entry.name for entry in os.scandir(directory)) != _FILENAMES:
            raise ValueError("artifact directory must contain exactly the two fixed files")
        raw: dict[str, bytes] = {}
        for filename in _FILENAMES:
            path = directory / filename
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or _is_reparse_stat(info, path):
                raise ValueError(f"{filename} must be a real regular file")
            if info.st_size > MAX_OPERATOR_SOLUTION_FILE_BYTES:
                raise ValueError(f"{filename} exceeds the bounded size limit")
            raw[filename] = _read_bounded(path, info.st_size)
        json_text = raw[OPERATOR_SOLUTION_JSON_FILENAME].decode("utf-8")
        markdown_text = raw[OPERATOR_SOLUTION_MARKDOWN_FILENAME].decode("utf-8")
        solution = OperatorSolution.model_validate_json(json_text)
        prepared = prepare_operator_solution_artifact(solution)
        errors = []
        if json_text != prepared.canonical_json:
            errors.append("persisted JSON is not the exact canonical JSON")
        if markdown_text != prepared.canonical_markdown:
            errors.append("persisted Markdown is not the exact canonical Markdown")
        if prepared.artifact_id != artifact_id:
            errors.append("persisted content identity does not match the requested artifact ID")
        if errors:
            raise ValueError("; ".join(errors))
    except (OSError, UnicodeError, ValueError) as exc:
        return _result(
            "invalid", artifact_id=artifact_id, errors=[str(exc)], filesystem_accessed=True
        )
    total = sum(len(value) for value in raw.values())
    return _result(
        "loaded",
        artifact_id=artifact_id,
        solution=solution,
        total_bytes_read=total,
        filesystem_accessed=True,
    )


def _cleanup(temporary: Path, paths: tuple[Path, ...]) -> None:
    """Remove only this invocation's unpublished files and directory."""
    for path in paths:
        with suppress(FileNotFoundError):
            os.unlink(path)
    with suppress(FileNotFoundError):
        os.rmdir(temporary)


def publish_operator_solution_artifact(
    solution: OperatorSolution, *, data_dir: Path | str
) -> OperatorSolutionPublicationResult:
    """Privately prepare, validate, and atomically publish one solution."""
    try:
        artifact = prepare_operator_solution_artifact(solution)
    except (TypeError, ValueError) as exc:
        return OperatorSolutionPublicationResult(status="publication_blocked", errors=(str(exc),))
    checked = _validate_data_dir(data_dir)
    if checked.path is None:
        return OperatorSolutionPublicationResult(
            status="publication_blocked",
            artifact_id=artifact.artifact_id,
            artifact=artifact,
            errors=checked.errors,
        )
    root = checked.path / OPERATOR_SOLUTIONS_DIRNAME
    final = root / artifact.artifact_id
    temporary: Path | None = None
    paths: tuple[Path, ...] = ()
    try:
        if not _path_exists_without_following(root):
            os.mkdir(root, PERSISTED_DIRECTORY_MODE)
        if _is_symlink_or_reparse(root) or not stat.S_ISDIR(os.lstat(root).st_mode):
            raise OSError("persistence root must be a real directory")
        if _path_exists_without_following(final):
            loaded = load_persisted_operator_solution_artifact(checked.path, artifact.artifact_id)
            if loaded.status == "loaded" and loaded.solution == artifact.solution:
                return OperatorSolutionPublicationResult(
                    status="already_present",
                    artifact_id=artifact.artifact_id,
                    artifact=artifact,
                    existing_identical_no_op=True,
                )
            return OperatorSolutionPublicationResult(
                status="conflict",
                artifact_id=artifact.artifact_id,
                artifact=artifact,
                errors=("destination is not the same valid canonical artifact",),
            )
        temporary = root / f".pending-{secrets.token_hex(8)}"
        os.mkdir(temporary, PERSISTED_DIRECTORY_MODE)
        json_path = temporary / OPERATOR_SOLUTION_JSON_FILENAME
        markdown_path = temporary / OPERATOR_SOLUTION_MARKDOWN_FILENAME
        paths = (json_path, markdown_path)
        for path, payload in (
            (json_path, artifact.canonical_json),
            (markdown_path, artifact.canonical_markdown),
        ):
            fd = os.open(
                path,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                PERSISTED_FILE_MODE,
            )
            try:
                data = payload.encode("utf-8")
                offset = 0
                while offset < len(data):
                    offset += os.write(fd, data[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
        # Validate the private representation with the same exact checks used on load.
        for path, expected in (
            (json_path, artifact.canonical_json.encode()),
            (markdown_path, artifact.canonical_markdown.encode()),
        ):
            if _read_bounded(path, len(expected)) != expected:
                raise OSError("private prepared content differs")
        OperatorSolution.model_validate_json(artifact.canonical_json)
        _fsync_directory(temporary)
        outcome = atomic_no_replace_approval_directory_publish(temporary, final)
        if outcome.outcome == "destination_exists":
            _cleanup(temporary, paths)
            loaded = load_persisted_operator_solution_artifact(checked.path, artifact.artifact_id)
            if loaded.status == "loaded" and loaded.solution == artifact.solution:
                return OperatorSolutionPublicationResult(
                    status="already_present",
                    artifact_id=artifact.artifact_id,
                    artifact=artifact,
                    atomic_publish_outcome=outcome.outcome,
                    existing_identical_no_op=True,
                )
            return OperatorSolutionPublicationResult(
                status="conflict",
                artifact_id=artifact.artifact_id,
                artifact=artifact,
                atomic_publish_outcome=outcome.outcome,
                errors=("atomic publication found a conflicting destination",),
            )
        if outcome.outcome != "published":
            _cleanup(temporary, paths)
            return OperatorSolutionPublicationResult(
                status="publication_blocked",
                artifact_id=artifact.artifact_id,
                artifact=artifact,
                atomic_publish_outcome=outcome.outcome,
                errors=(f"atomic no-replace publication failed: {outcome.outcome}",),
            )
        _fsync_directory(root)
        loaded = load_persisted_operator_solution_artifact(checked.path, artifact.artifact_id)
        if loaded.status != "loaded":
            return OperatorSolutionPublicationResult(
                status="publication_blocked",
                artifact_id=artifact.artifact_id,
                artifact=artifact,
                atomic_publish_outcome=outcome.outcome,
                errors=loaded.errors,
            )
        return OperatorSolutionPublicationResult(
            status="published",
            artifact_id=artifact.artifact_id,
            artifact=artifact,
            atomic_publish_outcome=outcome.outcome,
        )
    except OSError as exc:
        if temporary is not None and _path_exists_without_following(temporary):
            with suppress(OSError):
                _cleanup(temporary, paths)
        return OperatorSolutionPublicationResult(
            status="publication_blocked",
            artifact_id=artifact.artifact_id,
            artifact=artifact,
            errors=(str(exc),),
        )
