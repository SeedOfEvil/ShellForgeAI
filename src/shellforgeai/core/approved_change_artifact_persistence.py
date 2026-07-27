"""Governed atomic publisher and read-only loader for PR316 bundles (PR317).

PR316 defines exactly one immutable, checksum-protected, four-file in-memory
reviewed-change artifact bundle and records the fixed publication, atomicity,
overwrite, existing-identical, and destination policies as contract metadata.
It deliberately owns no filesystem boundary. This module is that boundary and
nothing else.

It adds exactly two public operations:

* :func:`publish_approved_change_artifact_bundle` — validate an exact PR316
  bundle in memory, require explicit confirmation of that exact bundle
  identity, prepare and verify the four canonical files inside one private
  temporary sibling directory, and publish them with one atomic no-replace
  directory transition beneath one fixed ShellForgeAI-owned subtree.
* :func:`load_persisted_approved_change_artifact_bundle` — read exactly one
  persisted bundle back by its exact full bundle ID and rerun the maintained
  PR316 validator on it.

It is an artifact-persistence operation only. It never overwrites, never
replaces, never repairs, never quarantines, never deletes a published bundle,
and never removes anything it did not create in that exact invocation. It
creates no approval, ``ApprovedChangeContract``, or receipt, evaluates or binds
no capability, runs no preflight, integrates no PR313 execution, registers no
CLI route, and reaches no shell, subprocess, network, model, or provider.

The four-file contract, the canonical bytes, the manifest, the bundle identity,
and the bundle ID all remain PR316's. This module persists those exact bytes
verbatim and revalidates them through the maintained PR316 validator.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import stat as stat_module
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from shellforgeai.core.approved_change_artifact_bundle import (
    BUNDLE_FILE_ORDER,
    BUNDLE_FILENAMES,
    BUNDLE_ID_PREFIX,
    EXECUTION_STATUS_NOT_EXECUTED,
    MANIFEST_ROLE,
    ApprovedChangeArtifactBundle,
    ApprovedChangeArtifactBundleFile,
    ApprovedChangeArtifactBundleManifest,
    ApprovedChangeArtifactBundleValidationResult,
    validate_approved_change_artifact_bundle,
)

PERSISTENCE_SCHEMA_VERSION = "1"

#: The one fixed ShellForgeAI-owned publication root name. There is no caller
#: override, no alias, no alternate spelling, and no configurable variant.
APPROVED_CHANGE_ARTIFACTS_DIRNAME = "approved_change_artifacts"

#: The private temporary sibling prefix. It never enters the final directory,
#: any persisted file, the manifest, the bundle identity, or the bundle ID.
#:
#: The pending directory is named ``.pending-<16 lowercase hex>`` — a short fixed
#: prefix plus one internally generated token, and deliberately *not* the bundle
#: ID. Carrying the full 68-character bundle ID here made the unpublished
#: temporary path 42 characters longer than the durable path it prepares, so a
#: data root whose final bundle path fits could still overflow the Windows
#: ``MAX_PATH`` limit while writing the temporary copy. The pending path is now
#: always shorter than the final path it prepares, so preparation can never be
#: the binding length constraint.
TEMPORARY_DIRECTORY_PREFIX = ".pending-"
TEMPORARY_NONCE_BYTES = 8
TEMPORARY_DIRECTORY_NAME_LENGTH = len(TEMPORARY_DIRECTORY_PREFIX) + 2 * TEMPORARY_NONCE_BYTES

#: The longest publication path this platform can address without extended-length
#: path syntax. Windows ``MAX_PATH`` is 260 including the terminating NUL; POSIX
#: ``PATH_MAX`` is 4096 on the maintained platforms. PR317 never emits a ``\\?\``
#: path and adds no extended-length support: an unaddressable final path is
#: blocked before anything is created.
MAX_PUBLICATION_PATH_CHARS = 259 if os.name == "nt" else 4095

#: Conservative read bounds enforced before any untrusted file is read.
MAX_PERSISTED_BUNDLE_FILE_BYTES = 1_048_576
MAX_PERSISTED_BUNDLE_TOTAL_BYTES = 4_194_304

#: Restrictive modes requested where the platform supports them.
PERSISTED_FILE_MODE = 0o600
PERSISTED_DIRECTORY_MODE = 0o700

#: The exact scope the explicit confirmation authorizes, and nothing more.
CONFIRMATION_SCOPE = "publish_this_exact_validated_bundle_identity_under_the_fixed_artifact_subtree"

PUBLICATION_STATUSES = (
    "bundle_published",
    "bundle_already_present",
    "publication_blocked",
    "invalid_publication_input",
    "publication_failed_precommit",
    "publication_failed_cleanup_incomplete",
    "published_verification_failed",
    "atomic_publication_unsupported",
)
LOAD_STATUSES = (
    "persisted_bundle_loaded",
    "persisted_bundle_not_found",
    "persisted_bundle_invalid",
    "invalid_persisted_bundle_reference",
    "unsafe_persistence_root",
)

PublicationStatus = Literal[
    "bundle_published",
    "bundle_already_present",
    "publication_blocked",
    "invalid_publication_input",
    "publication_failed_precommit",
    "publication_failed_cleanup_incomplete",
    "published_verification_failed",
    "atomic_publication_unsupported",
]
LoadStatus = Literal[
    "persisted_bundle_loaded",
    "persisted_bundle_not_found",
    "persisted_bundle_invalid",
    "invalid_persisted_bundle_reference",
    "unsafe_persistence_root",
]

FLUSH_STATUSES = ("not_attempted", "passed", "unsupported", "failed")
FlushStatus = Literal["not_attempted", "passed", "unsupported", "failed"]

POST_VALIDATION_STATUSES = ("not_attempted", "passed", "failed")
PostValidationStatus = Literal["not_attempted", "passed", "failed"]

CLEANUP_STATUSES = ("not_required", "completed", "incomplete", "not_attempted")
CleanupStatus = Literal["not_required", "completed", "incomplete", "not_attempted"]

#: Atomic no-replace primitive outcomes. ``rejected`` means the helper refused
#: an unvalidated or cross-parent request; ``unsupported`` means the platform
#: offers no proven atomic no-replace directory primitive.
ATOMIC_OUTCOMES = ("published", "destination_exists", "rejected", "unsupported", "failed")
AtomicOutcome = Literal["published", "destination_exists", "rejected", "unsupported", "failed"]

PERMANENT_PERSISTENCE_WARNINGS: tuple[str, ...] = (
    "a persisted bundle is not approval and persistence is not authorization",
    "a persisted bundle is not an ApprovedChangeContract",
    "reviewer provenance is not authenticated identity",
    "bundle identity is not subject identity and is not capability support",
    "explicit publication confirmation is scoped only to artifact publication and is not "
    "execution confirmation",
    "publication grants no execution eligibility",
    "no overwrite is permitted: an existing bundle directory is never replaced, repaired, "
    "renamed, quarantined, or deleted",
    "reviewed artifacts may contain operational context and must be reviewed before sharing",
    "no redaction is performed because redaction would change reviewed identity",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
#: The bundle-ID prefix is PR316's; it is never redefined here.
_BUNDLE_ID_RE = re.compile(rf"^{re.escape(BUNDLE_ID_PREFIX)}[0-9a-f]{{64}}$")

#: ``os.open`` defaults to text mode on Windows, where the C runtime rewrites
#: "\n" as "\r\n" on write. Persisted bundle bytes must be exact, so binary mode
#: is requested explicitly. ``os.O_BINARY`` does not exist on POSIX, where the
#: flag is unnecessary and resolves to 0.
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

#: Windows ``FILE_ATTRIBUTE_REPARSE_POINT``.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Internal deterministic seams
#
# These are private. They exist so failure, race, and nonce behaviour can be
# exercised deterministically. Neither one is part of the public API and
# neither one accepts a caller-supplied path, token, or destination.
# ---------------------------------------------------------------------------


def _failpoint(name: str) -> None:
    """Internal no-op stage seam used only by focused tests."""
    return None


def _temporary_nonce() -> str:
    """Return a short private token for the unpublished temporary directory name."""
    return secrets.token_hex(TEMPORARY_NONCE_BYTES)


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


class ApprovedChangeArtifactBundlePublicationResult(_FrozenModel):
    """Structured, non-throwing publication result.

    Only ``bundle_published`` and ``published_verification_failed`` mean the
    final bundle directory now exists because of this invocation.
    ``bundle_already_present`` means a fully valid byte-identical bundle was
    already there and nothing was written.
    """

    schema_version: Literal["1"] = PERSISTENCE_SCHEMA_VERSION
    status: PublicationStatus
    reason: str = ""
    bundle_id: str = ""
    bundle_identity_sha256: str = ""
    confirmation_matched: bool = False
    confirmation_scope: str = CONFIRMATION_SCOPE
    relative_bundle_directory: str = ""
    publication_root_created: bool = False
    publication_root_removed: bool = False
    temporary_directory_created: bool = False
    all_files_prepared_before_publish: bool = False
    prepared_file_count: int = 0
    file_flush_status: FlushStatus = "not_attempted"
    temporary_directory_flush_status: FlushStatus = "not_attempted"
    atomic_publish_attempted: bool = False
    atomic_publish_succeeded: bool = False
    atomic_publish_outcome: AtomicOutcome | Literal["not_attempted"] = "not_attempted"
    publication_root_flush_status: FlushStatus = "not_attempted"
    post_validation_status: PostValidationStatus = "not_attempted"
    temporary_cleanup: CleanupStatus = "not_required"
    residual_temporary_directory: str = ""
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PERSISTENCE_WARNINGS

    # Accurate safety ledger.
    read_only: bool = True
    mutation_performed: bool = False
    artifact_write_performed: bool = False
    filesystem_accessed: bool = False
    publication_performed: bool = False
    persistence_performed: bool = False
    persisted_bundle_present: bool = False
    overwrite_performed: Literal[False] = False
    temporary_cleanup_performed: bool = False
    host_configuration_mutation_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    receipt_created: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    approval_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


class ApprovedChangeArtifactBundleLoadResult(_FrozenModel):
    """Structured, non-throwing read-only persisted-bundle load result."""

    schema_version: Literal["1"] = PERSISTENCE_SCHEMA_VERSION
    status: LoadStatus
    reason: str = ""
    bundle_id: str = ""
    bundle_identity_sha256: str = ""
    relative_bundle_directory: str = ""
    bundle: ApprovedChangeArtifactBundle | None = None
    bundle_validation: ApprovedChangeArtifactBundleValidationResult | None = None
    total_bytes_read: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = PERMANENT_PERSISTENCE_WARNINGS

    # Accurate safety ledger. Loading never mutates anything.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    filesystem_accessed: bool = False
    publication_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    overwrite_performed: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    approval_created: Literal[False] = False
    contract_created: Literal[False] = False
    receipt_created: Literal[False] = False
    capability_support_evaluated: Literal[False] = False
    capability_supported: Literal[False] = False
    approval_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = EXECUTION_STATUS_NOT_EXECUTED


@dataclass(frozen=True)
class AtomicNoReplaceOutcome:
    """One atomic no-replace directory publication attempt."""

    outcome: AtomicOutcome
    platform_primitive: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Narrow platform-safe atomic no-replace directory primitive
#
# The only native platform API use in this module lives here. It receives
# already-validated, invocation-owned temporary and final paths, uses fixed
# platform API signatures, loads no caller-selected library, and exposes no
# generic native invocation.
# ---------------------------------------------------------------------------

#: ``linux/fs.h``: rename without ever replacing an existing destination.
_RENAME_NOREPLACE = 1
_AT_FDCWD = -100
#: ``__NR_renameat2`` for the architectures ShellForgeAI is validated on. Used
#: only when glibc is too old to export the ``renameat2`` wrapper directly.
_RENAMEAT2_SYSCALL_NUMBERS: dict[str, int] = {
    "x86_64": 316,
    "aarch64": 276,
    "armv7l": 382,
    "armv8l": 382,
    "i686": 353,
    "i386": 353,
    "ppc64le": 357,
    "s390x": 347,
}

_ERROR_ALREADY_EXISTS = 183
_ERROR_FILE_EXISTS = 80
_ERROR_ACCESS_DENIED = 5
_MOVEFILE_NO_FLAGS = 0


def _linux_renameat2_no_replace(source: Path, destination: Path) -> AtomicNoReplaceOutcome:
    """Publish ``source`` as ``destination`` with ``RENAME_NOREPLACE``."""
    primitive = "linux_renameat2_no_replace"
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:  # pragma: no cover - defensive
        return AtomicNoReplaceOutcome("unsupported", primitive, f"libc unavailable: {exc}")

    encoded_source = os.fsencode(str(source))
    encoded_destination = os.fsencode(str(destination))

    wrapper = getattr(libc, "renameat2", None)
    if wrapper is not None:
        wrapper.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        wrapper.restype = ctypes.c_int
        ctypes.set_errno(0)
        code = wrapper(
            _AT_FDCWD,
            encoded_source,
            _AT_FDCWD,
            encoded_destination,
            _RENAME_NOREPLACE,
        )
    else:
        number = _RENAMEAT2_SYSCALL_NUMBERS.get(platform.machine())
        if number is None:
            return AtomicNoReplaceOutcome(
                "unsupported",
                primitive,
                f"no renameat2 wrapper or known syscall number for {platform.machine()}",
            )
        syscall = libc.syscall
        syscall.argtypes = [
            ctypes.c_long,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        syscall.restype = ctypes.c_long
        ctypes.set_errno(0)
        code = syscall(
            number,
            _AT_FDCWD,
            encoded_source,
            _AT_FDCWD,
            encoded_destination,
            _RENAME_NOREPLACE,
        )

    if code == 0:
        return AtomicNoReplaceOutcome("published", primitive)
    errno_value = ctypes.get_errno()
    if errno_value in {getattr(os, "EEXIST", 17), getattr(os, "ENOTEMPTY", 39)}:
        return AtomicNoReplaceOutcome("destination_exists", primitive, os.strerror(errno_value))
    if errno_value in {
        getattr(os, "ENOSYS", 38),
        getattr(os, "EINVAL", 22),
        getattr(os, "EOPNOTSUPP", 95),
    }:
        # The kernel or filesystem offers no proven no-replace rename. Fail
        # closed instead of silently downgrading to a replace-capable rename.
        return AtomicNoReplaceOutcome("unsupported", primitive, os.strerror(errno_value))
    return AtomicNoReplaceOutcome("failed", primitive, os.strerror(errno_value))


def _windows_move_file_no_replace(source: Path, destination: Path) -> AtomicNoReplaceOutcome:
    """Publish ``source`` as ``destination`` with ``MoveFileExW`` and no flags.

    Without ``MOVEFILE_REPLACE_EXISTING`` the call fails when the destination
    exists, and ``MOVEFILE_REPLACE_EXISTING`` cannot replace a directory at all.
    """
    primitive = "windows_movefileexw_no_replace"
    windll = getattr(ctypes, "WinDLL", None)
    if windll is None:  # pragma: no cover - non-Windows
        return AtomicNoReplaceOutcome("unsupported", primitive, "ctypes.WinDLL unavailable")
    try:
        kernel32 = windll("kernel32", use_last_error=True)
    except OSError as exc:  # pragma: no cover - defensive
        return AtomicNoReplaceOutcome("unsupported", primitive, f"kernel32 unavailable: {exc}")
    move = kernel32.MoveFileExW
    move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move.restype = ctypes.c_int
    ctypes.set_last_error(0)
    if move(str(source), str(destination), _MOVEFILE_NO_FLAGS):
        return AtomicNoReplaceOutcome("published", primitive)
    code = ctypes.get_last_error()
    if code in {_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS}:
        return AtomicNoReplaceOutcome("destination_exists", primitive, f"win32 error {code}")
    if code == _ERROR_ACCESS_DENIED and _path_exists_without_following(destination):
        # A destination that appeared in a race can surface as access denied.
        return AtomicNoReplaceOutcome("destination_exists", primitive, f"win32 error {code}")
    return AtomicNoReplaceOutcome("failed", primitive, f"win32 error {code}")


def atomic_no_replace_directory_publish(source: Path, destination: Path) -> AtomicNoReplaceOutcome:
    """Publish one prepared directory as ``destination``, never replacing it.

    The transition is atomic, same-parent, same-filesystem, directory-level, and
    no-replace. It is never a pre-check followed by a replace-capable rename and
    it never uses ``os.replace``, ``os.rename``, ``shutil``, a shell, a
    subprocess, or an external binary. When the platform offers no proven atomic
    no-replace directory primitive the helper reports ``unsupported`` and the
    caller fails closed.
    """
    if not isinstance(source, Path) or not isinstance(destination, Path):
        return AtomicNoReplaceOutcome("rejected", "none", "paths must be Path objects")
    if not source.is_absolute() or not destination.is_absolute():
        return AtomicNoReplaceOutcome("rejected", "none", "paths must be absolute")
    if source == destination:
        return AtomicNoReplaceOutcome("rejected", "none", "source and destination are identical")
    if source.parent != destination.parent:
        return AtomicNoReplaceOutcome("rejected", "none", "paths must share one parent directory")
    if not source.name or not destination.name:
        return AtomicNoReplaceOutcome("rejected", "none", "paths must name a directory entry")
    try:
        source_stat = os.lstat(source)
        parent_stat = os.lstat(source.parent)
    except OSError as exc:
        return AtomicNoReplaceOutcome("rejected", "none", f"source is not inspectable: {exc}")
    if not stat_module.S_ISDIR(source_stat.st_mode) or _is_reparse_stat(source_stat, source):
        return AtomicNoReplaceOutcome(
            "rejected", "none", "source must be a real directory and not a symlink or reparse point"
        )
    if source_stat.st_dev != parent_stat.st_dev:
        return AtomicNoReplaceOutcome(
            "rejected", "none", "source and destination must share one filesystem"
        )

    if sys.platform.startswith("linux"):
        return _linux_renameat2_no_replace(source, destination)
    if os.name == "nt":
        return _windows_move_file_no_replace(source, destination)
    return AtomicNoReplaceOutcome(
        "unsupported",
        "none",
        f"no proven atomic no-replace directory primitive for platform {sys.platform}",
    )


# ---------------------------------------------------------------------------
# Filesystem-safety helpers
# ---------------------------------------------------------------------------


def _is_reparse_stat(stat_result: os.stat_result, path: Path) -> bool:
    if stat_module.S_ISLNK(stat_result.st_mode):
        return True
    if getattr(stat_result, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    return path.is_symlink()


def _is_symlink_or_reparse(path: Path) -> bool:
    try:
        return _is_reparse_stat(os.lstat(path), path)
    except OSError:
        return False


def _path_exists_without_following(path: Path) -> bool:
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _is_filesystem_root(path: Path) -> bool:
    return path.parent == path or len(path.parts) <= 1


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class _DataDirCheck:
    """One explicit data-directory validation outcome."""

    path: Path | None
    errors: tuple[str, ...]
    filesystem_accessed: bool


def _validate_data_dir(data_dir: Path | str) -> _DataDirCheck:
    """Validate the explicit ShellForgeAI data directory.

    No arbitrary destination, publication root, final directory name, or
    filename is ever accepted: only this already-resolved data root. Purely
    structural rejections happen before any filesystem object is inspected, so
    the reported ``filesystem_accessed`` flag stays truthful.
    """
    if isinstance(data_dir, str):
        if not data_dir.strip():
            return _DataDirCheck(None, ("data_dir must be a non-empty path",), False)
        candidate = Path(data_dir)
    elif isinstance(data_dir, Path):
        candidate = data_dir
    else:
        return _DataDirCheck(None, ("data_dir must be a path or string",), False)

    if not candidate.is_absolute():
        return _DataDirCheck(None, ("data_dir must be an absolute path",), False)
    if _is_filesystem_root(candidate):
        return _DataDirCheck(
            None, ("data_dir must not be the filesystem root or a drive root",), False
        )
    if _is_symlink_or_reparse(candidate):
        return _DataDirCheck(None, ("data_dir must not be a symlink or reparse point",), True)
    try:
        info = os.lstat(candidate)
    except OSError:
        return _DataDirCheck(None, ("data_dir must already exist",), True)
    if not stat_module.S_ISDIR(info.st_mode):
        return _DataDirCheck(None, ("data_dir must be a directory",), True)
    return _DataDirCheck(candidate, (), True)


def _publication_root(data_dir: Path) -> Path:
    return data_dir / APPROVED_CHANGE_ARTIFACTS_DIRNAME


def _check_publication_root_containment(data_dir: Path, root: Path) -> list[str]:
    """Recheck that the fixed root is still a safe direct child of ``data_dir``."""
    errors: list[str] = []
    if root.name != APPROVED_CHANGE_ARTIFACTS_DIRNAME or root.parent != data_dir:
        errors.append("publication root must be the fixed direct child of data_dir")
        return errors
    if _is_symlink_or_reparse(root):
        errors.append("publication root must not be a symlink or reparse point")
        return errors
    if _path_exists_without_following(root):
        try:
            info = os.lstat(root)
        except OSError as exc:
            errors.append(f"publication root is not inspectable: {exc}")
            return errors
        if not stat_module.S_ISDIR(info.st_mode):
            errors.append("publication root exists but is not a directory")
            return errors
        if _real(root).parent != _real(data_dir):
            errors.append("publication root escapes the resolved data directory")
    return errors


def _projected_final_path_errors(final_directory: Path) -> list[str]:
    """Refuse a data root whose fixed final durable paths are unaddressable.

    The four persisted filenames are fixed, so the longest final path this
    publication would ever need is known before anything is created. When that
    path cannot be addressed without extended-length path syntax the publication
    is blocked up front, so no temporary directory or file is created for a
    bundle that could never be published. Only lengths are reported: no host
    absolute path is ever placed in a result.
    """
    longest = max(len(str(final_directory / name)) for name in BUNDLE_FILENAMES)
    if longest > MAX_PUBLICATION_PATH_CHARS:
        return [
            "the data directory is too long for the fixed final bundle path: the longest "
            f"persisted path would be {longest} characters and this platform addresses at "
            f"most {MAX_PUBLICATION_PATH_CHARS}"
        ]
    return []


def _check_child_containment(root: Path, child: Path, label: str) -> list[str]:
    """Require ``child`` to remain a direct contained child of the fixed root."""
    errors: list[str] = []
    if child.parent != root:
        errors.append(f"{label} must be a direct child of the fixed publication root")
        return errors
    if _path_exists_without_following(child):
        if _is_symlink_or_reparse(child):
            errors.append(f"{label} must not be a symlink or reparse point")
            return errors
        if _real(child).parent != _real(root):
            errors.append(f"{label} escapes the fixed publication root")
    return errors


def _fsync_directory(path: Path) -> tuple[FlushStatus, str]:
    """Flush one directory where the platform supports it."""
    if os.name == "nt":  # pragma: no cover - platform dependent
        return "unsupported", "Windows offers no directory flush primitive"
    try:
        fd = os.open(path, os.O_RDONLY | _O_DIRECTORY)
    except OSError as exc:
        return "failed", f"directory could not be opened for flush: {exc}"
    try:
        os.fsync(fd)
    except OSError as exc:
        return "failed", f"directory flush failed: {exc}"
    except AttributeError:  # pragma: no cover - platform dependent
        return "unsupported", "os.fsync is unavailable"
    finally:
        os.close(fd)
    return "passed", ""


# ---------------------------------------------------------------------------
# Bounded, no-follow reads
# ---------------------------------------------------------------------------


def _open_regular_file_no_follow(path: Path, *, access_flags: int = os.O_RDONLY) -> int:
    """Open one existing regular file without ever following a link.

    ``access_flags`` selects the access mode only; every other flag and every
    safety check is fixed. Reads use the default ``O_RDONLY``; the durability
    flush uses ``O_RDWR`` because a read-only descriptor cannot be flushed on
    Windows. No caller-supplied path, filename, or flag beyond that access mode
    reaches this helper.

    Where ``O_NOFOLLOW`` is unavailable the pre-open ``lstat`` identity is
    compared with the post-open descriptor metadata instead.
    """
    before = os.lstat(path)
    if not stat_module.S_ISREG(before.st_mode) or _is_reparse_stat(before, path):
        raise OSError(f"{path.name} is not a regular file")
    fd = os.open(path, access_flags | _O_BINARY | _O_NOFOLLOW)
    try:
        after = os.fstat(fd)
        if not stat_module.S_ISREG(after.st_mode):
            raise OSError(f"{path.name} is not a regular file")
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise OSError(f"{path.name} changed identity between inspection and open")
    except Exception:
        os.close(fd)
        raise
    return fd


def _read_bounded(path: Path, expected_size: int) -> bytes:
    """Read exactly ``expected_size`` bytes and fail closed on any drift."""
    fd = _open_regular_file_no_follow(path)
    try:
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                raise OSError(f"{path.name} was truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise OSError(f"{path.name} grew during read")
        final = os.fstat(fd)
        if final.st_size != expected_size:
            raise OSError(f"{path.name} changed size between inspection and read")
    finally:
        os.close(fd)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Read-only persisted-bundle loader
# ---------------------------------------------------------------------------


def _load_result(
    status: LoadStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    bundle_id: str = "",
    bundle_identity_sha256: str = "",
    relative_bundle_directory: str = "",
    bundle: ApprovedChangeArtifactBundle | None = None,
    bundle_validation: ApprovedChangeArtifactBundleValidationResult | None = None,
    total_bytes_read: int = 0,
    filesystem_accessed: bool = False,
) -> ApprovedChangeArtifactBundleLoadResult:
    return ApprovedChangeArtifactBundleLoadResult(
        status=status,
        reason=reason,
        bundle_id=bundle_id,
        bundle_identity_sha256=bundle_identity_sha256,
        relative_bundle_directory=relative_bundle_directory,
        bundle=bundle,
        bundle_validation=bundle_validation,
        total_bytes_read=total_bytes_read,
        errors=tuple(sorted(set(errors or ()))),
        filesystem_accessed=filesystem_accessed,
    )


def _relative_bundle_directory(bundle_id: str) -> str:
    """Return the root-relative bundle directory. Never a host absolute path."""
    return f"{APPROVED_CHANGE_ARTIFACTS_DIRNAME}/{bundle_id}"


def _bundle_id_reference_errors(bundle_id: Any) -> list[str]:
    """Reject anything that is not exactly ``acb_`` plus 64 lowercase hex."""
    if not isinstance(bundle_id, str) or not bundle_id:
        return ["bundle_id must be a non-empty string"]
    errors: list[str] = []
    if bundle_id != bundle_id.strip():
        errors.append("bundle_id must not carry leading or trailing whitespace")
    if not _BUNDLE_ID_RE.fullmatch(bundle_id):
        errors.append(
            f"bundle_id must be exactly {BUNDLE_ID_PREFIX!r} followed by 64 lowercase "
            "hexadecimal characters"
        )
    return errors


def load_persisted_approved_change_artifact_bundle(
    bundle_id: str,
    *,
    data_dir: Path | str,
) -> ApprovedChangeArtifactBundleLoadResult:
    """Load exactly one persisted bundle by its exact full bundle ID.

    The loader is strictly read-only. It accepts no arbitrary path, directory,
    filename, glob, prefix, shortened hash, case variant, alias, or implicit
    "latest"/"current"/"most recent" reference, follows no path supplied inside
    the manifest, reads no unbounded untrusted file, and mutates nothing.
    """
    reference_errors = _bundle_id_reference_errors(bundle_id)
    if reference_errors:
        return _load_result(
            "invalid_persisted_bundle_reference",
            reason="the persisted-bundle reference is not one exact full bundle ID",
            errors=reference_errors,
        )

    data_dir_check = _validate_data_dir(data_dir)
    resolved_data_dir = data_dir_check.path
    if resolved_data_dir is None:
        return _load_result(
            "unsafe_persistence_root",
            reason="the explicit data directory is not a safe existing absolute directory",
            errors=list(data_dir_check.errors),
            bundle_id=bundle_id,
            filesystem_accessed=data_dir_check.filesystem_accessed,
        )

    root = _publication_root(resolved_data_dir)
    root_errors = _check_publication_root_containment(resolved_data_dir, root)
    if root_errors:
        return _load_result(
            "unsafe_persistence_root",
            reason="the fixed publication root is not a safe direct child of the data directory",
            errors=root_errors,
            bundle_id=bundle_id,
            filesystem_accessed=True,
        )

    relative = _relative_bundle_directory(bundle_id)
    if not _path_exists_without_following(root):
        return _load_result(
            "persisted_bundle_not_found",
            reason="the fixed publication root does not exist",
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )

    directory = root / bundle_id
    containment_errors = _check_child_containment(root, directory, "persisted bundle directory")
    if containment_errors:
        return _load_result(
            "unsafe_persistence_root",
            reason="the persisted bundle directory is not a safe direct child of the fixed root",
            errors=containment_errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )
    if not _path_exists_without_following(directory):
        return _load_result(
            "persisted_bundle_not_found",
            reason="no persisted bundle exists for this exact bundle ID",
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )

    errors: list[str] = []
    try:
        directory_stat = os.lstat(directory)
    except OSError as exc:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle directory is not inspectable",
            errors=[f"persisted bundle directory is not inspectable: {exc}"],
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )
    if not stat_module.S_ISDIR(directory_stat.st_mode):
        errors.append("the persisted bundle path is not a directory")
    if _is_reparse_stat(directory_stat, directory):
        errors.append("the persisted bundle directory must not be a symlink or reparse point")
    if errors:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle directory is not a safe real directory",
            errors=errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )

    try:
        entries = sorted(entry.name for entry in os.scandir(directory))
    except OSError as exc:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle directory could not be listed",
            errors=[f"persisted bundle directory could not be listed: {exc}"],
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )
    if entries != sorted(BUNDLE_FILENAMES):
        missing = sorted(set(BUNDLE_FILENAMES) - set(entries))
        extra = sorted(set(entries) - set(BUNDLE_FILENAMES))
        for name in missing:
            errors.append(f"persisted bundle is missing the required file: {name}")
        for name in extra:
            errors.append(f"persisted bundle contains an unexpected entry: {name}")
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle directory does not hold exactly the four fixed files",
            errors=errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )

    # Bound every file before any content is read.
    sizes: dict[str, int] = {}
    total = 0
    for filename in BUNDLE_FILENAMES:
        path = directory / filename
        try:
            info = os.lstat(path)
        except OSError as exc:
            errors.append(f"{filename} is not inspectable: {exc}")
            continue
        if not stat_module.S_ISREG(info.st_mode) or _is_reparse_stat(info, path):
            errors.append(f"{filename} must be a regular file and not a symlink or reparse point")
            continue
        size = info.st_size
        if size < 0:
            errors.append(f"{filename} reports an inconsistent size")
            continue
        if size > MAX_PERSISTED_BUNDLE_FILE_BYTES:
            errors.append(
                f"{filename} exceeds the {MAX_PERSISTED_BUNDLE_FILE_BYTES}-byte per-file limit"
            )
            continue
        sizes[filename] = size
        total += size
    if total > MAX_PERSISTED_BUNDLE_TOTAL_BYTES:
        errors.append(
            f"persisted bundle exceeds the {MAX_PERSISTED_BUNDLE_TOTAL_BYTES}-byte total limit"
        )
    if errors:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle files failed the fixed size and file-type bounds",
            errors=errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            filesystem_accessed=True,
        )

    records: list[ApprovedChangeArtifactBundleFile] = []
    for filename, role in BUNDLE_FILE_ORDER:
        path = directory / filename
        try:
            raw = _read_bounded(path, sizes[filename])
        except OSError as exc:
            errors.append(f"{filename} could not be read safely: {exc}")
            continue
        try:
            content = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            errors.append(f"{filename} is not strict UTF-8: {exc}")
            continue
        try:
            records.append(
                ApprovedChangeArtifactBundleFile(
                    relative_path=filename,
                    role=role,
                    content_utf8=content,
                    size_bytes=len(raw),
                    sha256=_sha256_bytes(raw),
                )
            )
        except Exception as exc:  # untrusted stored bytes must never raise publicly
            errors.append(f"{filename} does not form a valid PR316 logical file record: {exc}")
    if errors:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle files could not be reconstructed as PR316 file records",
            errors=errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            total_bytes_read=total,
            filesystem_accessed=True,
        )

    bundle, build_errors = _bundle_from_records(tuple(records))
    if bundle is None:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted files do not form one PR316 bundle",
            errors=build_errors,
            bundle_id=bundle_id,
            relative_bundle_directory=relative,
            total_bytes_read=total,
            filesystem_accessed=True,
        )

    validation = validate_approved_change_artifact_bundle(bundle)
    if validation.status != "bundle_valid" or not validation.bundle_valid:
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle failed maintained PR316 validation",
            errors=["persisted bundle failed PR316 validation", *validation.errors],
            bundle_id=bundle_id,
            bundle_identity_sha256=bundle.bundle_identity_sha256,
            relative_bundle_directory=relative,
            bundle_validation=validation,
            total_bytes_read=total,
            filesystem_accessed=True,
        )
    if not hmac.compare_digest(bundle.bundle_id, bundle_id):
        return _load_result(
            "persisted_bundle_invalid",
            reason="the persisted bundle records another bundle ID than its directory name",
            errors=["persisted bundle_id does not match the requested bundle directory"],
            bundle_id=bundle_id,
            bundle_identity_sha256=bundle.bundle_identity_sha256,
            relative_bundle_directory=relative,
            bundle_validation=validation,
            total_bytes_read=total,
            filesystem_accessed=True,
        )

    return _load_result(
        "persisted_bundle_loaded",
        reason="one persisted bundle was loaded and revalidated",
        bundle_id=bundle.bundle_id,
        bundle_identity_sha256=bundle.bundle_identity_sha256,
        relative_bundle_directory=relative,
        bundle=bundle,
        bundle_validation=validation,
        total_bytes_read=total,
        filesystem_accessed=True,
    )


def _bundle_from_records(
    records: tuple[ApprovedChangeArtifactBundleFile, ...],
) -> tuple[ApprovedChangeArtifactBundle | None, list[str]]:
    """Reconstruct one PR316 bundle from prepared or persisted file records.

    The manifest is parsed only as untrusted data by the maintained PR316
    validator; the bundle identity and bundle ID are taken from the maintained
    manifest model, never invented here.
    """
    manifest_record = next(
        (record for record in records if record.role == MANIFEST_ROLE),
        None,
    )
    if manifest_record is None:
        return None, ["the bundle files do not include a manifest"]
    try:
        raw = json.loads(manifest_record.content_utf8)
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        return None, [f"manifest.json is not parseable JSON: {exc}"]
    if not isinstance(raw, dict):
        return None, ["manifest.json must contain a JSON object"]
    try:
        manifest = ApprovedChangeArtifactBundleManifest.model_validate(raw)
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        return None, [f"manifest.json does not parse into its maintained model: {exc}"]
    try:
        bundle = ApprovedChangeArtifactBundle(
            bundle_id=manifest.bundle_id,
            bundle_identity_sha256=manifest.bundle_identity_sha256,
            files=records,
        )
    except Exception as exc:  # untrusted stored bytes must never raise publicly
        return None, [f"the files do not form one PR316 bundle: {exc}"]
    return bundle, []


# ---------------------------------------------------------------------------
# Publication
# ---------------------------------------------------------------------------


@dataclass
class _PublicationState:
    """Mutable per-invocation bookkeeping. Nothing here is ever persisted."""

    publication_root_created: bool = False
    publication_root_removed: bool = False
    temporary_directory: Path | None = None
    temporary_directory_created: bool = False
    created_files: list[Path] = None  # type: ignore[assignment]
    prepared_file_count: int = 0
    all_files_prepared_before_publish: bool = False
    file_flush_status: FlushStatus = "not_attempted"
    temporary_directory_flush_status: FlushStatus = "not_attempted"

    def __post_init__(self) -> None:
        if self.created_files is None:
            self.created_files = []


def _publication_result(
    status: PublicationStatus,
    *,
    reason: str,
    errors: list[str] | None = None,
    bundle_id: str = "",
    bundle_identity_sha256: str = "",
    confirmation_matched: bool = False,
    relative_bundle_directory: str = "",
    state: _PublicationState | None = None,
    atomic_publish_attempted: bool = False,
    atomic_publish_succeeded: bool = False,
    atomic_publish_outcome: str = "not_attempted",
    publication_root_flush_status: FlushStatus = "not_attempted",
    post_validation_status: PostValidationStatus = "not_attempted",
    temporary_cleanup: CleanupStatus = "not_required",
    residual_temporary_directory: str = "",
    read_only: bool = True,
    mutation_performed: bool = False,
    artifact_write_performed: bool = False,
    filesystem_accessed: bool = False,
    publication_performed: bool = False,
    persistence_performed: bool = False,
    persisted_bundle_present: bool = False,
    temporary_cleanup_performed: bool = False,
) -> ApprovedChangeArtifactBundlePublicationResult:
    state = state or _PublicationState()
    return ApprovedChangeArtifactBundlePublicationResult(
        status=status,
        reason=reason,
        bundle_id=bundle_id,
        bundle_identity_sha256=bundle_identity_sha256,
        confirmation_matched=confirmation_matched,
        relative_bundle_directory=relative_bundle_directory,
        publication_root_created=state.publication_root_created,
        publication_root_removed=state.publication_root_removed,
        temporary_directory_created=state.temporary_directory_created,
        all_files_prepared_before_publish=state.all_files_prepared_before_publish,
        prepared_file_count=state.prepared_file_count,
        file_flush_status=state.file_flush_status,
        temporary_directory_flush_status=state.temporary_directory_flush_status,
        atomic_publish_attempted=atomic_publish_attempted,
        atomic_publish_succeeded=atomic_publish_succeeded,
        atomic_publish_outcome=atomic_publish_outcome,
        publication_root_flush_status=publication_root_flush_status,
        post_validation_status=post_validation_status,
        temporary_cleanup=temporary_cleanup,
        residual_temporary_directory=residual_temporary_directory,
        errors=tuple(sorted(set(errors or ()))),
        read_only=read_only,
        mutation_performed=mutation_performed,
        artifact_write_performed=artifact_write_performed,
        filesystem_accessed=filesystem_accessed,
        publication_performed=publication_performed,
        persistence_performed=persistence_performed,
        persisted_bundle_present=persisted_bundle_present,
        temporary_cleanup_performed=temporary_cleanup_performed,
    )


def _cleanup_temporary_directory(state: _PublicationState) -> tuple[CleanupStatus, list[str]]:
    """Remove only this invocation's own unpublished temporary directory.

    Only the exact files this invocation created are considered for removal.
    Unknown or extra entries are preserved, the directory is removed only when
    it is empty, and no generic recursive deletion is ever used.
    """
    temporary = state.temporary_directory
    if temporary is None or not state.temporary_directory_created:
        return "not_required", []
    errors: list[str] = []
    if _is_symlink_or_reparse(temporary):
        return "incomplete", [
            "the temporary directory is no longer a real directory owned by this invocation"
        ]
    try:
        current = os.lstat(temporary)
    except OSError:
        # Already gone; nothing this invocation created remains.
        state.temporary_directory = None
        return "completed", []
    if not stat_module.S_ISDIR(current.st_mode):
        return "incomplete", ["the temporary path is no longer a directory"]

    for path in list(state.created_files):
        if path.parent != temporary:
            errors.append("a tracked temporary file no longer belongs to this invocation")
            continue
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if not stat_module.S_ISREG(info.st_mode) or _is_reparse_stat(info, path):
            errors.append(
                "a tracked temporary entry is no longer the regular file that was created"
            )
            continue
        try:
            os.unlink(path)
        except OSError as exc:
            errors.append(
                f"a temporary file created by this invocation could not be removed: {exc}"
            )

    try:
        remaining = sorted(entry.name for entry in os.scandir(temporary))
    except OSError as exc:
        return "incomplete", [*errors, f"the temporary directory could not be listed: {exc}"]
    if remaining:
        errors.append(
            "the temporary directory holds entries this invocation did not create; they are "
            "preserved and nothing was removed recursively"
        )
        return "incomplete", errors
    try:
        os.rmdir(temporary)
    except OSError as exc:
        return "incomplete", [*errors, f"the empty temporary directory could not be removed: {exc}"]
    state.temporary_directory = None
    if errors:
        return "incomplete", errors
    return "completed", []


def _cleanup_publication_root(root: Path, data_dir: Path, state: _PublicationState) -> None:
    """Remove the publication root only when this invocation created it empty."""
    if not state.publication_root_created or state.publication_root_removed:
        return
    if state.temporary_directory is not None:
        return
    if _check_publication_root_containment(data_dir, root):
        return
    if _is_symlink_or_reparse(root):
        return
    try:
        if any(True for _ in os.scandir(root)):
            return
        os.rmdir(root)
    except OSError:
        return
    state.publication_root_removed = True


def _write_exact_file(path: Path, data: bytes) -> None:
    """Create one new file exclusively and write exactly ``data``, byte for byte."""
    fd = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY | _O_NOFOLLOW,
        PERSISTED_FILE_MODE,
    )
    try:
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
    finally:
        os.close(fd)


def _flush_file(path: Path) -> None:
    """Flush one prepared file to stable storage.

    The descriptor must be write-capable. On Windows ``os.fsync`` maps to
    ``FlushFileBuffers``, which requires write access on the handle and fails
    with ``EBADF`` on a read-only descriptor, so ``O_RDWR`` is requested rather
    than ``O_RDONLY``. The file is one this invocation just created exclusively
    inside its own private temporary directory; nothing is written through this
    descriptor, and the maintained no-follow, regular-file, and pre-open/
    post-open descriptor-identity checks all still apply unchanged.

    A failed flush is never downgraded to ``unsupported`` and never swallowed:
    the caller records ``file_flush_status="failed"`` and blocks publication.
    """
    fd = _open_regular_file_no_follow(path, access_flags=os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_prepared_file(path: Path, expected: bytes) -> bytes:
    """Reread one prepared file and verify its type, byte length, and checksum."""
    info = os.lstat(path)
    if not stat_module.S_ISREG(info.st_mode) or _is_reparse_stat(info, path):
        raise OSError(f"{path.name} is not the regular file that was created")
    if info.st_size != len(expected):
        raise OSError(f"{path.name} byte length verification failed")
    observed = _read_bounded(path, len(expected))
    if not hmac.compare_digest(_sha256_bytes(observed), _sha256_bytes(expected)):
        raise OSError(f"{path.name} checksum verification failed")
    return observed


def publish_approved_change_artifact_bundle(
    bundle: ApprovedChangeArtifactBundle | dict[str, Any],
    *,
    data_dir: Path | str,
    confirm_bundle_identity_sha256: str,
) -> ApprovedChangeArtifactBundlePublicationResult:
    """Publish one already-valid PR316 bundle atomically and without overwrite.

    The bundle is revalidated in memory through the maintained PR316 validator,
    the explicit confirmation must equal that exact bundle identity, and only
    then is any filesystem object inspected or created. The four canonical files
    are prepared and fully verified inside one private temporary sibling
    directory and published with one atomic no-replace directory transition into
    ``<data_dir>/approved_change_artifacts/<bundle_id>/``.

    Publication is an artifact filesystem mutation. It is never approval,
    authorization, capability support, an ``ApprovedChangeContract``, a receipt,
    execution confirmation, or execution eligibility.
    """
    # 1-2. Fresh maintained PR316 validation of the untrusted bundle.
    validation = validate_approved_change_artifact_bundle(bundle)
    if validation.status != "bundle_valid" or not validation.bundle_valid:
        return _publication_result(
            "invalid_publication_input",
            reason="the bundle is not a valid PR316 bundle",
            errors=["the bundle did not pass maintained PR316 validation", *validation.errors],
        )
    if isinstance(bundle, ApprovedChangeArtifactBundle):
        validated = bundle
    else:
        try:
            validated = ApprovedChangeArtifactBundle.model_validate(bundle)
        except Exception as exc:  # pragma: no cover - validation already passed
            return _publication_result(
                "invalid_publication_input",
                reason="the bundle is not a valid PR316 bundle",
                errors=[f"artifact bundle model validation failed: {exc}"],
            )
    identity = validated.bundle_identity_sha256
    bundle_id = validated.bundle_id
    if not _SHA256_RE.fullmatch(identity) or not _BUNDLE_ID_RE.fullmatch(bundle_id):
        return _publication_result(
            "invalid_publication_input",
            reason="the bundle does not carry an exact bundle identity and full bundle ID",
            errors=["bundle identity or bundle ID is not the exact maintained PR316 form"],
        )

    # 3-4. Confirmation format, then an exact constant-time identity comparison.
    if not isinstance(confirm_bundle_identity_sha256, str) or not _SHA256_RE.fullmatch(
        confirm_bundle_identity_sha256
    ):
        return _publication_result(
            "invalid_publication_input",
            reason="confirm_bundle_identity_sha256 must be 64 lowercase hexadecimal characters",
            errors=[
                "confirm_bundle_identity_sha256 must be exactly 64 lowercase hexadecimal "
                "characters and is never the prefixed bundle ID"
            ],
            bundle_id=bundle_id,
            bundle_identity_sha256=identity,
        )
    if not hmac.compare_digest(confirm_bundle_identity_sha256, identity):
        return _publication_result(
            "invalid_publication_input",
            reason="confirm_bundle_identity_sha256 does not match this exact bundle identity",
            errors=["the explicit publication confirmation does not match the bundle identity"],
            bundle_id=bundle_id,
            bundle_identity_sha256=identity,
        )

    # No filesystem object has been inspected or mutated up to this point.
    return _publish_confirmed_bundle(validated, data_dir=data_dir, bundle_id=bundle_id)


def _publish_confirmed_bundle(
    validated: ApprovedChangeArtifactBundle,
    *,
    data_dir: Path | str,
    bundle_id: str,
) -> ApprovedChangeArtifactBundlePublicationResult:
    identity = validated.bundle_identity_sha256
    relative = _relative_bundle_directory(bundle_id)

    def blocked(
        status: PublicationStatus,
        reason: str,
        errors: list[str],
        *,
        state: _PublicationState | None = None,
        filesystem_accessed: bool = True,
        **kwargs: Any,
    ) -> ApprovedChangeArtifactBundlePublicationResult:
        return _publication_result(
            status,
            reason=reason,
            errors=errors,
            bundle_id=bundle_id,
            bundle_identity_sha256=identity,
            confirmation_matched=True,
            relative_bundle_directory=relative,
            state=state,
            filesystem_accessed=filesystem_accessed,
            **kwargs,
        )

    # 5. The explicit data directory.
    data_dir_check = _validate_data_dir(data_dir)
    resolved_data_dir = data_dir_check.path
    if resolved_data_dir is None:
        return blocked(
            "publication_blocked",
            "the explicit data directory is not a safe existing absolute directory",
            list(data_dir_check.errors),
            filesystem_accessed=data_dir_check.filesystem_accessed,
        )

    # 6-7. The fixed publication root, created only after validation and confirmation.
    root = _publication_root(resolved_data_dir)
    root_errors = _check_publication_root_containment(resolved_data_dir, root)
    if root_errors:
        return blocked(
            "publication_blocked",
            "the fixed publication root is not a safe direct child of the data directory",
            root_errors,
        )

    # The fixed final paths are fully known here. A data root that cannot address
    # them is refused before any directory or file is created.
    length_errors = _projected_final_path_errors(root / bundle_id)
    if length_errors:
        return blocked(
            "publication_blocked",
            "the fixed final bundle path is not addressable beneath this data directory",
            length_errors,
        )

    state = _PublicationState()
    if not _path_exists_without_following(root):
        try:
            _failpoint("publication_root_create")
            os.mkdir(root, PERSISTED_DIRECTORY_MODE)
        except Exception as exc:
            return blocked(
                "publication_failed_precommit",
                "the fixed publication root could not be created",
                [f"publication root creation failed: {exc}"],
                state=state,
            )
        state.publication_root_created = True
        recheck = _check_publication_root_containment(resolved_data_dir, root)
        if recheck:
            _cleanup_publication_root(root, resolved_data_dir, state)
            return blocked(
                "publication_blocked",
                "the fixed publication root is not a safe direct child of the data directory",
                recheck,
                state=state,
                read_only=False,
                mutation_performed=True,
            )

    # 8-9. The exact final directory, and the existing-destination decision.
    final_directory = root / bundle_id
    containment = _check_child_containment(root, final_directory, "final bundle directory")
    if containment:
        _cleanup_publication_root(root, resolved_data_dir, state)
        return blocked(
            "publication_blocked",
            "the final bundle directory is not a safe direct child of the fixed root",
            containment,
            state=state,
        )
    if _path_exists_without_following(final_directory):
        return _existing_destination_result(
            validated,
            data_dir=resolved_data_dir,
            bundle_id=bundle_id,
            state=state,
            temporary_cleanup="not_required",
        )

    # 10. One private temporary sibling directory. Its name is a short fixed
    # prefix plus one internally generated token only: no bundle ID, no semantic
    # identity, and nothing caller-controlled. It is always shorter than the
    # final directory it prepares.
    temporary = root / f"{TEMPORARY_DIRECTORY_PREFIX}{_temporary_nonce()}"
    temp_containment = _check_child_containment(root, temporary, "temporary directory")
    if temp_containment:
        _cleanup_publication_root(root, resolved_data_dir, state)
        return blocked(
            "publication_blocked",
            "the temporary directory is not a safe direct child of the fixed root",
            temp_containment,
            state=state,
        )
    try:
        _failpoint("temporary_directory_create")
        os.mkdir(temporary, PERSISTED_DIRECTORY_MODE)
    except Exception as exc:
        _cleanup_publication_root(root, resolved_data_dir, state)
        return blocked(
            "publication_failed_precommit",
            "the private temporary directory could not be created",
            [f"temporary directory creation failed: {exc}"],
            state=state,
        )
    state.temporary_directory = temporary
    state.temporary_directory_created = True

    def precommit_failure(
        reason: str, errors: list[str], *, artifact_write_performed: bool = True
    ) -> ApprovedChangeArtifactBundlePublicationResult:
        cleanup_status, cleanup_errors = _cleanup_temporary_directory(state)
        residual = "" if cleanup_status == "completed" else temporary.name
        if cleanup_status == "completed":
            _cleanup_publication_root(root, resolved_data_dir, state)
        status: PublicationStatus = (
            "publication_failed_precommit"
            if cleanup_status in {"completed", "not_required"}
            else "publication_failed_cleanup_incomplete"
        )
        combined = [*errors, *cleanup_errors]
        if cleanup_status == "incomplete":
            combined.append(
                "cleanup was incomplete: an unpublished temporary directory created by this "
                "invocation still exists and nothing further was published"
            )
        return blocked(
            status,
            reason,
            combined,
            state=state,
            read_only=False,
            mutation_performed=True,
            artifact_write_performed=artifact_write_performed,
            temporary_cleanup=cleanup_status,
            temporary_cleanup_performed=cleanup_status == "completed",
            residual_temporary_directory=residual,
        )

    if _is_symlink_or_reparse(temporary):
        return precommit_failure(
            "the temporary directory is not a real directory",
            ["the temporary directory must not be a symlink or reparse point"],
            artifact_write_performed=False,
        )

    # 11-12. Exact binary writes, flushed and verified file by file.
    expected_bytes: dict[str, bytes] = {}
    for index, logical in enumerate(validated.files, start=1):
        path = temporary / logical.relative_path
        data = logical.content_utf8.encode("utf-8")
        expected_bytes[logical.relative_path] = data
        try:
            _failpoint(f"file_create:{index}")
            _failpoint("write")
            _write_exact_file(path, data)
        except Exception as exc:
            return precommit_failure(
                f"{logical.relative_path} could not be created exclusively",
                [f"{logical.relative_path} could not be written: {exc}"],
            )
        state.created_files.append(path)
        try:
            _failpoint("file_flush")
            _flush_file(path)
        except Exception as exc:
            state.file_flush_status = "failed"
            return precommit_failure(
                f"{logical.relative_path} could not be flushed",
                [f"{logical.relative_path} flush failed: {exc}"],
            )
        try:
            _failpoint("file_hash_verify")
            _verify_prepared_file(path, data)
        except Exception as exc:
            state.file_flush_status = "passed"
            return precommit_failure(
                f"{logical.relative_path} failed preparation verification",
                [f"{logical.relative_path} verification failed: {exc}"],
            )
        state.prepared_file_count += 1
    state.file_flush_status = "passed"

    # 13. The exact temporary directory contents.
    try:
        prepared_entries = sorted(entry.name for entry in os.scandir(temporary))
    except OSError as exc:
        return precommit_failure(
            "the temporary directory could not be listed",
            [f"the temporary directory could not be listed: {exc}"],
        )
    if prepared_entries != sorted(BUNDLE_FILENAMES):
        return precommit_failure(
            "the temporary directory does not hold exactly the four fixed files",
            ["the prepared directory does not hold exactly the four fixed PR316 files"],
        )
    state.all_files_prepared_before_publish = True

    # 14-15. Reconstruct from the prepared bytes and rerun PR316 validation.
    try:
        _failpoint("prepared_bundle_reconstruct")
        prepared_records = tuple(
            ApprovedChangeArtifactBundleFile(
                relative_path=filename,
                role=role,
                content_utf8=_read_bounded(
                    temporary / filename, len(expected_bytes[filename])
                ).decode("utf-8", errors="strict"),
                size_bytes=len(expected_bytes[filename]),
                sha256=_sha256_bytes(expected_bytes[filename]),
            )
            for filename, role in BUNDLE_FILE_ORDER
        )
        prepared_bundle, reconstruct_errors = _bundle_from_records(prepared_records)
    except Exception as exc:
        prepared_bundle, reconstruct_errors = (
            None,
            [f"prepared bundle reconstruction failed: {exc}"],
        )
    if prepared_bundle is None:
        return precommit_failure(
            "the prepared files do not reconstruct one PR316 bundle",
            reconstruct_errors,
        )
    try:
        _failpoint("prepared_bundle_validate")
        prepared_validation = validate_approved_change_artifact_bundle(prepared_bundle)
    except Exception as exc:
        return precommit_failure(
            "the prepared bundle could not be revalidated",
            [f"prepared bundle validation failed: {exc}"],
        )
    if prepared_validation.status != "bundle_valid" or not prepared_validation.bundle_valid:
        return precommit_failure(
            "the prepared bundle failed maintained PR316 validation",
            ["the prepared bundle failed PR316 validation", *prepared_validation.errors],
        )
    if not hmac.compare_digest(prepared_bundle.bundle_identity_sha256, identity):
        return precommit_failure(
            "the prepared bundle carries another bundle identity",
            ["the prepared bundle identity does not match the confirmed bundle identity"],
        )

    # 16. Flush the prepared directory where supported.
    try:
        _failpoint("temporary_directory_flush")
        flush_status, flush_detail = _fsync_directory(temporary)
    except Exception as exc:
        flush_status, flush_detail = "failed", f"directory flush failed: {exc}"
    state.temporary_directory_flush_status = flush_status
    if flush_status == "failed":
        return precommit_failure(
            "the prepared directory could not be flushed",
            [flush_detail or "the prepared directory flush failed"],
        )

    # 17. One atomic no-replace directory transition.
    if _path_exists_without_following(final_directory):
        # The destination appeared during preparation; never replace it.
        cleanup_status, cleanup_errors = _cleanup_temporary_directory(state)
        return _existing_destination_result(
            validated,
            data_dir=resolved_data_dir,
            bundle_id=bundle_id,
            state=state,
            temporary_cleanup=cleanup_status,
            cleanup_errors=cleanup_errors,
            atomic_publish_attempted=False,
            wrote_temporary=True,
        )
    try:
        _failpoint("atomic_publish")
        outcome = atomic_no_replace_directory_publish(temporary, final_directory)
    except Exception as exc:
        return precommit_failure(
            "the atomic no-replace publication could not be attempted",
            [f"atomic no-replace publication failed: {exc}"],
        )
    if outcome.outcome == "destination_exists":
        cleanup_status, cleanup_errors = _cleanup_temporary_directory(state)
        return _existing_destination_result(
            validated,
            data_dir=resolved_data_dir,
            bundle_id=bundle_id,
            state=state,
            temporary_cleanup=cleanup_status,
            cleanup_errors=cleanup_errors,
            atomic_publish_attempted=True,
            wrote_temporary=True,
        )
    if outcome.outcome == "unsupported":
        cleanup_status, cleanup_errors = _cleanup_temporary_directory(state)
        residual = "" if cleanup_status == "completed" else temporary.name
        if cleanup_status == "completed":
            _cleanup_publication_root(root, resolved_data_dir, state)
        return blocked(
            "atomic_publication_unsupported",
            "this platform offers no proven atomic no-replace directory publication primitive",
            [
                "atomic no-replace directory publication is unsupported here; publication failed "
                "closed rather than downgrading to a replace-capable primitive",
                *([outcome.detail] if outcome.detail else []),
                *cleanup_errors,
            ],
            state=state,
            read_only=False,
            mutation_performed=True,
            artifact_write_performed=True,
            atomic_publish_attempted=True,
            atomic_publish_outcome=outcome.outcome,
            temporary_cleanup=cleanup_status,
            temporary_cleanup_performed=cleanup_status == "completed",
            residual_temporary_directory=residual,
        )
    if outcome.outcome != "published":
        return precommit_failure(
            "the atomic no-replace publication did not succeed",
            [
                f"atomic no-replace publication result: {outcome.outcome}",
                *([outcome.detail] if outcome.detail else []),
            ],
        )

    # Publication has occurred. From here the final bundle is never removed.
    state.temporary_directory = None
    published_state = state

    root_flush_status: FlushStatus
    root_flush_detail: str
    try:
        _failpoint("publication_root_flush")
        root_flush_status, root_flush_detail = _fsync_directory(root)
    except Exception as exc:
        root_flush_status, root_flush_detail = "failed", f"publication root flush failed: {exc}"

    def published(
        status: PublicationStatus,
        reason: str,
        errors: list[str],
        post_validation_status: PostValidationStatus,
    ) -> ApprovedChangeArtifactBundlePublicationResult:
        combined = list(errors)
        if root_flush_status == "failed":
            combined.append(
                "post-publication durability flush failed; the published bundle was retained and "
                "no automatic removal was attempted"
            )
            if root_flush_detail:
                combined.append(root_flush_detail)
        return _publication_result(
            status,
            reason=reason,
            errors=combined,
            bundle_id=bundle_id,
            bundle_identity_sha256=identity,
            confirmation_matched=True,
            relative_bundle_directory=relative,
            state=published_state,
            atomic_publish_attempted=True,
            atomic_publish_succeeded=True,
            atomic_publish_outcome="published",
            publication_root_flush_status=root_flush_status,
            post_validation_status=post_validation_status,
            temporary_cleanup="not_required",
            read_only=False,
            mutation_performed=True,
            artifact_write_performed=True,
            filesystem_accessed=True,
            publication_performed=True,
            persistence_performed=True,
            persisted_bundle_present=True,
        )

    # 18-19. Read-only post-publication load and complete revalidation.
    try:
        _failpoint("post_publication_load")
        loaded = load_persisted_approved_change_artifact_bundle(
            bundle_id, data_dir=resolved_data_dir
        )
        _failpoint("post_publication_validate")
    except Exception as exc:
        return published(
            "published_verification_failed",
            "publication occurred but post-publication verification failed",
            [f"post-publication load failed: {exc}"],
            "failed",
        )
    if loaded.status != "persisted_bundle_loaded" or loaded.bundle is None:
        return published(
            "published_verification_failed",
            "publication occurred but post-publication verification failed",
            ["post-publication load did not return a valid persisted bundle", *loaded.errors],
            "failed",
        )
    if not _bundles_are_byte_identical(loaded.bundle, validated):
        return published(
            "published_verification_failed",
            "publication occurred but the persisted bytes are not byte-identical",
            ["the persisted bundle is not byte-identical to the confirmed bundle"],
            "failed",
        )

    # 20. One structured publication result.
    return published(
        "bundle_published",
        "one reviewed-change artifact bundle was published atomically",
        [],
        "passed",
    )


def _bundles_are_byte_identical(
    left: ApprovedChangeArtifactBundle, right: ApprovedChangeArtifactBundle
) -> bool:
    """Compare two bundles by identity, ID, and all four exact byte streams."""
    if not hmac.compare_digest(left.bundle_id, right.bundle_id):
        return False
    if not hmac.compare_digest(left.bundle_identity_sha256, right.bundle_identity_sha256):
        return False
    if len(left.files) != len(right.files):
        return False
    for a, b in zip(left.files, right.files, strict=True):
        if a.relative_path != b.relative_path or a.role != b.role:
            return False
        if a.size_bytes != b.size_bytes:
            return False
        if not hmac.compare_digest(a.sha256, b.sha256):
            return False
        if a.content_utf8.encode("utf-8") != b.content_utf8.encode("utf-8"):
            return False
    return True


def _existing_destination_result(
    validated: ApprovedChangeArtifactBundle,
    *,
    data_dir: Path,
    bundle_id: str,
    state: _PublicationState,
    temporary_cleanup: CleanupStatus,
    cleanup_errors: list[str] | None = None,
    atomic_publish_attempted: bool = False,
    wrote_temporary: bool = False,
) -> ApprovedChangeArtifactBundlePublicationResult:
    """Decide the existing-destination outcome without ever writing around it.

    ``bundle_already_present`` is returned only when the existing directory
    loads cleanly, revalidates through PR316, and is byte-identical to the input
    bundle. Every other case blocks. The destination is never repaired,
    replaced, quarantined, renamed, deleted, merged, or written around.
    """
    identity = validated.bundle_identity_sha256
    relative = _relative_bundle_directory(bundle_id)
    cleanup_errors = list(cleanup_errors or ())
    residual = ""
    if temporary_cleanup == "incomplete" and state.temporary_directory is not None:
        residual = state.temporary_directory.name

    loaded = load_persisted_approved_change_artifact_bundle(bundle_id, data_dir=data_dir)
    identical = (
        loaded.status == "persisted_bundle_loaded"
        and loaded.bundle is not None
        and _bundles_are_byte_identical(loaded.bundle, validated)
    )

    common: dict[str, Any] = {
        "bundle_id": bundle_id,
        "bundle_identity_sha256": identity,
        "confirmation_matched": True,
        "relative_bundle_directory": relative,
        "state": state,
        "atomic_publish_attempted": atomic_publish_attempted,
        "atomic_publish_outcome": "destination_exists"
        if atomic_publish_attempted
        else ("not_attempted"),
        "temporary_cleanup": temporary_cleanup,
        "temporary_cleanup_performed": temporary_cleanup == "completed",
        "residual_temporary_directory": residual,
        "filesystem_accessed": True,
        "read_only": not wrote_temporary,
        "mutation_performed": wrote_temporary,
        "artifact_write_performed": wrote_temporary,
    }

    if identical:
        return _publication_result(
            "bundle_already_present",
            reason=(
                "a fully valid byte-identical bundle is already published; nothing was written, "
                "replaced, or refreshed"
            ),
            errors=cleanup_errors,
            persisted_bundle_present=True,
            post_validation_status="passed",
            **common,
        )
    return _publication_result(
        "publication_blocked",
        reason=(
            "the final bundle directory already exists and is not a fully valid byte-identical "
            "bundle; it was left untouched"
        ),
        errors=[
            "an existing bundle directory conflicts with this publication and is never repaired, "
            "replaced, quarantined, renamed, deleted, merged, or written around",
            *loaded.errors,
            *cleanup_errors,
        ],
        persisted_bundle_present=loaded.status == "persisted_bundle_loaded",
        post_validation_status="failed",
        **common,
    )
