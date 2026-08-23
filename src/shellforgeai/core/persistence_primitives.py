"""Shared low-level primitives for safe persisted-artifact filesystems.

This internal module owns only path validation, bounded reads, durability, and
atomic no-replace directory publication.  Artifact domains retain ownership of
their schemas, layouts, results, and publication policy.
"""

from __future__ import annotations

import ctypes
import os
import platform
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PERSISTED_FILE_MODE = 0o600
PERSISTED_DIRECTORY_MODE = 0o700

AtomicOutcome = Literal["published", "destination_exists", "rejected", "unsupported", "failed"]
FlushStatus = Literal["not_attempted", "passed", "unsupported", "failed"]

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class AtomicNoReplaceOutcome:
    """One atomic no-replace directory publication attempt."""

    outcome: AtomicOutcome
    platform_primitive: str
    detail: str = ""


_RENAME_NOREPLACE = 1
_AT_FDCWD = -100
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
        code = wrapper(_AT_FDCWD, encoded_source, _AT_FDCWD, encoded_destination, _RENAME_NOREPLACE)
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
            number, _AT_FDCWD, encoded_source, _AT_FDCWD, encoded_destination, _RENAME_NOREPLACE
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
        return AtomicNoReplaceOutcome("unsupported", primitive, os.strerror(errno_value))
    return AtomicNoReplaceOutcome("failed", primitive, os.strerror(errno_value))


def _windows_move_file_no_replace(source: Path, destination: Path) -> AtomicNoReplaceOutcome:
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
        return AtomicNoReplaceOutcome("destination_exists", primitive, f"win32 error {code}")
    return AtomicNoReplaceOutcome("failed", primitive, f"win32 error {code}")


def atomic_no_replace_directory_publish(source: Path, destination: Path) -> AtomicNoReplaceOutcome:
    """Atomically publish a same-parent directory without replacement."""
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
    if not stat.S_ISDIR(source_stat.st_mode) or _is_reparse_stat(source_stat, source):
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


def _is_reparse_stat(stat_result: os.stat_result, path: Path) -> bool:
    return bool(
        stat.S_ISLNK(stat_result.st_mode)
        or getattr(stat_result, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
        or path.is_symlink()
    )


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


@dataclass(frozen=True)
class _DataDirCheck:
    path: Path | None
    errors: tuple[str, ...]
    filesystem_accessed: bool


def _validate_data_dir(data_dir: Path | str) -> _DataDirCheck:
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
    if not stat.S_ISDIR(info.st_mode):
        return _DataDirCheck(None, ("data_dir must be a directory",), True)
    return _DataDirCheck(candidate, (), True)


def _check_child_containment(root: Path, child: Path, label: str) -> list[str]:
    errors: list[str] = []
    if child.parent != root:
        errors.append(f"{label} must be a direct child of the fixed approval publication root")
        return errors
    if _path_exists_without_following(child):
        if _is_symlink_or_reparse(child):
            errors.append(f"{label} must not be a symlink or reparse point")
        elif _real(child).parent != _real(root):
            errors.append(f"{label} escapes the fixed approval publication root")
    return errors


def _fsync_directory(path: Path) -> tuple[FlushStatus, str]:
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


def _open_regular_file_no_follow(path: Path, *, access_flags: int = os.O_RDONLY) -> int:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or _is_reparse_stat(before, path):
        raise OSError(f"{path.name} is not a regular file")
    fd = os.open(path, access_flags | _O_BINARY | _O_NOFOLLOW)
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode):
            raise OSError(f"{path.name} is not a regular file")
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise OSError(f"{path.name} changed identity between inspection and open")
    except Exception:
        os.close(fd)
        raise
    return fd


def _read_bounded(path: Path, expected_size: int) -> bytes:
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
        if os.fstat(fd).st_size != expected_size:
            raise OSError(f"{path.name} changed size between inspection and read")
    finally:
        os.close(fd)
    return b"".join(chunks)
