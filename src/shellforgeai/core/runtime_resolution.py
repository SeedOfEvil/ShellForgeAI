from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

RUNTIME_ROOT_ENV = "SHELLFORGEAI_RUNTIME_ROOT"
PROFILE_ROOT_ENV = "SHELLFORGEAI_PROFILE_ROOT"


@dataclass(frozen=True)
class RuntimeProfileContext:
    runtime_root: Path | None
    profile_root: Path | None
    source: str
    checked_sources: tuple[str, ...] = field(default_factory=tuple)
    error_class: str | None = None
    error_message: str | None = None

    @property
    def resolved(self) -> bool:
        return self.profile_root is not None


def _profile_dir(root: Path) -> Path:
    return root / "config" / "profiles"


def _is_profile_root(root: Path, profile: str) -> bool:
    return (_profile_dir(root) / f"{profile}.yaml").is_file()


def _clean_env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip().strip('"')
    if not value:
        return None
    return Path(value).expanduser()


def _package_profile_root(profile: str) -> Path | None:
    try:
        pkg_root = Path(str(files("shellforgeai")))
    except Exception:
        return None
    return pkg_root if _is_profile_root(pkg_root, profile) else None


def resolve_runtime_profile_context(
    profile: str,
    cwd: Path | None = None,
    *,
    config_path: Path | None = None,
) -> RuntimeProfileContext:
    """Resolve the ShellForgeAI profile context without depending on cwd.

    Resolution is deliberately bounded: explicit configuration/env first,
    wrapper-supplied runtime root next, safely inferred installed roots, then a
    valid current workspace, then package defaults when present. It never scans
    arbitrary parent trees or searches the filesystem broadly.
    """
    current = (cwd or Path.cwd()).resolve()
    checked: list[str] = []

    if config_path is not None:
        cfg = config_path.expanduser()
        checked.append("explicit_config_path")
        root = cfg.parent.parent if cfg.name == f"{profile}.yaml" else cfg.parent
        if cfg.is_file():
            return RuntimeProfileContext(root, root, "explicit_config_path", tuple(checked))

    explicit_profile_root = _clean_env_path(PROFILE_ROOT_ENV)
    if explicit_profile_root is not None:
        checked.append(PROFILE_ROOT_ENV)
        if _is_profile_root(explicit_profile_root, profile):
            return RuntimeProfileContext(
                explicit_profile_root,
                explicit_profile_root,
                PROFILE_ROOT_ENV,
                tuple(checked),
            )

    env_runtime = _clean_env_path(RUNTIME_ROOT_ENV)
    if env_runtime is not None:
        checked.append(RUNTIME_ROOT_ENV)
        if _is_profile_root(env_runtime, profile):
            return RuntimeProfileContext(env_runtime, env_runtime, RUNTIME_ROOT_ENV, tuple(checked))

    # Installed console entrypoints commonly live under <venv>/Scripts or
    # <venv>/bin; when the package is imported from an installed runtime, the
    # package root or its parents may carry config/profiles. This is bounded to
    # the executable/package lineage only, not a filesystem search.
    candidates: list[tuple[str, Path]] = []
    try:
        import sys

        exe = Path(sys.executable).resolve()
        candidates.extend(
            [
                ("python_executable_parent", exe.parent),
                ("python_executable_grandparent", exe.parent.parent),
            ]
        )
    except Exception:
        pass
    try:
        package_root = Path(str(files("shellforgeai"))).resolve()
        candidates.extend(
            [
                ("installed_package_parent", package_root.parent),
                ("installed_package_grandparent", package_root.parent.parent),
                ("installed_package_root", package_root),
            ]
        )
    except Exception:
        pass
    for source, root in candidates:
        checked.append(source)
        if _is_profile_root(root, profile):
            return RuntimeProfileContext(root, root, source, tuple(checked))

    checked.append("current_working_directory")
    if _is_profile_root(current, profile):
        return RuntimeProfileContext(current, current, "current_working_directory", tuple(checked))

    checked.append("package_defaults")
    pkg = _package_profile_root(profile)
    if pkg is not None:
        return RuntimeProfileContext(pkg, pkg, "package_defaults", tuple(checked))

    return RuntimeProfileContext(
        None,
        None,
        "unresolved",
        tuple(checked),
        "runtime_profile_not_resolved",
        (
            "ShellForgeAI profile context could not be resolved. Launch through the "
            f"official sfai.cmd wrapper or set {RUNTIME_ROOT_ENV} to the installed runtime root."
        ),
    )
