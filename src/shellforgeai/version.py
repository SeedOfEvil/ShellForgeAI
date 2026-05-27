from __future__ import annotations

import os
from dataclasses import dataclass

__version__ = "1.0.0"


@dataclass(frozen=True)
class BuildInfo:
    version: str
    git_commit: str | None = None
    git_branch: str | None = None
    github_pr: str | None = None
    build_date: str | None = None

    @property
    def display_version(self) -> str:
        suffix: list[str] = []
        if self.github_pr:
            suffix.append(f"pr{self.github_pr}")
        if self.git_commit:
            suffix.append(f"g{self.git_commit[:7]}")
        return f"{self.version}+{'.'.join(suffix)}" if suffix else self.version

    def build_line(self) -> str:
        parts: list[str] = []
        if self.github_pr:
            parts.append(f"pr={self.github_pr}")
        if self.git_commit:
            parts.append(f"commit={self.git_commit[:7]}")
        if self.git_branch:
            parts.append(f"branch={self.git_branch}")
        if self.build_date:
            parts.append(f"date={self.build_date}")
        return "Build: " + " ".join(parts) if parts else ""


def get_build_info() -> BuildInfo:
    pr = os.getenv("SHELLFORGEAI_BUILD_PR")
    commit = os.getenv("SHELLFORGEAI_BUILD_COMMIT") or os.getenv("GITHUB_SHA")
    branch = (
        os.getenv("SHELLFORGEAI_BUILD_BRANCH")
        or os.getenv("GITHUB_HEAD_REF")
        or os.getenv("GITHUB_REF_NAME")
    )
    date = os.getenv("SHELLFORGEAI_BUILD_DATE")
    return BuildInfo(
        version=__version__, git_commit=commit, git_branch=branch, github_pr=pr, build_date=date
    )
