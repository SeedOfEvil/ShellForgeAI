from __future__ import annotations

import getpass
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class WorkspaceTrust:
    path: str
    trusted_at: str
    hostname: str
    user: str
    version: str


class WorkspaceTrustStore:
    def __init__(self, data_dir: Path) -> None:
        self._file = data_dir / "trust" / "workspaces.json"

    def is_trusted(self, workspace: Path) -> bool:
        entries = self._load()
        return str(workspace.resolve()) in entries

    def trust(self, workspace: Path, version: str) -> WorkspaceTrust:
        entries = self._load()
        record = WorkspaceTrust(
            path=str(workspace.resolve()),
            trusted_at=datetime.now(timezone.utc).isoformat(),
            hostname=socket.gethostname(),
            user=getpass.getuser(),
            version=version,
        )
        entries[record.path] = record.__dict__
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        return record

    def _load(self) -> dict[str, dict[str, str]]:
        if not self._file.exists():
            return {}
        return json.loads(self._file.read_text(encoding="utf-8"))
