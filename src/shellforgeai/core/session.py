from __future__ import annotations

import getpass
import socket
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from shellforgeai.core.config import Settings
from shellforgeai.core.profiles import Profile


class SessionContext(BaseModel):
    session_id: str
    started_at: datetime
    user: str
    host: str
    cwd: str
    mode: str
    profile_name: str
    data_dir: Path
    artifact_dir: Path
    config_summary: dict[str, str | bool]
    shellforge_guidance_loaded: bool
    online_enabled: bool
    breakglass: bool


def build_session_context(
    settings: Settings, profile: Profile, mode: str, cwd: Path
) -> SessionContext:
    now = datetime.now(timezone.utc)
    sid = f"sf_{now.strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
    data_dir = Path(settings.app.data_dir).expanduser()
    artifact_dir = data_dir / "artifacts" / sid
    guidance = (cwd / "SHELLFORGE.md").exists()
    return SessionContext(
        session_id=sid,
        started_at=now,
        user=getpass.getuser() if getpass.getuser() else "unknown",
        host=socket.gethostname() or "unknown",
        cwd=str(cwd),
        mode=mode,
        profile_name=profile.name,
        data_dir=data_dir,
        artifact_dir=artifact_dir,
        config_summary={"provider": settings.model.provider, "model": settings.model.model},
        shellforge_guidance_loaded=guidance,
        online_enabled=profile.online_allowed and settings.knowledge.online_enabled,
        breakglass=False,
    )
