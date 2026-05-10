from __future__ import annotations

from pathlib import Path

from .base import ToolResult

COMMON = {
    "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"],
    "docker": ["/etc/docker/daemon.json", "docker-compose.yml", "compose.yaml"],
    "ssh": ["/etc/ssh/sshd_config"],
}


def find_common(target: str) -> ToolResult:
    t = (target or "").lower().strip()
    paths = COMMON.get(t, [])
    rows = []
    for p in paths:
        pp = Path(p)
        rows.append(f"{p}: {'exists' if pp.exists() else 'missing'}")
    return ToolResult(tool="config.find_common", stdout="\n".join(rows) or "no known config hints")


def recent_changes() -> ToolResult:
    roots = [Path("/etc"), Path("/opt"), Path("/srv")]
    found: list[tuple[float, str]] = []
    for r in roots:
        if not r.exists():
            continue
        for p in r.rglob("*"):
            if len(found) >= 50:
                break
            if p.is_file() and any(
                x in p.name for x in [".conf", ".ini", ".yaml", ".yml", ".json", ".env"]
            ):
                st = p.stat()
                found.append((st.st_mtime, f"{p} mtime={int(st.st_mtime)} size={st.st_size}"))
    found.sort(key=lambda x: x[0], reverse=True)
    return ToolResult(tool="config.recent_changes", stdout="\n".join([x[1] for x in found[:50]]))
