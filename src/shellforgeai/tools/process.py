from __future__ import annotations

import json
import re
from pathlib import Path

from shellforgeai.util.subprocess import run_command

from .base import ToolResult

_SECRET_RE = re.compile(r"(?i)(token|apikey|api_key|secret|password)=\S+")


def top(limit: int = 10) -> ToolResult:
    r = run_command(["ps", "-eo", "pid,ppid,pcpu,pmem,comm", "--sort=-pcpu"])
    out = "\n".join(r.stdout.splitlines()[: limit + 1]) if r.stdout else ""
    return ToolResult(
        tool="process.top",
        command=r.command,
        exit_code=r.exit_code,
        stdout=out,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def find(name: str, exact: bool = False) -> ToolResult:
    r = run_command(["ps", "-eo", "pid,comm,args"])
    if r.exit_code != 0:
        return ToolResult(
            tool=f"process.find {name}",
            command=r.command,
            exit_code=r.exit_code,
            stderr=r.stderr,
            ok=False,
        )
    needles = [name.lower()]
    if name.lower() == "docker":
        needles = ["dockerd", "containerd", "docker-proxy", "rootlesskit"]
    lines = []
    for ln in r.stdout.splitlines():
        low = ln.lower()
        if "shellforgeai" in low and name.lower() != "shellforgeai":
            continue
        comm = low.split()[1] if len(low.split()) > 1 else ""
        matched = any((comm == n if exact else n in low) for n in needles)
        if matched:
            lines.append(ln)
    return ToolResult(
        tool=f"process.find {name}",
        command=r.command,
        stdout="\n".join(lines[:50]),
        stderr="not found" if not lines else "",
        exit_code=0,
        ok=bool(lines),
    )


def snapshot() -> ToolResult:
    r = run_command(["ps", "-eo", "stat="])
    if r.exit_code != 0:
        return ToolResult(
            tool="process.snapshot",
            command=r.command,
            exit_code=r.exit_code,
            stderr=r.stderr,
            ok=False,
        )
    total = running = sleeping = zombies = 0
    for st in r.stdout.splitlines():
        st = st.strip()
        if not st:
            continue
        total += 1
        c = st[0]
        running += c == "R"
        sleeping += c in {"S", "D", "I"}
        zombies += c == "Z"
    return ToolResult(
        tool="process.snapshot",
        stdout=f"processes={total} running={running} sleeping={sleeping} zombies={zombies}",
        ok=True,
    )


def io(limit: int = 10, proc_root: Path = Path("/proc")) -> ToolResult:
    rows: list[dict[str, int | str]] = []
    if not proc_root.exists():
        return ToolResult(
            tool="process.io",
            ok=False,
            exit_code=1,
            stderr="process I/O details unavailable from this context",
        )
    for child in proc_root.iterdir():
        if not child.name.isdigit():
            continue
        try:
            io_text = (child / "io").read_text(errors="ignore")
            comm = (child / "comm").read_text(errors="ignore").strip() or "unknown"
        except OSError:
            continue
        values: dict[str, int] = {}
        for ln in io_text.splitlines():
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            if v.strip().isdigit():
                values[k.strip()] = int(v.strip())
        rows.append(
            {
                "pid": int(child.name),
                "comm": comm,
                "read_bytes": values.get("read_bytes", 0),
                "write_bytes": values.get("write_bytes", 0),
                "cancelled_write_bytes": values.get("cancelled_write_bytes", 0),
            }
        )
    if not rows:
        return ToolResult(
            tool="process.io",
            ok=False,
            exit_code=1,
            stderr="process I/O details unavailable from this context",
        )
    top_w = sorted(rows, key=lambda r: int(r["write_bytes"]), reverse=True)[:limit]
    top_r = sorted(rows, key=lambda r: int(r["read_bytes"]), reverse=True)[:limit]
    summary = (
        f"top_io_write={top_w[0]['comm']} pid={top_w[0]['pid']} write={top_w[0]['write_bytes']}; "
        f"top_io_read={top_r[0]['comm']} pid={top_r[0]['pid']} read={top_r[0]['read_bytes']}"
    )
    return ToolResult(
        tool="process.io",
        stdout=json.dumps({"top_write": top_w, "top_read": top_r}),
        stderr=_SECRET_RE.sub("token=<redacted>", summary),
        ok=True,
    )
