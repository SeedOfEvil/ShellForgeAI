from shellforgeai.util.subprocess import run_command

from .base import ToolResult


def usage() -> ToolResult:
    r = run_command(["df", "-hP"])
    return ToolResult(
        tool="disk.usage",
        command=r.command,
        exit_code=r.exit_code,
        stdout=r.stdout,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def inodes() -> ToolResult:
    r = run_command(["df", "-ihP"])
    return ToolResult(
        tool="disk.inodes",
        command=r.command,
        exit_code=r.exit_code,
        stdout=r.stdout,
        stderr=r.stderr,
        duration_ms=r.duration_ms,
        ok=r.exit_code == 0,
    )


def top_dirs(path: str = "/", max_entries: int = 8) -> ToolResult:
    r = run_command(["du", "-x", "-d", "1", "-B1", path], timeout=8)
    if r.exit_code != 0:
        return ToolResult(
            tool="disk.top_dirs",
            command=r.command,
            exit_code=r.exit_code,
            stderr="top directory usage unavailable or timed out safely",
            ok=False,
        )
    rows = []
    for ln in r.stdout.splitlines():
        parts = ln.split("\t")
        if len(parts) == 2 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1]))
    rows = sorted(rows, reverse=True)[:max_entries]
    summary_parts = [f"{p}={b / 1024 / 1024 / 1024:.1f}GiB" for b, p in rows if p != path]
    return ToolResult(
        tool="disk.top_dirs",
        command=r.command,
        stdout="\n".join(f"{b}\t{p}" for b, p in rows),
        stderr="top_dirs: " + " ".join(summary_parts),
        ok=True,
    )
