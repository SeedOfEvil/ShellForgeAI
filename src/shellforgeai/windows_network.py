"""Bounded read-only Windows network interface collector."""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable
from typing import Any

from shellforgeai.platform_detection import PlatformInfo, detect_platform

MAX_INTERFACES = 32
MAX_ADDRESSES_PER_INTERFACE = 16
MODE = "windows_network"
METHOD = "psutil_net_if_addrs_stats_counters"
UNSUPPORTED_NEXT_SAFE_COMMAND = "shellforgeai platform doctor --json"
LIMITATION = (
    "No packet capture, socket inventory, route-table lookup, DNS lookup, remote probing, "
    "or network mutation was performed. Counters are cumulative snapshots when available."
)

_SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    "powershell_executed": False,
    "winrm_used": False,
    "remote_execution": False,
    "packet_capture": False,
    "socket_inventory": False,
    "dns_lookup": False,
    "route_table_lookup": False,
    "network_mutation": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "secret_read": False,
    "auth_cache_read": False,
    "model_called": False,
    "network_call": False,
}

NetworkSources = tuple[
    Callable[[], dict[str, Any]], Callable[[], dict[str, Any]], Callable[[], dict[str, Any]]
]


def _psutil_sources() -> NetworkSources:
    try:
        import psutil  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - exercised via injection
        raise RuntimeError("psutil network interface APIs are unavailable") from exc
    return psutil.net_if_addrs, psutil.net_if_stats, lambda: psutil.net_io_counters(pernic=True)


def _norm(value: Any) -> str:
    return str(value or "").casefold()


def _safe_int(value: Any, warnings: list[str], field: str) -> int | None:
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        warnings.append(f"{field} unavailable or malformed")
        return None
    if number < 0:
        warnings.append(f"{field} negative value ignored")
        return None
    return number


def classify_ip_address(address: str) -> tuple[str, bool, bool]:
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return "unknown", False, False
    if ip.is_loopback:
        scope = "loopback"
    elif ip.is_link_local:
        scope = "link_local"
    elif ip.is_private:
        scope = "private"
    elif ip.is_multicast:
        scope = "multicast"
    elif ip.is_global:
        scope = "global"
    elif ip.is_unspecified:
        scope = "unspecified"
    elif ip.is_reserved:
        scope = "reserved"
    else:
        scope = "unknown"
    return scope, bool(ip.is_loopback), bool(ip.is_link_local)


def _family_name(family: Any) -> str | None:
    if family == socket.AF_INET:
        return "ipv4"
    if family == socket.AF_INET6:
        return "ipv6"
    return None


def _duplex_name(value: Any) -> str | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return {0: "unknown", 1: "full", 2: "half"}.get(number)


def _address_record(raw: Any) -> dict[str, Any] | None:
    family = _family_name(getattr(raw, "family", None))
    if family is None:
        return None
    address = str(getattr(raw, "address", "") or "")
    scope, is_loopback, is_link_local = classify_ip_address(address)
    return {
        "family": family,
        "address": address,
        "netmask": getattr(raw, "netmask", None),
        "broadcast": getattr(raw, "broadcast", None),
        "scope": scope,
        "is_loopback": is_loopback,
        "is_link_local": is_link_local,
    }


def _counter_record(raw: Any, warnings: list[str]) -> dict[str, int | None] | None:
    if raw is None:
        return None
    mapping = {
        "bytes_sent": "bytes_sent",
        "bytes_recv": "bytes_received",
        "packets_sent": "packets_sent",
        "packets_recv": "packets_received",
        "errin": "input_errors",
        "errout": "output_errors",
        "dropin": "input_drops",
        "dropout": "output_drops",
    }
    return {
        out: _safe_int(getattr(raw, attr, None), warnings, out) for attr, out in mapping.items()
    }


def windows_network_payload(
    info: PlatformInfo | None = None,
    *,
    sources: NetworkSources | None = None,
    max_interfaces: int = MAX_INTERFACES,
    max_addresses_per_interface: int = MAX_ADDRESSES_PER_INTERFACE,
) -> dict[str, Any]:
    info = info or detect_platform()
    if info.system != "windows":
        return windows_network_unsupported_payload(info)
    warnings: list[str] = []
    try:
        addrs_func, stats_func, counters_func = sources or _psutil_sources()
        addrs = dict(addrs_func() or {})
        stats = dict(stats_func() or {})
        counters = dict(counters_func() or {})
    except Exception as exc:
        return windows_network_error_payload(info, reason=str(exc))

    names = sorted(set(addrs) | set(stats) | set(counters), key=_norm)
    total = len(names)
    selected = names[: max(0, int(max_interfaces))]
    truncated = len(selected) < total
    interfaces: list[dict[str, Any]] = []
    ipv4 = ipv6 = up = down = with_errors = 0
    for name in selected:
        iwarnings: list[str] = []
        stat = stats.get(name)
        if stat is None:
            iwarnings.append("interface stats unavailable")
        raw_addresses = [_address_record(a) for a in addrs.get(name, [])]
        addresses = sorted(
            (a for a in raw_addresses if a is not None),
            key=lambda a: (a["family"], _norm(a["address"]), _norm(a.get("netmask"))),
        )
        address_total = len(addresses)
        if address_total > max_addresses_per_interface:
            iwarnings.append("interface address output truncated")
        addresses = addresses[:max_addresses_per_interface]
        ipv4 += sum(1 for a in addresses if a["family"] == "ipv4")
        ipv6 += sum(1 for a in addresses if a["family"] == "ipv6")
        is_up = getattr(stat, "isup", None) if stat is not None else None
        if is_up is True:
            up += 1
        elif is_up is False:
            down += 1
        counter = _counter_record(counters.get(name), iwarnings)
        if counter and any(
            (counter.get(k) or 0) > 0
            for k in ("input_errors", "output_errors", "input_drops", "output_drops")
        ):
            with_errors += 1
        interfaces.append(
            {
                "name": str(name),
                "is_up": is_up,
                "mtu": _safe_int(getattr(stat, "mtu", None), iwarnings, "mtu")
                if stat is not None
                else None,
                "speed_mbps": _safe_int(getattr(stat, "speed", None), iwarnings, "speed_mbps")
                if stat is not None
                else None,
                "duplex": _duplex_name(getattr(stat, "duplex", None)) if stat is not None else None,
                "addresses": addresses,
                "addresses_total": address_total,
                "addresses_returned": len(addresses),
                "addresses_truncated": address_total > len(addresses),
                "counters": counter,
                "warnings": iwarnings,
            }
        )
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "ok",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "method": METHOD,
        "caps": {
            "max_interfaces": max_interfaces,
            "max_addresses_per_interface": max_addresses_per_interface,
        },
        "summary": {
            "interfaces_total": total,
            "interfaces_returned": len(interfaces),
            "interfaces_up": up,
            "interfaces_down": down,
            "ipv4_addresses": ipv4,
            "ipv6_addresses": ipv6,
            "interfaces_with_errors": with_errors,
            "truncated": truncated,
        },
        "interfaces": interfaces,
        "limitations": [LIMITATION],
        "warnings": warnings,
        "errors": [],
        "safety": dict(_SAFETY),
    }


def windows_network_error_payload(
    info: PlatformInfo | None = None, *, reason: str
) -> dict[str, Any]:
    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "error",
        "platform": {"system": info.system},
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "interfaces_total": 0,
            "interfaces_returned": 0,
            "interfaces_up": 0,
            "interfaces_down": 0,
            "ipv4_addresses": 0,
            "ipv6_addresses": 0,
            "interfaces_with_errors": 0,
            "truncated": False,
        },
        "interfaces": [],
        "limitations": [LIMITATION],
        "warnings": [],
        "errors": [reason],
        "safety": dict(_SAFETY),
    }


def windows_network_unsupported_payload(info: PlatformInfo | None = None) -> dict[str, Any]:
    info = info or detect_platform()
    return {
        "schema_version": 1,
        "mode": MODE,
        "status": "unsupported",
        "platform": {"system": info.system},
        "reason": "Windows network interfaces are only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "interfaces_total": 0,
            "interfaces_returned": 0,
            "interfaces_up": 0,
            "interfaces_down": 0,
            "ipv4_addresses": 0,
            "ipv6_addresses": 0,
            "interfaces_with_errors": 0,
            "truncated": False,
        },
        "interfaces": [],
        "limitations": [LIMITATION],
        "warnings": [],
        "errors": [],
        "safety": dict(_SAFETY),
        "next_safe_command": UNSUPPORTED_NEXT_SAFE_COMMAND,
    }


def render_windows_network_text(payload: dict[str, Any]) -> str:
    lines = ["Windows network", f"Status: {payload.get('status', 'unknown')}"]
    summary = payload.get("summary") or {}
    lines.append(
        "Interfaces: "
        f"{summary.get('interfaces_total', 0)} total, "
        f"{summary.get('interfaces_up', 0)} up, "
        f"{summary.get('interfaces_down', 0)} down"
    )
    lines.append(
        "Addresses: "
        f"{summary.get('ipv4_addresses', 0)} IPv4, "
        f"{summary.get('ipv6_addresses', 0)} IPv6"
    )
    if payload.get("status") == "unsupported":
        lines.append(str(payload.get("reason", "Windows network collection is unavailable.")))
    for iface in payload.get("interfaces", []):
        lines.append("")
        lines.append(str(iface.get("name", "unknown")))
        state = (
            "up"
            if iface.get("is_up") is True
            else "down"
            if iface.get("is_up") is False
            else "unknown"
        )
        lines.append(f"  State: {state}")
        if iface.get("speed_mbps") is not None:
            lines.append(f"  Speed: {iface.get('speed_mbps')} Mbps")
        if iface.get("mtu") is not None:
            lines.append(f"  MTU: {iface.get('mtu')}")
        for addr in iface.get("addresses", [])[:MAX_ADDRESSES_PER_INTERFACE]:
            suffix = f"/{addr.get('netmask')}" if addr.get("netmask") else ""
            lines.append(f"  {str(addr.get('family')).upper()}: {addr.get('address')}{suffix}")
        counters = iface.get("counters") or {}
        if counters:
            errors = (counters.get("input_errors") or 0) + (counters.get("output_errors") or 0)
            drops = (counters.get("input_drops") or 0) + (counters.get("output_drops") or 0)
            lines.append(f"  Errors/drops: {errors}/{drops}")
        for warning in iface.get("warnings", []):
            lines.append(f"  Warning: {warning}")
    if summary.get("truncated"):
        lines.append("Warning: interface output truncated.")
    lines.append(f"Read-only: {str(payload.get('read_only', False)).lower()}")
    lines.append(
        "Limitations: no packet capture, sockets, routes, DNS lookup, "
        "remote probes, or network changes."
    )
    return os.linesep.join(lines)
