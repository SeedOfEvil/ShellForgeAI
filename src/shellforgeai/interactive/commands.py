from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RoutedCommand:
    name: str
    args: str = ""


def _normalize_intent_text(text: str) -> str:
    lowered = re.sub(r"[^a-z0-9/\s]", " ", text.lower())
    lowered = re.sub(r"\s+", " ", lowered).strip()
    fillers = (
        "hey ",
        "hi ",
        "hello ",
        "yo ",
        "please ",
        "can you ",
        "could you ",
        "i think ",
        "so ",
        "uh ",
        "um ",
    )
    changed = True
    while changed:
        changed = False
        for prefix in fillers:
            if lowered.startswith(prefix):
                lowered = lowered[len(prefix) :].strip()
                changed = True
    return lowered


def route_input(text: str) -> RoutedCommand:
    raw = text.strip()
    if not raw:
        return RoutedCommand(name="noop")
    if raw.startswith("/"):
        head, _, tail = raw.partition(" ")
        return RoutedCommand(name=head.lower(), args=tail.strip())

    lowered = _normalize_intent_text(raw)
    perf_intents = [
        "my machine is running slow",
        "my computer is slow",
        "my computer feels slow",
        "computer feels slow",
        "my pc is slow",
        "my pc feels slow",
        "pc feels slow",
        "system feels slow",
        "my system feels slow",
        "machine feels sluggish",
        "machine feels slow",
        "this machine feels slow",
        "this computer feels slow",
        "server is slow",
        "server feels slow",
        "host is slow",
        "host feels slow",
        "why is this machine slow",
        "why is my server slow",
        "high cpu",
        "high memory",
        "high load",
        "performance issue",
        "high io",
        "laggy",
        "hanging",
        "system is crawling",
        "everything is slow",
    ]
    if any(p in lowered for p in perf_intents):
        return RoutedCommand(name="diagnose", args="performance")
    storage_perf_intents = [
        "i think my disk is slow",
        "disk is slow",
        "disk feels slow",
        "storage is slow",
        "drive is slow",
        "filesystem is slow",
        "io is slow",
        "i/o is slow",
        "high io",
        "high disk io",
        "disk performance",
        "storage performance",
        "disk latency",
        "disk lag",
        "writes are slow",
        "reads are slow",
        "disk is dying",
        "drive is dying",
        "disk failing",
        "drive failing",
        "disk health",
        "storage health",
        "nvme issue",
        "ssd issue",
        "hard drive issue",
        "filesystem issue",
        "storage issue",
        "disk slow",
        "disk dying",
    ]
    if any(p in lowered for p in storage_perf_intents):
        return RoutedCommand(name="diagnose", args="storage_performance")
    disk_intents = [
        "how much disk space do we have left",
        "disk space left",
        "free disk space",
        "are we running out of disk",
        "is disk full",
        "disk usage",
        "storage left",
        "how full is the disk",
        "out of space",
        "inode usage",
        "are inodes full",
        "disk is dying",
        "drive is dying",
        "disk failing",
        "drive failing",
        "disk health",
        "storage health",
        "disk errors",
        "hard drive issue",
        "nvme issue",
        "ssd issue",
    ]
    if any(p in lowered for p in disk_intents):
        return RoutedCommand(name="diagnose", args="disk")
    health_intents = [
        "my system is glitchy",
        "computer is acting weird",
        "machine is acting weird",
        "something is wrong with this machine",
        "system health",
        "check this machine",
        "any issue on this machine",
        "any issues on this machine",
        "anything wrong with my computer",
        "anything wrong with this computer",
        "anything wrong with my machine",
        "anything wrong with this machine",
        "anything wrong with my pc",
        "anything wrong with this pc",
        "anything wrong with my server",
        "anything wrong with this server",
        "is my computer having any issue",
        "so is everything okay with my computer",
        "is everything okay with my computer",
        "is anything wrong",
        "is anything wrong with this system",
        "is my computer okay",
        "is my machine okay",
        "is this host okay",
        "is this system healthy",
        "check my computer",
        "check my machine",
        "check this host",
        "check this system",
        "host health",
        "computer health",
        "machine health",
        "do you see any issues",
        "do you see anything wrong",
        "what’s wrong with my computer",
        "what is wrong with my computer",
        "is this host healthy",
        "things are unstable",
        "weird behavior",
        "glitches",
    ]
    if any(p in lowered for p in health_intents):
        return RoutedCommand(name="diagnose", args="health")
    service_intents = [
        "what services this computer is running",
        "what services are running",
        "what is running on this machine",
        "what is this host running",
        "what services are listening",
        "what ports are open",
        "what daemons are running",
        "show running services",
        "list services",
        "list listening services",
        "what apps are running",
        "what is exposed",
        "what is listening on ports",
        "which services are active",
    ]
    if any(p in lowered for p in service_intents):
        return RoutedCommand(name="diagnose", args="services")
    if "is nginx running" in lowered:
        return RoutedCommand(name="diagnose", args="nginx")
    if "is ssh running" in lowered:
        return RoutedCommand(name="diagnose", args="ssh")
    if "is docker running" in lowered:
        return RoutedCommand(name="diagnose", args="docker")
    for prefix, cmd in [
        ("diagnose ", "diagnose"),
        ("research ", "research"),
        ("plan ", "plan"),
        ("inspect host", "inspect_host"),
        ("inspect service ", "inspect_service"),
        ("ask ", "ask"),
    ]:
        if lowered.startswith(prefix):
            return RoutedCommand(name=cmd, args=raw[len(prefix) :].strip())
    return RoutedCommand(name="ask", args=raw)
