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
    log_service_aliases = [
        "nginx",
        "apache",
        "httpd",
        "caddy",
        "ssh",
        "sshd",
        "docker",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "shellforgeai",
    ]
    auth_phrases = [
        "auth failing",
        "auth fail",
        "login failing",
        "logins failing",
        "ssh login failing",
        "ssh failed",
        "ssh failing",
        "sudo failing",
        "sudo failed",
        "permission denied",
        "permision denied",
        "failed password",
        "invalid user",
        "pam error",
        "pam errors",
        "auth log",
        "auth logs",
        "login failed",
    ]
    lab_container_aliases = (
        "missing env",
        "missing-env",
        "restart loop",
        "restart-loop",
        "noisy logs",
        "noisy-logs",
        "bad volume perms",
        "bad-volume-perms",
        "bad network",
        "bad-network",
        "sfai-missing-env",
        "sfai missing env",
        "sfai-restart-loop",
        "sfai restart loop",
        "sfai-noisy-logs",
        "sfai noisy logs",
        "sfai-bad-volume-perms",
        "sfai bad volume perms",
        "sfai-bad-network",
        "sfai bad network",
    )
    if any(alias in lowered for alias in lab_container_aliases) or any(
        alias in raw.lower() for alias in lab_container_aliases
    ):
        return RoutedCommand(name="diagnose", args="docker")
    container_failure_phrases = [
        "why is the app restarting",
        "why is my app restarting",
        "why is the container restarting",
        "why is the container restaring",
        "container restarting",
        "container restaring",
        "why did the container exit",
        "why did the contianer exit",
        "exited container",
        "exited containers",
        "what containers are failing",
        "what containers failing",
        "any container errors",
        "container errors",
        "container error",
        "container is crashing",
        "container is crashng",
        "containers are crashing",
        "is the container healthy",
        "container unhealthy",
        "restart loop",
        "crash loop",
        "crashloop",
        "container crashing",
        "is anything crashing",
        "anything crashing",
        "is anything crasing",
        "is the app crashing",
        "is the app restarting",
        "show container logs",
        "show docker logs",
    ]
    if any(p in lowered for p in container_failure_phrases):
        return RoutedCommand(name="diagnose", args="docker")
    log_phrases = [
        "any errors",
        "any erorrs",
        "any erors",
        "any error",
        "any warnings",
        "any critical errors",
        "check logs",
        "check loggs",
        "show logs",
        "show recent errors",
        "recent errors",
        "recent failures",
        "anything failing",
        "anything crashing",
        "is anything crashing",
        "what do the logs say",
        "look for errors",
        "summarize errors",
        "summarize the errors",
        "summarise errors",
        "check recent failures",
        "why did it fail",
        "why is it failing",
        "is it failng",
        "is it crasing",
        "loggs",
        "log errors",
        "find recent logs",
        "find recent errors",
        "find recent logs and errors",
        "recent logs and errors",
        "show recent logs",
        "find logs",
    ]
    log_storage_phrases = [
        "disk errors",
        "i/o errors",
        "io errors",
        "no space left",
        "filesystem read-only",
        "read-only filesystem",
        "oom killed",
        "oom kill",
    ]
    log_network_error_phrases = [
        "connection refused errors",
        "timeout errors",
        "tls errors",
        "certificate errors",
        "dns errors",
    ]
    delete_log_phrases = [
        "delete logs",
        "clear logs",
        "truncate logs",
        "rotate logs",
        "wipe logs",
        "remove logs",
    ]
    if any(p in lowered for p in delete_log_phrases):
        return RoutedCommand(name="logs_mutation_refused", args=raw)
    if any(p in lowered for p in auth_phrases):
        return RoutedCommand(name="diagnose", args="auth")
    for svc in log_service_aliases:
        if (
            (f"check {svc} logs" in lowered)
            or (f"{svc} logs" in lowered)
            or (f"{svc} errors" in lowered)
            or (f"why is {svc} failing" in lowered)
            or (f"why is {svc} broken" in lowered)
        ):
            return RoutedCommand(name="diagnose", args=f"logs:{svc}")
    if any(p in lowered for p in log_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    if any(p in lowered for p in log_storage_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    if any(p in lowered for p in log_network_error_phrases):
        return RoutedCommand(name="diagnose", args="logs")
    perf_intents = [
        "my machine is running slow",
        "my computer is slow",
        "my computer feels slow",
        "computer feels slow",
        "my pc is slow",
        "my pc feels slow",
        "pc feels slow",
        "system feels slow",
        "system feels sluggish",
        "the system feels sluggish",
        "my system feels slow",
        "server feels sluggish",
        "server feels a bit slow",
        "server feels a bit sluggish",
        "this server feels slow",
        "the server feels a bit slow",
        "computer feels sluggish",
        "it feels sluggish",
        "system is sluggish",
        "server is sluggish",
        "machine is laggy",
        "system is laggy",
        "feels slow",
        "feels laggy",
        "things feel slow",
        "things are slow",
        "the box feels slow",
        "machine feels sluggish",
        "machine feels slow",
        "this machine feels slow",
        "this computer feels slow",
        "server is slow",
        "server feels slow",
        "host is slow",
        "host feels slow",
        "the host feels slow",
        "why is this machine slow",
        "why is my server slow",
        "high cpu",
        "high memory",
        "high load",
        "performance issue",
        "laggy",
        "hanging",
        "system is crawling",
        "everything is slow",
        "device feels slow",
        "device feels sluggish",
        "device feels a bit sluggish",
        "device is slow",
        "device is sluggish",
        "device is laggy",
        "device feels laggy",
        "device feels a bit slow",
        "the device feels a bit slow",
        "device feels a bit laggy",
    ]
    if any(p in lowered for p in perf_intents):
        return RoutedCommand(name="diagnose", args="performance")
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
        "is the system ok",
        "is the system okay",
        "is system ok",
        "is system okay",
        "system ok",
        "system okay",
        "is the host ok",
        "is the host okay",
        "is everything ok",
        "is everything okay",
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
    network_intents = [
        "network status",
        "check network",
        "is networking okay",
        "is this server online",
        "check dns",
        "dns status",
        "dns broken",
        "cannot resolve",
        "resolver issue",
        "firewall status",
        "is port ",
        "can it reach ",
        "can this server reach ",
        "server reach ",
        "sever reach ",
        "box reach ",
        "host reach ",
        "machine reach ",
        "can it connect to ",
        "can it conenct to ",
        "conenct to ",
        "reachable",
        "test port ",
        "tcp connect ",
        "open port ",
        "allow port ",
        "add firewall rule",
        "netwrok status",
        "dns statsu",
        "firwall status",
        "listerning ports",
    ]
    if any(p in lowered for p in network_intents):
        return RoutedCommand(name="diagnose", args="network")
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
    tool_first_ops_hints = [
        ("cpu", "performance"),
        ("memory", "performance"),
        ("load", "performance"),
        ("slow", "performance"),
        ("disk", "disk"),
        ("storage", "disk"),
        ("inode", "disk"),
        ("firewall", "firewall"),
        ("service", "services"),
        ("ports", "services"),
        ("exposed", "services"),
        ("nginx", "nginx"),
        ("docker", "docker"),
        ("ssh", "ssh"),
        ("host health", "health"),
        ("machine health", "health"),
        ("system ok", "health"),
        ("system okay", "health"),
        ("host ok", "health"),
        ("host okay", "health"),
        ("everything ok", "health"),
        ("everything okay", "health"),
    ]
    for token, target in tool_first_ops_hints:
        if token in lowered:
            return RoutedCommand(name="diagnose", args=target)
    return RoutedCommand(name="ask", args=raw)
