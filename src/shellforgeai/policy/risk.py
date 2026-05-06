from enum import StrEnum


class RiskTier(StrEnum):
    read = "read"
    change = "change"
    service = "service"
    system = "system"
    danger = "danger"


class PolicyAction(StrEnum):
    allow = "allow"
    ask = "ask"
    deny = "deny"
