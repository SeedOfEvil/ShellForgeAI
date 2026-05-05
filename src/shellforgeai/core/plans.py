from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class PlanStepStatus(str, Enum):
    planned = "planned"


class PlanStep(BaseModel):
    step_id: str
    title: str
    description: str
    tool: str | None = None
    args: dict[str, str | int | bool] | None = None
    risk: str = "read"
    destructive: bool = False
    status: PlanStepStatus = PlanStepStatus.planned


class Plan(BaseModel):
    plan_id: str
    goal: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str
    risk: str = "read"
    steps: list[PlanStep]
    requires_approval: bool = False
    notes: list[str] = Field(default_factory=list)
