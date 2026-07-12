from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from shellforgeai.policy.risk import RiskTier


class Profile(BaseModel):
    name: str
    description: str = ""
    allow_risks: list[RiskTier] = Field(default_factory=list)
    ask_risks: list[RiskTier] = Field(default_factory=list)
    deny_risks: list[RiskTier] = Field(default_factory=list)
    allow_shell_raw: bool = False
    online_allowed: bool = False


def _profile_path(name: str, repo_root: Path) -> Path:
    candidate = repo_root / "config/profiles" / f"{name}.yaml"
    if candidate.exists():
        return candidate
    packaged = Path(str(files("shellforgeai").joinpath(f"config/profiles/{name}.yaml")))
    if packaged.exists():
        return packaged
    return candidate


def load_profile(name: str, repo_root: Path) -> Profile:
    return Profile.model_validate(yaml.safe_load(_profile_path(name, repo_root).read_text()))
