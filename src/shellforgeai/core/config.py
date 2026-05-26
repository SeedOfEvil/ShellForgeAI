import os
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel


class AppCfg(BaseModel):
    name: str
    data_dir: Path
    default_profile: str


class ModelCfg(BaseModel):
    provider: str
    base_url: str = ""
    model: str
    fallback_model: str = "gpt-5.4"
    api_key_env: str = ""
    timeout_seconds: int
    codex_binary: str = "codex"
    codex_sandbox: str = "read-only"
    codex_json: bool = True
    codex_skip_git_repo_check: bool = True
    allow_model_fallback: bool = True


class KnowledgeCfg(BaseModel):
    local_paths: list[str]
    online_enabled: bool


class AuditCfg(BaseModel):
    enabled: bool
    jsonl: str
    artifact_output: str


class PolicyCfg(BaseModel):
    default_action: str
    deny_danger_without_breakglass: bool


class Settings(BaseModel):
    app: AppCfg
    model: ModelCfg
    knowledge: KnowledgeCfg
    audit: AuditCfg
    policy: PolicyCfg


def load_settings(config_path: Path | None = None) -> Settings:
    base = Path(__file__).resolve().parents[3] / "config/default.yaml"
    if not base.exists():
        base = Path(str(files("shellforgeai").joinpath("config/default.yaml")))
    data = yaml.safe_load(base.read_text())
    if config_path and config_path.exists():
        data.update(yaml.safe_load(config_path.read_text()))
    data["app"]["data_dir"] = os.getenv("SHELLFORGEAI_DATA_DIR", data["app"]["data_dir"])
    data.setdefault("model", {})
    data["model"]["provider"] = os.getenv(
        "SHELLFORGEAI_MODEL_PROVIDER", data["model"].get("provider", "openai-codex")
    )
    data["model"]["model"] = os.getenv(
        "SHELLFORGEAI_MODEL_NAME", data["model"].get("model", "gpt-5.5")
    )
    data["model"]["fallback_model"] = os.getenv(
        "SHELLFORGEAI_MODEL_FALLBACK", data["model"].get("fallback_model", "gpt-5.4")
    )
    data["model"]["codex_binary"] = os.getenv(
        "SHELLFORGEAI_CODEX_BINARY", data["model"].get("codex_binary", "codex")
    )
    data["model"]["timeout_seconds"] = int(
        os.getenv("SHELLFORGEAI_CODEX_TIMEOUT_SECONDS", data["model"].get("timeout_seconds", 180))
    )
    data["model"]["codex_skip_git_repo_check"] = os.getenv(
        "SHELLFORGEAI_CODEX_SKIP_GIT_REPO_CHECK", "1"
    ) not in {"0", "false", "False"}
    return Settings.model_validate(data)
