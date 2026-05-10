import json

from shellforgeai.core.ask_routing import evidence_brief
from shellforgeai.core.diagnose import Finding
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem


def test_evidence_brief_includes_docker_problem_rows() -> None:
    payload = {
        "failing": [
            {
                "name": "sfai-restart-loop",
                "state": "restarting",
                "log_themes": {"simulated_crash": True},
            },
            {
                "name": "sfai-missing-env",
                "state": "exited",
                "log_themes": {"missing_required_setting": True},
            },
        ],
        "noisy": [
            {"name": "sfai-bad-network", "state": "running", "log_themes": {"dns_failure": True}},
        ],
        "healthy": [{"name": "sfai-healthy-web", "state": "running", "log_themes": {}}],
    }
    item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        title="docker summary",
        summary="ok",
        content=json.dumps(payload),
        ok=True,
    )
    brief = evidence_brief([Finding(severity="warning", title="x", detail="y")], [item])
    names = [r["name"] for r in brief.get("docker_problem_rows", [])]
    assert "sfai-restart-loop" in names
    assert "sfai-bad-network" in names
