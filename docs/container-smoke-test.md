# Container smoke test

Validate ShellForgeAI in Docker with read-only ops behavior and optional Codex model assist.

## Basic runtime smoke
```bash
cd /srv/compose/shellforgeai
sudo docker exec -it shellforgeai shellforgeai doctor
sudo docker exec -it shellforgeai shellforgeai inspect host
sudo docker exec -it shellforgeai shellforgeai tools list
sudo docker exec -it shellforgeai shellforgeai diagnose disk --save-plan
sudo docker exec -it shellforgeai shellforgeai audit list
```

## Codex install (Debian container)
```bash
sudo docker exec -u 0 -it shellforgeai sh -lc '
mkdir -p /var/lib/apt/lists/partial
apt-get update
apt-get install -y --no-install-recommends nodejs npm ca-certificates
npm install -g @openai/codex
command -v codex
codex --version
'
```

## Codex auth + model smoke
```bash
sudo docker exec -it shellforgeai codex login --device-auth
sudo docker exec -it shellforgeai shellforgeai model doctor
sudo docker exec -it shellforgeai shellforgeai model test
sudo docker exec -it shellforgeai shellforgeai ask "In one sentence, what is ShellForgeAI?"
sudo docker exec -it shellforgeai shellforgeai diagnose disk --model --save-plan
sudo docker exec -it shellforgeai shellforgeai diagnose network --model --save-plan
```

## Apply safety test
```bash
sudo docker exec -it shellforgeai shellforgeai apply /data/artifacts/<session-id>/plan.json
```
Expected: apply execution is intentionally disabled.

## Persistent Codex auth volume
Never commit `.codex/auth.json`; treat it as a password.

```yaml
services:
  shellforgeai:
    volumes:
      - ./data:/data
      - ./codex-home:/root/.codex
```

Check actual container home:
```bash
sudo docker exec -it shellforgeai sh -lc 'echo $HOME; whoami; id'
```

## Dockerfile snippet
```dockerfile
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && npm install -g @openai/codex \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
```

## Interactive smoke

Run `shellforgeai`, then `/doctor`, `/model`, `/tools`, `diagnose disk`, and `/exit`.

- Note: In restricted containers, Codex may emit bwrap/namespace errors; treat as provider sandbox limitation, not host failure. ShellForgeAI still collects evidence via typed read-only tools.
\n## Interactive guardrails update\n- Interactive mode is not a shell; shell-looking pasted input is blocked unless explicitly prefixed with ask explain/review.\n- Slash commands are deterministic and unknown slash commands do not call the model.\n- Added /health and /audit latest interactive commands.\n- Apply remains validation-only; workspace trust does not bypass mutation policy.\n- Service-impacting commands must be described as approval-required/operator-run.\n

## Context-first + Codex provider note (PR)
- ShellForgeAI runtime auto-runs approved typed read-only collectors for recognized ops intents (disk/performance/health/firewall/service).
- In current architecture, Codex is used as a model/provider for synthesis; ShellForgeAI tools are executed by the ShellForgeAI runtime.
- Runtime context bundles are the immediate solution; optional MCP exposure of read-only tools is a future path.
- Arbitrary shell remains blocked in interactive mode.
- Mutating/service-impacting actions remain blocked or approval-required/operator-run.
- apply remains validation-only in this alpha.
## Update: streaming synthesis and service-discovery routing\n- Interactive diagnostics now show a post-collection synthesis status and stream model answers when supported.\n- Service-discovery questions (services/listening/ports/nginx/ssh/docker) route to read-only evidence collection before synthesis.\n- Safety boundaries are unchanged: no arbitrary shell execution, no destructive execution, and apply remains validation-only.\n
