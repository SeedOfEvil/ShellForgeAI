# OPS

Operator smoke tests and runbook tips.

## Interactive smoke test

```bash
shellforgeai
```

Inside the REPL:

```text
/doctor
/health
/model
/tools
/audit
diagnose disk
diagnose network
ask what services are listening on this host?
/pending
/exit
```

## Non-interactive smoke test

```bash
shellforgeai doctor
shellforgeai inspect host
shellforgeai tools list
shellforgeai diagnose disk --save-plan
shellforgeai audit list
```

## Restricted containers

In restricted containers, the Codex CLI may emit `bwrap`/namespace errors.
Treat that as a provider sandbox limitation, not a host failure: ShellForgeAI
still collects evidence via its typed read-only tools, and `model doctor`
will report whether `codex` is reachable.

## Safety reminders

- `apply` is validation-only.
- Service-impacting actions are described as approval-required / operator-run.
  ShellForgeAI does not execute them.
- Mutation is blocked or asks regardless of workspace trust.
