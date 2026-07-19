# Profiles

Profiles map ShellForgeAI's risk classes to one of `allow`, `ask`, or
`deny`. They live in `config/profiles/` and are selected by name with
`--profile` or via `app.default_profile` in config.

## Risk classes

| Class | Examples |
| --- | --- |
| `read` | `host_info`, `journalctl --no-pager`, `systemctl status`, disk/network introspection. |
| `change` | Safe local config or file changes (still validation-only under the current guarded V1 boundary). |
| `service` | Service restarts and reloads. |
| `system` | Package installs, kernel-level changes. |
| `danger` | Destructive operations (e.g. `rm -rf`, partition writes). |

## Built-in profiles

| Profile | allow | ask | deny | shell raw | online |
| --- | --- | --- | --- | --- | --- |
| `inspect` (default) | `read` | `change` | `service`, `system`, `danger` | no | no |
| `assisted` | `read`, `change` | `service`, `system` | `danger` | no | yes |
| `lab-direct` | `read`, `change`, `service`, `system` | `danger` | — | yes | yes |
| `prod-readonly` | `read` | — | `change`, `service`, `system`, `danger` | no | no |

`apply` is validation-only across all profiles under the current guarded V1 boundary — `allow_*`
risk classes describe what the policy *would* permit, not what the runtime
will execute.

## Custom profile

Create a YAML file under `config/profiles/` (or anywhere on disk and pass
`--profile path`):

```yaml
name: my-profile
description: my-profile
allow_risks: [read]
ask_risks: [change]
deny_risks: [service, system, danger]
allow_shell_raw: false
online_allowed: false
```
