# Example SHELLFORGE.md

This file is an example of a workspace-local knowledge file. ShellForgeAI
indexes lines from this file (and other paths in `knowledge.local_paths`)
for `shellforgeai research <query>`.

## Example notes

- nginx address already in use: usually another process holds :80 / :443.
  Check `ss -ltnp 'sport = :80'` before reloading.
- Disk full on `/var/log`: rotate or vacuum journals with
  `journalctl --vacuum-size=200M` (run by the operator, not ShellForgeAI).
- Service flapping after deploy: check `systemctl status <unit>` and
  `journalctl -u <unit> --since '15m ago' --no-pager`.
