# SHELLFORGE workspace knowledge

`SHELLFORGE.md` is a workspace-local knowledge file that ShellForgeAI
searches when you run `shellforgeai research <query>` (and during the
`/research` interactive command).

Drop runbooks, known-issue notes, and host-specific context here. Lines
matching the query are returned as snippets along with their file/line
locations.

ShellForgeAI also searches paths listed in `knowledge.local_paths`
(default: `./SHELLFORGE.md`, `./docs`, `/opt/runbooks`, `/usr/share/doc`).
