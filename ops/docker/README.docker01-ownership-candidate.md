# Docker01 ownership candidate

`ops/docker/Dockerfile.docker01.ownership-candidate` is a repository-owned review artifact only. It is not the active Docker01 production Dockerfile and must not be copied, applied, or deployed blindly.

The candidate records a safer ownership direction after the Docker01 build-path diagnostic, proposal, preview, and rehearsal work: avoid broad recursive ownership over `/data`, `/home/appuser/.codex`, and `/opt/shellforgeai`; prefer targeted `install -d -o appuser -g appuser ...` runtime directory creation and `COPY --chown=appuser:appuser` for application source ownership where applicable.

Run the static verifier with:

```bash
python3 scripts/docker01_build_path_candidate_verify.py --candidate ops/docker/Dockerfile.docker01.ownership-candidate
python3 scripts/docker01_build_path_candidate_verify.py --candidate ops/docker/Dockerfile.docker01.ownership-candidate --json
python3 scripts/docker01_build_path_candidate_verify.py --candidate ops/docker/Dockerfile.docker01.ownership-candidate --out candidate-verification --json
```

An optional source comparison may read the external Docker01 Dockerfile only when supplied explicitly:

```bash
python3 scripts/docker01_build_path_candidate_verify.py --candidate ops/docker/Dockerfile.docker01.ownership-candidate --source-dockerfile /srv/compose/shellforgeai/Dockerfile --out candidate-verification --json
```

The verifier is static and review-only. It does not edit `/srv/compose/shellforgeai/Dockerfile`, does not edit Compose, does not run Docker, Docker Compose, build, `chown`, `chmod`, `chgrp`, package installs, cleanup, prune, restart, remediation, rollback, or recovery. Any actual Dockerfile/build remediation must be a separate PR or operator-reviewed change. Docker01 build-path investigation alone should not trigger duplicate full pytest runs.

## Ownership handoff packet

After candidate verification, operators can generate a read-only handoff packet that compares the explicitly supplied external Docker01 Dockerfile with this repository-owned candidate:

```bash
python3 scripts/docker01_build_path_ownership_handoff_packet.py --source-dockerfile /srv/compose/shellforgeai/Dockerfile --candidate ops/docker/Dockerfile.docker01.ownership-candidate
python3 scripts/docker01_build_path_ownership_handoff_packet.py --source-dockerfile /srv/compose/shellforgeai/Dockerfile --candidate ops/docker/Dockerfile.docker01.ownership-candidate --out handoff-packet --json
```

The handoff packet writes evidence, a diff, an operator checklist, future-change preflight, and rollback-planning notes only under explicit `--out`. It is not approval, not execution, and not remediation. It does not edit `/srv/compose/shellforgeai/Dockerfile`, edit Compose, run Docker/Compose/build, run `chown`/`chmod`/`chgrp`, install packages, clean up, prune, restart, remediate, roll back, or recover. Any actual Dockerfile/build remediation must remain a separate PR or operator-reviewed change.
