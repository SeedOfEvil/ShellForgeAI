## Summary

- 

## Validation

- [ ] `ruff format .`
- [ ] `ruff check .`
- [ ] `pytest -q`
- [ ] `python -m compileall src`
- [ ] `mypy src/shellforgeai tests` (required when production code changes)

## Documentation impact

- [ ] AGENTS.md checked
- [ ] OPS.md checked
- [ ] README.md checked
- [ ] SHELLFORGE.md checked
- [ ] architecture.md checked
- [ ] cli.md checked
- [ ] codex-integration.md checked
- [ ] interactive-mode.md checked
- [ ] model-providers.md checked
- [ ] north-star.md checked
- [ ] profiles.md checked
- [ ] roadmap.md checked
- [ ] safety.md checked
- [ ] tools.md checked
- [ ] No docs update required, with reason

### Required mappings

- If tools/collectors changed, `docs/tools.md` must be checked.
- If safety/apply/mutation behavior changed, `docs/safety.md` must be checked.
- If model/Codex/provider behavior changed, `docs/codex-integration.md` and `docs/model-providers.md` must be checked.
- If REPL commands or natural-language routing changed, `docs/interactive-mode.md` and `docs/cli.md` must be checked.
- If architecture/runtime layout changed, `docs/architecture.md` must be checked.
- If project direction changed, `docs/north-star.md` and `docs/roadmap.md` must be checked.
