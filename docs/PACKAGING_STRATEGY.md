# Packaging and Install Strategy

## Goal

Operators should eventually be able to run ShellForgeAI without manually preparing Python every time. Packaging and install work should make local execution predictable on supported hosts while preserving ShellForgeAI's read-only default, evidence-first routing, and explicit confirmation gates.

## Current problem

Python setup is friction for operators, especially outside a prepared developer container. Windows Server 2025 test VM support needs predictable install and run behavior so a local operator can start ShellForgeAI consistently. Packaging must not weaken safety boundaries or add hidden mutation paths.


### Read-only install/runtime preflight (implemented by PR304)

PR304 implements the observation-only Windows runtime-integrity preflight stage with `scripts/windows_runtime_integrity.py` and saved-artifact validation with `scripts/windows_runtime_integrity_acceptance.py`. This stage checks a staged source root, explicit runtime/profile root, durable versus canonical wrapper content, embedded Python existence, explicit Scripts entry point existence, and bounded `~hellforgeai*` site-package residue without installing, repairing, cleaning, deleting, or executing the wrapper/entry point. Packaging, installer, updater, frozen executable, and cleanup decisions remain deferred.

## Options considered

### Installer/bootstrap script

Pros: simple, transparent, operator-friendly, and able to check for or install prerequisites such as Python or `uv` when explicitly requested by the operator.

Cons: still depends on an external runtime and often network access unless everything is bundled or pre-staged.

### uv-managed runtime

Pros: fast, reproducible, useful for developer and operator workflows, and able to pin Python and dependencies.

Cons: still needs `uv` installation or bootstrap before it can manage the runtime.

### PyInstaller frozen executable

Pros: gives a single-executable feel and avoids a manual Python install for many operators.

Cons: larger artifacts, antivirus false positives are possible, packaging complexity increases, and builds are platform-specific.

### Nuitka/frozen native-ish build

Pros: can provide native-ish packaging and potentially better performance.

Cons: build complexity is higher and compiler/toolchain requirements are a maintenance burden.

### Windows embeddable Python

Pros: gives ShellForgeAI a controlled Python runtime without requiring system Python.

Cons: dependency handling can be awkward and the bundle creates a packaging maintenance burden.

### pipx / standard Python package

Pros: conventional Python CLI installation model that is familiar to Python users.

Cons: still expects Python and `pipx` or `pip` readiness on the operator host.

## Recommended staged approach

1. Short term: document and test a `uv`/virtualenv developer-operator install path.
2. Near term: add a platform detector and install preflight that reports prerequisites without mutating the host.
3. Next: build the Windows read-only doctor/status prototype after platform detection exists.
4. Packaging spike: compare `uv`-managed runtime versus PyInstaller on the Windows Server 2025 test VM.
5. Later: decide whether to ship a frozen executable, Windows embeddable Python bundle, or explicit installer/bootstrap path.

Do not build packaged binaries in PR258. Do not add installer scripts in PR258. Do not fetch packages or call network in PR258. This PR is design and docs tests only.

Packaging must preserve the read-only default and explicit confirmation gates. Install/run convenience must not create a mutation bypass.

## Windows packaging considerations

Windows packaging should prioritize predictable local execution on the Windows Server 2025 test VM before any broader Windows support claim. The package should not lower PowerShell execution policy automatically, enable WinRM, install services silently, modify firewall rules, or assume domain-wide permissions.

Candidate follow-up spikes should compare:

- `uv`-managed runtime with pinned Python/dependencies.
- PyInstaller frozen executable behavior on Windows Server 2025.
- Windows embeddable Python bundle maintenance and dependency handling.
- A transparent installer/bootstrap that requires explicit operator approval for each prerequisite action.

## Linux packaging considerations

Linux remains the current core ShellForgeAI lane. Packaging work should keep the Docker/Linux operator workflow intact, support predictable virtualenv or `uv` setup, and avoid service restarts, package installs, or Docker/Compose mutation unless a future installer explicitly asks and receives operator approval outside ShellForgeAI runtime behavior.

## Security and safety constraints

Packaging and installation must preserve these constraints:

- No secret reads.
- No auth-cache scraping.
- No hidden remote execution.
- No silent installation.
- No auto-update without explicit operator control.
- No mutation bypass through an installer.
- No lowering PowerShell execution policy automatically.
- No WinRM enablement.
- No natural-language command execution.
- No autonomous self-healing, automatic remediation, automatic rollback, or automatic recovery claims.

## Proposed implementation sequence

1. Land this PR258 strategy without package builds or installer implementation.
2. Add docs and tests for a supported `uv`/virtualenv local development and operator path.
3. Add a read-only install preflight that reports missing prerequisites without installing them.
4. Add platform detection and graceful unsupported output.
5. Prototype Windows read-only doctor/status.
6. Run a controlled packaging spike comparing `uv` runtime management, PyInstaller, Nuitka, and Windows embeddable Python.
7. Choose one supported packaging lane only after evidence, operator review, and safety-gate review.
