from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "pr298_windows_events_shared", Path(__file__).with_name("test_pr298_windows_events.py")
)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_module)
for _name, _value in vars(_module).items():
    if _name.startswith("test_"):
        globals()[_name] = _value
