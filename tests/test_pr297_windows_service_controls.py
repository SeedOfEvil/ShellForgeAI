import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pr297_windows_service_runtime_records import *  # noqa: F401,F403,E402
