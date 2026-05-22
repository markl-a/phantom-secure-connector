"""Project-root conftest: ensure imports resolve when pytest is invoked from
any cwd (e.g. `pytest -v` at the project root or from a subdir)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
