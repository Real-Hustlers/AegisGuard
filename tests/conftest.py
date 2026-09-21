"""Pytest bootstrap for repository-local imports.

The Windows pytest console-script launcher may not place the repository root on
sys.path. Add it explicitly before test modules are imported so tests can use
the same backend package imports as normal application execution.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
