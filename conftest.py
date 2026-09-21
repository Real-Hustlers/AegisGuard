"""Repository-wide pytest bootstrap for local package imports.

The Windows pytest console-script launcher may omit the repository root from
sys.path. Pytest loads this root conftest for tests anywhere in the repository,
including backend/analyzer/test and tests/platform.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
