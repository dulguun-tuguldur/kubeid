# ABOUTME: Shared pytest setup: makes tests/support importable for all test layers.
# ABOUTME: Keeps helper imports (testca) identical in unit, integration and e2e tests.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "support"))
