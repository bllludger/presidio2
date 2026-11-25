"""Exercise lazy imports in a fresh interpreter before other tests import spaCy."""

import os
from pathlib import Path
import subprocess
import sys
import unittest


class LazyImportSdkTests(unittest.TestCase):
    def test_sdk_compatibility_in_fresh_interpreter(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONPATH=str(root))
        subprocess.run(
            [sys.executable, str(root / "benchmarks/check_lazy_import_sdk.py")],
            env=environment,
            check=True,
            timeout=60,
            capture_output=True,
            text=True,
        )
