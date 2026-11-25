"""A baseline must reject drift and malformed evidence before comparison."""
# ruff: noqa: D101,D102,D103

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "freeze_baseline", Path(__file__).parents[1] / "benchmarks/freeze_baseline.py"
)
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in baseline.ROOTS:
            path = self.root / name / "nested/input.dat"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"original")
        self.manifest = {
            "runtime": {"python": "test"},
            "files": {
                name: baseline.file_inventory(self.root / name)
                for name in baseline.ROOTS
            },
        }
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))

    def test_unchanged_snapshot_verifies(self):
        with patch.object(baseline, "runtime", return_value={"python": "test"}):
            self.assertEqual(baseline.verify(self.root), self.manifest)

    def test_capture_never_overwrites_existing_snapshot(self):
        before = baseline.file_inventory(self.root)
        with self.assertRaises(FileExistsError):
            baseline.capture(SimpleNamespace(workspace=self.root, snapshot=self.root))
        self.assertEqual(baseline.file_inventory(self.root), before)

    def test_added_removed_modified_and_renamed_inputs_rejected(self):
        for operation in ("add", "remove", "modify", "rename"):
            for name in baseline.ROOTS:
                with self.subTest(operation=operation, root=name):
                    original = self.root / name / "nested/input.dat"
                    extra = original.with_name("extra.so")
                    if operation == "add":
                        extra.write_bytes(b"native")
                    elif operation == "remove":
                        original.unlink()
                    elif operation == "modify":
                        original.write_bytes(b"changed")
                    else:
                        original.rename(extra)
                    with self.assertRaisesRegex(ValueError, "input drift"):
                        baseline.verify(self.root, check_runtime=False)
                    extra.unlink(missing_ok=True)
                    original.write_bytes(b"original")

    def test_generated_bytecode_does_not_invalidate_snapshot(self):
        path = self.root / "core/__pycache__/module.cpython.pyc"
        path.parent.mkdir()
        path.write_bytes(b"generated")
        baseline.verify(self.root, check_runtime=False)

    def test_dependency_discovery_is_independent_of_frozen_source_paths(self):
        with patch.object(baseline.metadata, "distributions", return_value=[]) as find:
            with patch.object(baseline.sys, "path", ["injected-source"]):
                baseline.runtime()
            find.assert_called_once_with(path=baseline.PACKAGE_SEARCH_PATH)

    def test_dependency_drift_rejected(self):
        with patch.object(baseline, "runtime", return_value={"python": "changed"}):
            with self.assertRaisesRegex(ValueError, "runtime drift"):
                baseline.verify(self.root)

    def test_wheel_and_native_bytes_are_included(self):
        root = self.root / "port"
        for name in ("package.whl", "native.so", "rules.toml"):
            path = root / name
            path.write_bytes(b"one")
            old = baseline.file_inventory(root)
            path.write_bytes(b"two")
            self.assertNotEqual(old, baseline.file_inventory(root))

    def test_corpus_validates_unicode_offsets_and_unique_ids(self):
        path = self.root / "corpus.jsonl"
        row = {
            "case_id": "one",
            "input": "Я😀!",
            "entities": [{"start": 1, "end": 2, "value": "😀"}],
        }
        path.write_text(json.dumps(row) + "\n")
        self.assertEqual(baseline.read_corpus(path), [row])
        path.write_text((json.dumps(row) + "\n") * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            baseline.read_corpus(path)
        for label in (
            {"start": 1, "end": 5},
            {"start": 1, "end": 2, "value": "!"},
            {"start": True, "end": 2},
        ):
            row["entities"] = [label]
            path.write_text(json.dumps(row))
            with self.assertRaises(ValueError):
                baseline.read_corpus(path)

    def test_replay_cannot_mix_variants_or_manifests(self):
        expected = {"variant": "core", "manifest_sha256": "a", "outputs_sha256": "b"}
        baseline.check_reference(expected, "core", "a", "b")
        for variant, manifest in (("installed", "a"), ("core", "c")):
            with self.assertRaisesRegex(ValueError, "incompatible"):
                baseline.check_reference(expected, variant, manifest, "b")
        with self.assertRaisesRegex(AssertionError, "outputs changed"):
            baseline.check_reference(expected, "core", "a", "changed")


if __name__ == "__main__":
    unittest.main()
