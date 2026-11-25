"""Quality metrics must distinguish full coverage, exact ranges and overmasking."""
# ruff: noqa: D101,D102,D103

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "evaluate_ru_port", Path(__file__).parents[1] / "benchmarks/evaluate_ru_port.py"
)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_coverage_counts_intersection_not_merely_any_overlap():
    spans = [[1, 3], [4, 7]]
    assert benchmark.covered_length(spans, 2, 6) == 3
    assert benchmark.covered_length(spans, 7, 9) == 0
    assert benchmark.covered_length(spans, 1, 7) == 5


def test_quality_keeps_partial_misses_and_negative_hits_separate():
    row = {
        "case_id": "fixture",
        "entities": [
            {"start": 1, "end": 3, "type": "exact"},
            {"start": 5, "end": 7, "type": "overmasked"},
            {"start": 9, "end": 12, "type": "partial"},
            {"start": 14, "end": 16, "type": "miss"},
        ],
        "negatives": [{"start": 7, "end": 9}],
    }
    report = benchmark.quality(
        [("pii", row)], [(0, [[1, 3], [4, 8], [9, 10]], 0, 0, 0)]
    )
    assert report["datasets"]["pii"] == {
        "cases": 1,
        "cases_masked": 1,
        "labels": 4,
        "fully_covered": 2,
        "exact_span": 1,
        "partially_covered": 1,
        "missed": 1,
        "negative_labels": 1,
        "negative_labels_touched": 1,
    }
    assert [
        (r["type"], r["covered_characters"]) for r in report["incomplete_labels"]
    ] == [("partial", 1), ("miss", 0)]


def test_clean_case_false_positive_count_is_per_case():
    row = {"case_id": "clean", "entities": [], "negatives": []}
    report = benchmark.quality(
        [("negative", row), ("negative", row)],
        [(0, [[1, 3], [5, 7]], 0, 0, 0), (1, [], 0, 0, 0)],
    )
    assert report["datasets"]["negative"]["false_positive_cases"] == 1
