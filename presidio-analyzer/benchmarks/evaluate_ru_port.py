"""Evaluate labeled masking quality and local process scaling without logging values.

Run with the port's Python environment. No model API, HTTP service or Redis is used.
Process counts are workers on one host, not independently provisioned replicas.
"""

import argparse
import hashlib
import importlib.metadata
import json
import math
import multiprocessing
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

SOURCES = {
    "pii": "datasets/pii/ru-banking-privacy/critical-250.jsonl",
    "secrets": "datasets/secrets/creddetx/critical-250.jsonl",
    "negative": "datasets/false-positives/curated-hard-negatives-500/cases.jsonl",
}
DETECTOR = None


def initialize(core, port, ready=None):
    """Load one complete profile per process and warm imports/compiled patterns."""
    global DETECTOR
    sys.path[:0] = [core, str(Path(port) / "profile/src")]
    import presidio_analyzer
    from detector import Detector

    if Path(core) not in Path(presidio_analyzer.__file__).resolve().parents:
        raise RuntimeError("wrong analyzer imported")
    DETECTOR = Detector()
    DETECTOR.detect({"text": "ФИО: Иванов Иван Иванович; contact@example.com"})
    if ready is not None:
        ready.put(os.getpid())


def scan(task):
    """Return only spans and measurements; never serialize source values to report."""
    index, text, submitted = task
    start = time.perf_counter()
    cpu = time.process_time()
    spans = DETECTOR.detect({"text": text})
    cpu_ms = (time.process_time() - cpu) * 1000
    end = time.perf_counter()
    previous_end = 0
    for a, b in spans:
        if not 0 <= a < b <= len(text) or a < previous_end:
            raise AssertionError(f"invalid ranges for case index {index}")
        previous_end = b
    return index, spans, cpu_ms, (end - start) * 1000, (start - submitted) * 1000


def covered_length(spans, start, end):
    """Count covered characters in one annotated interval (spans are disjoint)."""
    return sum(max(0, min(b, end) - max(a, start)) for a, b in spans)


def quality(rows, results):
    """Report exact/full coverage separately from explicit negative-span violations."""
    groups = defaultdict(lambda: defaultdict(int))
    misses = []
    for (kind, row), (_, spans, *_timing) in zip(rows, results):
        group = groups[kind]
        group["cases"] += 1
        group["cases_masked"] += bool(spans)
        labels = row.get("entities", [])
        for label in labels:
            a, b = label["start"], label["end"]
            count = covered_length(spans, a, b)
            group["labels"] += 1
            group["fully_covered"] += count == b - a
            group["exact_span"] += [a, b] in spans
            group["partially_covered"] += 0 < count < b - a
            group["missed"] += count == 0
            if count != b - a:
                misses.append(
                    {
                        "dataset": kind,
                        "case_id": row["case_id"],
                        "type": label["type"],
                        "start": a,
                        "end": b,
                        "covered_characters": count,
                    }
                )
        for label in row.get("negatives", []):
            if "start" not in label or "end" not in label:
                raise ValueError("negative label has no offsets")
            group["negative_labels"] += 1
            group["negative_labels_touched"] += bool(
                covered_length(spans, label["start"], label["end"])
            )
        if kind == "negative":
            group["false_positive_cases"] += bool(spans)
    return {"datasets": dict(groups), "incomplete_labels": misses}


def percentile(values, fraction):
    """Return the nearest-rank percentile."""
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def revision(path):
    """Record the base commit of a checked-out repository."""
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def tree_hash(root):
    """Fingerprint runtime source/configuration without recording their contents."""
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and path.suffix in {
            ".py",
            ".yaml",
            ".yml",
            ".toml",
            ".json",
            ".txt",
        }:
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    """Measure correctness once, then identical uncached work with several pools."""
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--core", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--port", type=Path, default=root / "litellm-presidio-port")
    parser.add_argument("--data-root", type=Path, default=root)
    parser.add_argument("--workload", choices=["labeled", "server"], default="labeled")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, nargs="*", default=[1, 2, 5, 10])
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1 or any(n < 1 for n in args.workers):
        parser.error("workers and repeats must be positive")
    rows, hashes = [], {}
    sources = (
        SOURCES
        if args.workload == "labeled"
        else {
            "server": (
                "load-testing/runs/campaign-remaining-20261120/cases-diverse.jsonl"
            )
        }
    )
    for kind, relative in sources.items():
        data = (args.data_root / relative).read_bytes()
        hashes[relative] = hashlib.sha256(data).hexdigest()
        for line in data.splitlines():
            row = json.loads(line)
            if kind == "server":
                row = {"case_id": row["id"], "input": row["text"]}
            for label in row.get("entities", []) + row.get("negatives", []):
                a, b = label["start"], label["end"]
                if not 0 <= a < b <= len(row["input"]):
                    raise ValueError(f"invalid label offsets: {row['case_id']}")
                if "value" in label and row["input"][a:b] != label["value"]:
                    raise ValueError(f"invalid label value: {row['case_id']}")
            rows.append((kind, row))
    core, port = str(args.core.resolve()), str(args.port.resolve())
    initialize(core, port)
    reference = [
        scan((i, row["input"], time.perf_counter())) for i, (_, row) in enumerate(rows)
    ]
    report = {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
            "dependencies": {
                name: importlib.metadata.version(name)
                for name in [
                    "spacy",
                    "regex",
                    "google-re2",
                    "pyahocorasick",
                    "phonenumbers",
                ]
            },
            "core_head": revision(args.core),
            "port_head": revision(args.port),
            "dataset_sha256": hashes,
            "core_source_sha256": tree_hash(args.core / "presidio_analyzer"),
            "port_profile_sha256": tree_hash(args.port / "profile"),
            "workload": args.workload,
        },
        "input_bytes": {
            "total": sum(len(row["input"].encode()) for _, row in rows),
            "max": max(len(row["input"].encode()) for _, row in rows),
            "cases": len(rows),
        },
        "quality": quality(rows, reference),
        "scaling": [],
        "scope": "Local spawned workers; uncached Detector calls; no HTTP/Redis/LLM. "
        "Finite queued batch, not steady-state open-loop RPS. "
        "Labels may be incomplete.",
    }
    context = multiprocessing.get_context("spawn")
    for count in args.workers:
        ready = context.Queue()
        init_start = time.perf_counter()
        with context.Pool(count, initialize, (core, port, ready)) as pool:
            for _ in range(count):
                ready.get(timeout=120)
            startup = time.perf_counter() - init_start
            start = time.perf_counter()
            tasks = [
                (i, row["input"], start)
                for _ in range(args.repeats)
                for i, (_, row) in enumerate(rows)
            ]
            measurements = list(pool.imap(scan, tasks, chunksize=1))
            elapsed = time.perf_counter() - start
        ready.close()
        mismatches = sum(
            result[1] != reference[result[0]][1] for result in measurements
        )
        if mismatches:
            raise AssertionError(f"{mismatches} worker outputs differ")
        cpu = [result[2] for result in measurements]
        scan_wall = [result[3] for result in measurements]
        queue = [result[4] for result in measurements]
        report["scaling"].append(
            {
                "workers": count,
                "cases": len(measurements),
                "startup_seconds": startup,
                "elapsed_seconds": elapsed,
                "blocks_per_second": len(measurements) / elapsed,
                "cpu_ms_per_block": sum(cpu) / len(cpu),
                "cpu_seconds": sum(cpu) / 1000,
                "scan_wall_p95_ms": percentile(scan_wall, 0.95),
                "scan_wall_p99_ms": percentile(scan_wall, 0.99),
                "batch_queue_p95_ms": percentile(queue, 0.95),
                "mismatches": mismatches,
            }
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(
            f"{count} workers: {len(measurements) / elapsed:.1f} blocks/s; "
            "identical spans",
            flush=True,
        )
    # Also support quality-only runs with --workers and no values.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report["quality"]["datasets"], ensure_ascii=False))


if __name__ == "__main__":
    main()
