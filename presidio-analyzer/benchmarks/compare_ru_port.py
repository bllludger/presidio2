"""Compare two RU builds using a direct Detector or native Gitleaks call."""

import contextlib
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[3]
PORT = ROOT / "litellm-presidio-port"


def cases():
    """Yield each input with its deterministic workload label."""
    sources = {
        "pii": "datasets/pii/ru-banking-privacy/critical-250.jsonl",
        "secrets": "datasets/secrets/creddetx/critical-250.jsonl",
        "negatives": "datasets/false-positives/curated-hard-negatives-500/cases.jsonl",
        "server": "load-testing/runs/campaign-remaining-20261120/cases-diverse.jsonl",
    }
    for name, path in sources.items():
        for line in (ROOT / path).read_text().splitlines():
            row = json.loads(line)
            text = row.get("input", row.get("text"))
            size = len(text.encode())
            group = (
                f"server-{8 if size < 16000 else 32}KB" if name == "server" else name
            )
            yield group, text
            if name == "secrets":
                yield "core-gitleaks-corpus", text

    for i in range(60):
        code = "".join(
            f"def normalize_{i}_{j}(value): return value.strip()\n" for j in range(180)
        )
        yield "core-gitleaks-code", code
        yield "clean-code", code
        yield (
            "one-secret",
            code + 'token = "ghp_' + "Aj9Kdx4Fbz0Q3emcY1qv58tu7ZLgWpfahBRs" + '"',
        )
        yield (
            "many-candidates",
            ("ИНН 1234567891, email example@example.com\n" * 120) + str(i),
        )


def worker():
    """Time a direct call and emit findings for pairwise verification."""
    from detector import Detector
    from presidio_analyzer.predefined_recognizers import GitleaksSecretRecognizer

    detector = Detector()
    secrets = GitleaksSecretRecognizer()
    assert (
        Path(sys.argv[2]).resolve()
        in Path(sys.modules["presidio_analyzer"].__file__).resolve().parents
    )
    assert any(
        getattr(r, "_without_dictionary", None) is not None
        for r in detector.engine.registry.recognizers
    )
    detector.detect({"text": "Тестовый контакт example@example.com"})
    data = list(cases())
    try:
        from presidio_analyzer import strict_scan
    except ImportError:
        strict_scan = contextlib.nullcontext
    for line in sys.stdin:
        group, text = data[int(line)]
        start = time.process_time_ns()
        wall = time.perf_counter_ns()
        with strict_scan():
            if group.startswith("core-gitleaks-"):
                result = [vars(finding) for finding in secrets.detect(text)]
            else:
                result = detector.detect({"text": text})
        latency = (time.perf_counter_ns() - wall) / 1e6
        elapsed = (time.process_time_ns() - start) / 1e6
        print(json.dumps([result, elapsed, latency]), flush=True)


def run(old, new):
    """Alternate two isolated Python processes and verify every result."""
    times = {}
    with contextlib.ExitStack() as stack:
        children = []
        sizes = {}
        for path in (old, new):
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            if Path(path).is_dir():
                directory = str(Path(path).resolve())
            else:
                with ZipFile(path) as wheel:
                    wheel.extractall(directory)
            env = dict(
                os.environ,
                PYTHONHASHSEED="0",
                PYTHONPATH=os.pathsep.join(
                    (
                        directory,
                        str(PORT / "profile/src"),
                        os.environ.get("PYTHONPATH", ""),
                    )
                ),
            )
            p = subprocess.Popen(
                [sys.executable, __file__, "worker", directory],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                env=env,
            )
            stack.enter_context(p)
            stack.callback(p.stdin.close)
            children.append(p)
        for i, (group, text) in enumerate(cases()):
            sizes[group] = sizes.get(group, 0) + len(text.encode())
            pair = [None, None]
            for n in (i % 2, 1 - i % 2):
                p = children[n]
                print(i, file=p.stdin, flush=True)
                pair[n] = json.loads(p.stdout.readline())
            if pair[0][0] != pair[1][0]:
                raise AssertionError(
                    f"Different masking ranges for {group}, input index {i}"
                )
            dest = times.setdefault(group, [[], []])
            for n in range(2):
                dest[n].append(pair[n][1:])
    result = {}
    for group, samples in times.items():
        result[group] = {"inputs": len(samples[0])}
        for label, records in zip(("before", "fork"), samples):
            row, wall = zip(*records)
            result[group][label] = {
                k: round(v, 3)
                for k, v in {
                    "cpu_ms_per_MB": sum(row) * 1_000_000 / sizes[group],
                    "wall_p95_ms": sorted(wall)[math.ceil(0.95 * len(wall)) - 1],
                    "mean_ms": statistics.mean(row),
                    "p50_ms": statistics.median(row),
                    "p95_ms": sorted(row)[math.ceil(0.95 * len(row)) - 1],
                }.items()
            }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if sys.argv[1] == "worker":
        worker()
    else:
        run(*sys.argv[1:])
