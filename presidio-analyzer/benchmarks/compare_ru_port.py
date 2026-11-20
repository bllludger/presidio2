"""Compare two packaged RU analyzers on identical inputs using the port's Detector."""

import contextlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[3]
PORT = ROOT / "litellm-presidio-port"


def cases():
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


def worker():
    from detector import Detector

    detector = Detector()
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
    for line in sys.stdin:
        start = time.process_time_ns()
        result = detector.detect({"text": data[int(line)][1]})
        elapsed = (time.process_time_ns() - start) / 1e6
        print(json.dumps([result, elapsed]), flush=True)


def run(old, new):
    times = {}
    with contextlib.ExitStack() as stack:
        children = []
        for path in (old, new):
            directory = stack.enter_context(tempfile.TemporaryDirectory())
            with ZipFile(path) as wheel:
                wheel.extractall(directory)
            env = dict(
                os.environ,
                PYTHONHASHSEED="0",
                PYTHONPATH=os.pathsep.join((directory, str(PORT / "profile/src"))),
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
        for i, (group, _) in enumerate(cases()):
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
                dest[n].append(pair[n][1])
    result = {}
    for group, samples in times.items():
        result[group] = {"inputs": len(samples[0])}
        for label, row in zip(("before", "fork"), samples):
            result[group][label] = {
                k: round(v, 3)
                for k, v in {
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
