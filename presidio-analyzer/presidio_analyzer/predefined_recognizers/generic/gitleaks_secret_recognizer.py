"""Native, RE2-based execution of the bundled Gitleaks configuration.

Semantics ported from gitleaks v8.30.1 config/ and detect/ (MIT, Zachary Rice).
See conf/GITLEAKS_LICENSE and https://github.com/gitleaks/gitleaks/tree/v8.30.1.
No subprocess, Git access, decoding, network call or secret logging at runtime.
"""

import bisect
import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

import tomllib

from presidio_analyzer import AnalysisExplanation, EntityRecognizer, RecognizerResult


def _lower(value):
    # Go strings.ToLower uses one rune per input rune (not Python's expanded İ).
    return "".join(c.lower()[0] for c in value)


@lru_cache(maxsize=8)
def _compile_config(source):
    try:
        import re2
    except ImportError as exc:
        raise ImportError(
            "Install presidio-analyzer[gitleaks] to enable RE2 secrets"
        ) from exc
    options = re2.Options()
    options.log_errors = False

    def compile_regex(pattern):
        return re2.compile(pattern.encode(), options=options)

    def allowlist(value):
        data = {k.lower(): v for k, v in value.items()}
        unknown = set(data) - {
            "description",
            "condition",
            "regexes",
            "paths",
            "stopwords",
            "regextarget",
            "commits",
        }
        if unknown:
            raise ValueError(
                f"Unsupported Gitleaks allowlist fields: {sorted(unknown)}"
            )
        condition = data.get("condition", "OR").upper()
        if condition not in {"AND", "OR", "&&", "||"}:
            raise ValueError("Gitleaks allowlist condition must be AND or OR")
        target = data.get("regextarget", "secret") or "secret"
        if target not in {"secret", "match", "line"}:
            raise ValueError("Gitleaks regexTarget must be secret, match or line")
        for key in ("paths", "regexes"):
            values = data.get(key, [])
            data[key] = (
                compile_regex("(?:" + "|".join(values) + ")") if values else None
            )
        data["stopwords"] = tuple(_lower(s) for s in data.get("stopwords", []))
        data["commits"] = frozenset(_lower(s.strip()) for s in data.get("commits", []))
        if not any(data[k] for k in ("paths", "regexes", "stopwords", "commits")):
            raise ValueError("Gitleaks allowlist must contain at least one check")
        data["and"] = condition in {"AND", "&&"}
        data["target"] = target
        return data

    config = tomllib.loads(source.decode("utf-8"))
    unknown = set(config) - {"title", "description", "allowlist", "rules"}
    if unknown:
        raise ValueError(f"Unsupported Gitleaks config fields: {sorted(unknown)}")
    global_allow = [allowlist(config["allowlist"])] if config.get("allowlist") else []
    rules = {}
    for raw in config.get("rules", []):
        data = {k.lower(): v for k, v in raw.items()}
        unknown = set(data) - {
            "id",
            "description",
            "regex",
            "path",
            "entropy",
            "secretgroup",
            "keywords",
            "tags",
            "allowlist",
            "allowlists",
        }
        if unknown:
            raise ValueError(f"Unsupported Gitleaks rule fields: {sorted(unknown)}")
        if not data.get("id") or not data.get("regex"):
            raise ValueError("Gitleaks text recognizer requires rule id and regex")
        if data.get("allowlist") and data.get("allowlists"):
            raise ValueError("Cannot combine Gitleaks allowlist and allowlists")
        data["pattern"] = compile_regex(data["regex"])
        group = data.get("secretgroup", 0)
        if not isinstance(group, int) or not 0 <= group <= data["pattern"].groups:
            raise ValueError("Gitleaks secretGroup is outside regex capture groups")
        data["group"] = group
        data["path_pattern"] = compile_regex(data["path"]) if data.get("path") else None
        data["keywords"] = tuple(_lower(k) for k in data.get("keywords", []))
        data["allows"] = [allowlist(a) for a in data.get("allowlists", [])]
        if data.get("allowlist"):
            data["allows"].append(allowlist(data["allowlist"]))
        # Gitleaks Translate stores rules in a map: the final duplicate wins.
        rules[data["id"]] = data
    return tuple(rules.values()), tuple(global_allow)


def _location(raw, start, end, newlines):
    """Port Gitleaks location(), including its newline-start line slicing."""
    first = bisect.bisect_right(newlines, start)
    if first == len(newlines):
        # Preserve Gitleaks' slice from byte zero for the unterminated last line.
        previous = newlines[-1]
        line_end = end
        while line_end < len(raw) and raw[line_end] not in (10, 13):
            line_end += 1
        return first, first, start - previous + 1, end - previous, 0, line_end

    previous = newlines[first - 1] if first else 0
    last = bisect.bisect_left(newlines, end)
    last_column = 0
    if end and last < len(newlines):
        last_column = end - (newlines[last - 1] if last else 0)
    # Empty matches at a newline can end on the preceding line.
    if last < first or last == len(newlines):
        last = first
    return (
        first,
        last,
        start - previous + 1,
        last_column,
        previous,
        max(newlines[last], end),
    )


@dataclass(frozen=True)
class GitleaksFinding:
    """Value-free finding with Python secret offsets and Go byte coordinates."""

    rule_id: str
    start: int
    end: int
    match_byte_start: int
    match_byte_end: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    entropy: float
    secret_sha256: str
    match_sha256: str
    line_sha256: str


class GitleaksSecretRecognizer(EntityRecognizer):
    """
    Execute the bundled 200-entry / 199-effective-rule Gitleaks snapshot.

    Includes fragment keywords, secret-group extraction, entropy, global and
    rule allowlists, stopword substrings, paths, AND/OR, line/match/secret targets,
    inline gitleaks:allow and generic-rule precedence. Reference: v8.30.1.
    Text-only mode has an empty path, as Gitleaks Fragment does. Pass file_path
    in request metadata to apply file-dependent rules and exclusions.
    Only the exact text fragment is scanned: no Git traversal or decoding.

    :param config_path: Optional replacement TOML; unsupported features fail.
    :param supported_language: Language code; rules themselves are not linguistic.
    :param supported_entity: Entity returned, SECRET by default.
    :param name: Optional registry name.
    :param context: Accepted for loader compatibility; no score boosting is used.
    """

    requires_raw_text = True

    def __init__(
        self,
        config_path: Optional[str] = None,
        supported_language="ru",
        supported_entity="SECRET",
        name=None,
        context=None,
    ):
        self.config_path = (
            Path(config_path)
            if config_path
            else Path(__file__).parents[2] / "conf/gitleaks-source.toml"
        )
        self.entity = supported_entity
        super().__init__(
            supported_entities=[supported_entity],
            supported_language=supported_language,
            name=name,
            context=[],
        )

    def load(self):
        """Load and compile the TOML using optional RE2; never log its values."""
        source = self.config_path.read_bytes()
        self.source_sha256 = hashlib.sha256(source).hexdigest()
        self.rules, self.allowlists = _compile_config(source)

    @staticmethod
    def _allowed(
        allowlists, path, windows_path, commit, secret=None, match=None, line=None
    ):
        for a in allowlists:
            checks = []
            if a["commits"]:
                checks.append(bool(commit) and _lower(commit) in a["commits"])
            if a["paths"]:
                checks.append(
                    any(
                        p and a["paths"].search(p.encode()) is not None
                        for p in (path, windows_path)
                    )
                )
            if secret is None:
                # AND lists with content checks must be evaluated after matching.
                if a["and"] and (a["regexes"] or a["stopwords"]):
                    continue
            else:
                # OR path/commit exclusions were already handled before regexes.
                if not a["and"]:
                    checks = []
                target = {"secret": secret, "match": match, "line": line}[a["target"]]
                if a["regexes"]:
                    checks.append(
                        bool(target) and a["regexes"].search(target) is not None
                    )
                if a["stopwords"]:
                    lowered = _lower(secret.decode())
                    checks.append(
                        bool(secret) and any(w in lowered for w in a["stopwords"])
                    )
            if all(checks) if a["and"] else any(checks):
                return True
        return False

    def _candidate_rules(self, text):
        lowered = _lower(text)
        for rule in self.rules:
            if not rule["keywords"] or any(key in lowered for key in rule["keywords"]):
                yield rule

    def detect(self, text, *, file_path="", windows_file_path="", commit=""):
        """Return per-rule findings before Presidio merges duplicate SECRET spans."""
        if file_path and file_path == str(self.config_path):
            return []
        raw = text.encode("utf-8")
        if self._allowed(self.allowlists, file_path, windows_file_path, commit):
            return []
        newlines = None
        byte_offsets = None
        ascii_text = text.isascii()
        findings = []
        for r in self._candidate_rules(text):
            if r["path_pattern"] and not any(
                p and r["path_pattern"].search(p.encode())
                for p in (file_path, windows_file_path)
            ):
                continue
            if self._allowed(r["allows"], file_path, windows_file_path, commit):
                continue
            for full in r["pattern"].finditer(raw):
                match = full.group().strip(b"\n")
                match_end = full.start() + len(match)
                if newlines is None:
                    newlines = [i for i, c in enumerate(raw) if c == 10] or [len(raw)]
                loc = _location(raw, full.start(), match_end, newlines)
                line = raw[loc[4] : loc[5]]
                if b"gitleaks:allow" in line:
                    continue
                sub = r["pattern"].search(match)
                group = r["group"]
                if not group and sub:
                    group = next((i for i, v in enumerate(sub.groups(), 1) if v), 0)
                secret = sub.group(group) if sub else match
                secret = secret or b""
                if group and sub and sub.start(group) >= 0:
                    secret_start = (
                        full.start()
                        + len(full.group())
                        - len(full.group().lstrip(b"\n"))
                        + sub.start(group)
                    )
                else:
                    secret_start = (
                        full.start()
                        + len(full.group())
                        - len(full.group().lstrip(b"\n"))
                    )
                counts = Counter(secret.decode())
                entropy = (
                    -sum(
                        (n / len(secret)) * math.log2(n / len(secret))
                        for n in counts.values()
                    )
                    if secret
                    else 0.0
                )
                if r.get("entropy", 0) and entropy <= r["entropy"]:
                    continue
                if self._allowed(
                    self.allowlists,
                    file_path,
                    windows_file_path,
                    commit,
                    secret,
                    match,
                    line,
                ) or self._allowed(
                    r["allows"],
                    file_path,
                    windows_file_path,
                    commit,
                    secret,
                    match,
                    line,
                ):
                    continue
                start = secret_start
                end = start + len(secret)
                if not ascii_text:
                    if byte_offsets is None:
                        byte_offsets = [0]
                        for char in text:
                            byte_offsets.append(byte_offsets[-1] + len(char.encode()))
                    start = bisect.bisect_left(byte_offsets, start)
                    end = bisect.bisect_left(byte_offsets, end)
                findings.append(
                    GitleaksFinding(
                        r["id"],
                        start,
                        end,
                        full.start(),
                        match_end,
                        *loc[:4],
                        entropy,
                        hashlib.sha256(secret).hexdigest(),
                        hashlib.sha256(match).hexdigest(),
                        hashlib.sha256(line).hexdigest(),
                    )
                )
        # Gitleaks filter(): a specialized rule suppresses generic findings with
        # contained secret text on the same start line, even at another offset.
        return [
            f
            for f in findings
            if not (
                "generic" in f.rule_id.lower()
                and any(
                    "generic" not in other.rule_id.lower()
                    and other.start_line == f.start_line
                    and text[f.start : f.end] in text[other.start : other.end]
                    for other in findings
                )
            )
        ]

    def analyze(self, text, entities, nlp_artifacts=None):
        """Analyze a raw text fragment without a filename."""
        return self.analyze_with_metadata(text, entities, nlp_artifacts, {})

    def analyze_with_metadata(self, text, entities, nlp_artifacts=None, metadata=None):
        """Apply per-request file context without changing the registry instance."""
        if self.entity not in entities:
            return []
        metadata = metadata or {}
        path = metadata.get("file_path", "")
        windows_path = metadata.get("windows_file_path", "")
        if "\\" in path:
            windows_path, path = path, path.replace("\\", "/")
        findings = self.detect(
            text,
            file_path=path,
            windows_file_path=windows_path,
            commit=metadata.get("commit", ""),
        )
        return [
            RecognizerResult(
                self.entity,
                f.start,
                f.end,
                0.5,
                analysis_explanation=AnalysisExplanation(
                    self.name,
                    0.5,
                    pattern_name=f.rule_id,
                    textual_explanation=(
                        "Gitleaks snapshot match after RE2, entropy and "
                        "exclusions; not a probability"
                    ),
                ),
                recognition_metadata={
                    "recognizer_name": self.name,
                    "recognizer_identifier": self.id,
                    "gitleaks_rule_id": f.rule_id,
                    "config_sha256": self.source_sha256,
                },
            )
            for f in findings
            if f.end > f.start
        ]
