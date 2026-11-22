"""RU masking must preserve complete results, offsets and decision scores."""

from unittest.mock import Mock, patch

import pytest
from presidio_analyzer import (
    AnalyzerEngine,
    IncompleteScan,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
    strict_scan,
)
from presidio_analyzer.predefined_recognizers import GitleaksSecretRecognizer
from presidio_analyzer.predefined_recognizers.generic import iban_recognizer


def test_partial_match_then_timeout():
    """A successful first match must not hide a subsequent timeout."""
    recognizer = PatternRecognizer("TEST", patterns=[Pattern("test", "abc", 0.5)])
    original = recognizer._iter_pattern_matches

    def interrupted(*args):
        yield next(iter(original(*args)))
        raise TimeoutError

    with patch.object(recognizer, "_iter_pattern_matches", interrupted):
        with strict_scan(), pytest.raises(IncompleteScan):
            recognizer.analyze("abc", ["TEST"])
        assert len(recognizer.analyze("abc", ["TEST"])) == 1


@pytest.mark.parametrize("call", ["finditer", "match"])
def test_iban_strict_timeout(call):
    """Both the IBAN search and its country validator can time out."""
    recognizer = iban_recognizer.IbanRecognizer()
    with (
        strict_scan(),
        patch.object(iban_recognizer.re, call, side_effect=TimeoutError),
    ):
        with pytest.raises(IncompleteScan):
            recognizer.analyze("DE89370400440532013000", ["IBAN_CODE"])


def test_allowlist_strict_timeout():
    """Apply the same policy to the final regex allowlist pass."""
    compiled = Mock()
    compiled.search.side_effect = TimeoutError
    result = RecognizerResult("TEST", 0, 3, 0.5)
    with patch("presidio_analyzer.analyzer_engine.re.compile", return_value=compiled):
        with strict_scan(), pytest.raises(IncompleteScan):
            AnalyzerEngine._remove_allow_list([result], ["abc"], "abc", 0, "regex")


def test_rejected_matches_allocate_no_explanations():
    """Keep original and validated scores on accepted results."""
    recognizer = PatternRecognizer("TEST", patterns=[Pattern("test", "a|b|c", 0.5)])
    with (
        patch.object(recognizer, "validate_result", side_effect=[False, True, True]),
        patch.object(
            recognizer, "invalidate_result", side_effect=[False, True, False]
        ) as invalidate,
        patch.object(
            recognizer,
            "build_regex_explanation",
            wraps=recognizer.build_regex_explanation,
        ) as explain,
    ):
        (result,) = recognizer.analyze("abc", ["TEST"])
    assert invalidate.call_count == 3
    assert explain.call_count == 1
    assert (result.start, result.end, result.score) == (2, 3, 1)
    assert result.analysis_explanation.original_score == 0.5
    assert result.analysis_explanation.score == 1


def test_keyword_selection_matches_legacy(tmp_path):
    """Exercise overlaps, Unicode mapping, literals, order and always-on rules."""
    pytest.importorskip("ahocorasick")
    path = tmp_path / "rules.toml"
    path.write_text(
        "".join(
            f'[[rules]]\nid="rule{i}"\nregex="abc"\nkeywords={keys}\n'
            for i, keys in enumerate(
                ['["a"]', '["a+b", "abc"]', '["İ", "Σ"]', "[]", '[""]']
            )
        )
    )
    recognizer = GitleaksSecretRecognizer(config_path=path)
    assert recognizer._keyword_index is not None
    for text in ("", "🙂A+B", "ABC", "İ", "ΟΣ"):
        selected = list(recognizer._candidate_rules(text))
        with patch.object(recognizer, "_keyword_index", None):
            assert selected == list(recognizer._candidate_rules(text))
