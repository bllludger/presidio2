"""Context optimizations preserve offsets, ordering and custom hook semantics."""
# ruff: noqa: D101,D102,D103

import random
from types import SimpleNamespace

import pytest
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer


def test_token_lookup_matches_linear_scan_at_every_unicode_boundary():
    """Include gaps, substring starts, punctuation and out-of-range offsets."""
    rng = random.Random(24011)
    for _ in range(30):
        tokens, offsets = [], []
        end = 0
        for _ in range(60):
            token = rng.choice(["Иван", "🙂", "e\u0301", "123-45", ":", "x"])
            start = end + rng.randrange(4)
            tokens.append(token)
            offsets.append(start)
            end = start + len(token)
        for start in range(-1, end + 2):
            expected = next(
                (
                    i
                    for i, token in enumerate(tokens)
                    if offsets[i] == start or start < offsets[i] + len(token)
                ),
                None,
            )
            if expected is None:
                with pytest.raises(ValueError, match="token at index"):
                    LemmaContextAwareEnhancer._find_index_of_match_token(
                        "sensitive fixture", start, tokens, offsets
                    )
            else:
                assert (
                    LemmaContextAwareEnhancer._find_index_of_match_token(
                        "", start, tokens, offsets
                    )
                    == expected
                )


def test_empty_tokens_error_does_not_include_matched_value():
    with pytest.raises(ValueError) as error:
        LemmaContextAwareEnhancer._find_index_of_match_token("private-value", 0, [], [])
    assert "private-value" not in str(error.value)


class Passthrough:
    def enhance_using_context(self, **kwargs):
        return kwargs["raw_results"]


def finding(rule, start):
    return RecognizerResult(
        "TEST",
        start,
        start + 1,
        0.4,
        recognition_metadata={RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: rule.id},
    )


def test_noop_hooks_preserve_recognizer_order_and_finding_identity():
    rules = [
        PatternRecognizer("TEST", deny_list=["x"], name=name) for name in ("a", "b")
    ]
    engine = SimpleNamespace(context_aware_enhancer=Passthrough())
    raw = [finding(rules[1], 2), finding(rules[0], 0), finding(rules[1], 3)]
    result = AnalyzerEngine._enhance_using_context(engine, "xxxx", raw, None, rules)
    assert [r.start for r in result] == [0, 2, 3]
    assert result[0] is raw[1]
    assert [r.start for r in raw] == [2, 0, 3]


def test_custom_hook_keeps_others_and_metadata_mutation_visible_to_next_hook():
    rules = [
        PatternRecognizer("TEST", deny_list=["x"], name=name) for name in ("a", "b")
    ]
    raw = [finding(rules[0], 0), finding(rules[1], 2)]
    calls = []

    def custom(**kwargs):
        calls.append([r.start for r in kwargs["other_raw_recognizer_results"]])
        result = kwargs["raw_recognizer_results"][0]
        result.recognition_metadata[RecognizerResult.RECOGNIZER_IDENTIFIER_KEY] = rules[
            1
        ].id
        result.score = 0.9
        return [result]

    rules[0].enhance_using_context = custom
    engine = SimpleNamespace(context_aware_enhancer=Passthrough())
    result = AnalyzerEngine._enhance_using_context(engine, "xxxx", raw, None, rules)
    assert calls == [[2]]
    assert [(r.start, r.score) for r in result] == [(0, 0.9), (0, 0.9), (2, 0.4)]


def test_no_recognizers_do_not_inspect_unrelated_result_metadata():
    engine = SimpleNamespace(context_aware_enhancer=Passthrough())
    raw = [RecognizerResult("TEST", 0, 1, 0.4)]
    assert AnalyzerEngine._enhance_using_context(engine, "x", raw, None, []) == []
