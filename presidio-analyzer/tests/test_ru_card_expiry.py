"""Explicit card year-month fields, including the real YAML loading path."""

import pytest
from presidio_analyzer import AnalyzerEngine, Pattern
from presidio_analyzer.nlp_engine import NoOpNlpEngine
from presidio_analyzer.predefined_recognizers import RuCardExpiryRecognizer
from presidio_analyzer.recognizer_registry import RecognizerRegistryProvider


@pytest.mark.parametrize(
    "text,value",
    [
        ('🙂 {"card_expiry": "2031-09"}', "2031-09"),
        ("Срок действия карты: 2001-01.", "2001-01"),
        ("card_expiry = '2099-12'", "2099-12"),
        ("card_expiry: 09/31", "09/31"),
    ],
)
def test_card_expiry_has_exact_offsets_and_medium_score(text, value):
    """Expired dates stay sensitive; preceding Unicode uses character offsets."""
    (result,) = RuCardExpiryRecognizer().analyze(text, ["CARD_EXPIRY"])
    assert (result.start, result.end, result.score) == (
        text.index(value),
        text.index(value) + len(value),
        0.4,
    )


@pytest.mark.parametrize(
    "text",
    [
        "card_expiry: 2031-00",
        "card_expiry: 2031-13",
        "card_expiry: 2031-09-12",
        "card_expiry: 2031-09.2",
        "card_expiry: 2031-090",
        "other_card_expiry: 2031-09",
        "release_version: 2031-09",
        "expiry_date: 2031-09",
        "срок действия договора: 2031-09",
        "2031-09",
    ],
)
def test_year_month_without_valid_card_field_does_not_match(text):
    """Do not turn generic dates, versions or invalid months into card data."""
    assert RuCardExpiryRecognizer().analyze(text, ["CARD_EXPIRY"]) == []


def test_card_expiry_yaml_loading_and_explicit_context(tmp_path):
    """The port loads this predefined recognizer through the same provider."""
    config = tmp_path / "recognizers.yaml"
    config.write_text("""
supported_languages: [ru]
recognizers:
  - name: RuCardExpiryRecognizer
    type: predefined
    enabled: true
    supported_languages: [ru]
    country_code: ru
""")
    registry = RecognizerRegistryProvider(conf_file=config).create_recognizer_registry()
    engine = AnalyzerEngine(
        registry=registry,
        supported_languages=["ru"],
        nlp_engine=NoOpNlpEngine(models=[{"lang_code": "ru", "model_name": "none"}]),
    )
    text = "card_expiry: 2031-09"
    (plain,) = engine.analyze(text, "ru")
    (boosted,) = engine.analyze(
        text, "ru", context=["card"], return_decision_process=True
    )
    assert (plain.start, plain.end, plain.score) == (13, 20, 0.4)
    assert boosted.score == 0.75
    assert boosted.analysis_explanation.supportive_context_word == "card"


def test_custom_card_expiry_patterns_remain_authoritative():
    """An explicit user pattern must not acquire additional default matches."""
    recognizer = RuCardExpiryRecognizer(patterns=[Pattern("custom", "fixture", 0.5)])
    assert recognizer.analyze("card_expiry: 2031-09", ["CARD_EXPIRY"]) == []
