"""Disabled debug output must not read the wall clock for every pattern."""

import datetime
import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import pattern_recognizer as module


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO, logging.WARNING])
def test_pattern_timing_obeys_debug_level(level, caplog):
    """Keep DEBUG timing while avoiding wall-clock reads at ordinary levels."""
    caplog.set_level(level, logger=module.logger.name)
    recognizer = PatternRecognizer(
        supported_entity="TEST", patterns=[Pattern("test", "abc", 0.8)]
    )
    now = Mock(return_value=datetime.datetime(2000, 1, 1))
    clock = SimpleNamespace(datetime=SimpleNamespace(now=now))
    with (
        patch.object(module, "datetime", clock),
        patch.object(module.logger, "debug") as debug,
    ):
        results = recognizer.analyze("abc", ["TEST"])
    assert [(r.start, r.end, r.score) for r in results] == [(0, 3, 0.8)]
    assert now.call_count == (2 if level == logging.DEBUG else 0)
    assert debug.call_count == (1 if level == logging.DEBUG else 0)


def test_pattern_timeout_still_logs_warning_without_debug_timing(caplog):
    """Preserve timeout reporting when pattern timing is disabled."""
    caplog.set_level(logging.WARNING, logger=module.logger.name)
    recognizer = PatternRecognizer(
        supported_entity="TEST", patterns=[Pattern("test", "abc", 0.8)]
    )
    clock = SimpleNamespace(
        datetime=SimpleNamespace(now=Mock(side_effect=AssertionError))
    )
    with (
        patch.object(module, "datetime", clock),
        patch.object(recognizer, "_iter_pattern_matches", side_effect=TimeoutError),
        patch.object(module.logger, "warning") as warning,
    ):
        assert recognizer.analyze("abc", ["TEST"]) == []
    warning.assert_called_once()
    assert warning.call_args.kwargs["exc_info"] is True
