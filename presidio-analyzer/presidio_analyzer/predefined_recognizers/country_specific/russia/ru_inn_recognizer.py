"""Detect Russian tax identifiers using bounded patterns and check digits."""

from typing import List, Optional

import regex as re

from presidio_analyzer import Pattern, PatternRecognizer


class RuInnRecognizer(PatternRecognizer):
    """
    Recognize ten-digit organization and twelve-digit individual Russian INN.

    Structure (FTS): https://www.nalog.gov.ru/eng/inn/
    Check-digit weights are independently documented in python-stdnum:
    https://github.com/arthurdejong/python-stdnum/blob/master/stdnum/ru/inn.py
    Weighted sums use modulo 11 then modulo 10. Both personal check digits
    must match. Invalid checksums and all-zero placeholders are discarded.
    No tax-authority assignment or registry existence is verified.

    A valid checksum does not promote confidence to 1.0. Post-check scores
    are at least 0.2 for ten digits (needs context at threshold 0.4), and 0.4
    for twelve digits. Context enhancement still belongs to the analyzer.

    :param patterns: Override the default INN patterns.
    :param context: Override INN-specific context words.
    :param supported_language: Language code, ru by default.
    :param supported_entity: Entity type returned for an INN.
    :param name: Optional recognizer instance name.
    """

    COUNTRY_CODE = "ru"
    _HSPACE = r"[ \t\u00a0\u202f]"
    _SEP = rf"(?:{_HSPACE}{{1,3}}|-)"
    # Do not extract a suffix/prefix from a longer grouped number, e.g. a card.
    _START = rf"(?<![\w-])(?<![0-9]{_SEP})"
    _END = rf"(?![\w-])(?!{_SEP}[0-9])"
    PATTERNS = [
        Pattern(
            "Russian explicitly labelled compact INN (medium)",
            rf"(?<=\b(?:инн|inn)[\"']?{_HSPACE}{{0,3}}"
            rf"[:=]{_HSPACE}{{0,3}}[\"']?)"
            rf"[0-9]{{10}}(?:[0-9]{{2}})?{_END}",
            0.4,
        ),
        Pattern(
            "Russian INN compact (very weak)",
            rf"{_START}[0-9]{{10}}(?:[0-9]{{2}})?{_END}",
            0.05,
        ),
        Pattern(
            "Russian INN grouped 4+4+4 (weak)",
            rf"{_START}[0-9]{{4}}{_SEP}[0-9]{{4}}{_SEP}[0-9]{{4}}{_END}",
            0.1,
        ),
        Pattern(
            "Russian INN grouped 4+6 or 4+6+2 (weak)",
            rf"{_START}[0-9]{{4}}{_SEP}[0-9]{{6}}"
            rf"(?:{_SEP}[0-9]{{2}})?{_END}",
            0.1,
        ),
        Pattern(
            "Russian INN grouped 4+3+3 (weak)",
            rf"{_START}[0-9]{{4}}{_SEP}[0-9]{{3}}{_SEP}[0-9]{{3}}{_END}",
            0.1,
        ),
        Pattern(
            "Russian INN grouped in pairs (weak)",
            rf"{_START}[0-9]{{2}}(?:{_SEP}[0-9]{{2}}){{4,5}}{_END}",
            0.1,
        ),
    ]
    CONTEXT = ["инн", "inn", "идентификационный номер налогоплательщика"]
    _WEIGHTS_10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
    _WEIGHTS_11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    _WEIGHTS_12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: str = "RU_INN",
        name: Optional[str] = None,
    ):
        super().__init__(
            supported_entity=supported_entity,
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            name=name,
        )

    @staticmethod
    def _digits(value: str) -> str:
        return re.sub(r"[ \t\u00a0\u202f-]", "", value)

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Discard bad checksums; never use the base class's 1.0 promotion."""
        digits = self._digits(pattern_text)
        if not re.fullmatch(r"(?:[0-9]{10}|[0-9]{12})", digits):
            return False
        if set(digits) == {"0"}:
            return False
        checks = (
            ((9, self._WEIGHTS_10),)
            if len(digits) == 10
            else ((10, self._WEIGHTS_11), (11, self._WEIGHTS_12))
        )
        for index, weights in checks:
            total = sum(int(digits[i]) * weight for i, weight in enumerate(weights))
            if total % 11 % 10 != int(digits[index]):
                return False
        return None

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        """Assign bounded evidence scores after mandatory checksum pruning."""
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        for result in results:
            length = len(self._digits(text[result.start : result.end]))
            result.score = max(result.score, 0.4 if length == 12 else 0.2)
            explanation = result.analysis_explanation
            # This is recognizer evidence; the analyzer adds context separately.
            explanation.original_score = result.score
            explanation.score = result.score
            explanation.textual_explanation += (
                f"; {length}-digit INN checksum passed; "
                "bounded evidence score, no registry lookup"
            )
        return results
