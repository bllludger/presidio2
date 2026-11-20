"""Detect the series and number of a Russian internal passport."""

from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer


class RuPassportRecognizer(PatternRecognizer):
    """
    Recognize a complete Russian internal-passport series and number.

    Decree 2267 of 23 December 2023, description of the passport form, item 3,
    specifies four series digits and six number digits:
    https://magord--chel.sudrf.ru/modules.php?name=info_court&rid=3

    Printed 2+2 series groups and common text separators are accepted. A bare
    ten-digit candidate is weaker because it can also be an INN or another ID.
    There is no checksum promotion or assertion that a document was issued.
    Isolated series/numbers, foreign passports and OCR repair are out of scope.

    :param patterns: Override the default patterns.
    :param context: Override passport-specific context words.
    :param supported_language: Language code, ru by default.
    :param supported_entity: Entity type returned for a passport.
    :param name: Optional recognizer instance name.
    """

    COUNTRY_CODE = "ru"

    # Bounded horizontal separators prevent joining numbers across lines.
    _SPACE = r"[ \t\u00a0\u202f]"
    _SERIES = rf"(?:[0-9]{{2}}(?:{_SPACE}{{1,3}}|-)[0-9]{{2}}|[0-9]{{4}})"
    _SEPARATOR = (
        rf"(?:{_SPACE}{{1,3}}(?:№{_SPACE}{{0,3}})?"
        rf"|{_SPACE}{{0,3}}-{_SPACE}{{0,3}}|№{_SPACE}{{0,3}})"
    )
    PATTERNS = [
        Pattern(
            "Russian internal passport, separated (weak)",
            rf"(?<![\w]){_SERIES}{_SEPARATOR}[0-9]{{6}}(?![\w])",
            0.2,
        ),
        Pattern(
            "Russian internal passport, compact (very weak)",
            r"(?<![\w])[0-9]{10}(?![\w])",
            0.05,
        ),
    ]
    CONTEXT = ["паспорт", "паспортные данные", "серия паспорта", "passport"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: str = "RU_PASSPORT",
        name: Optional[str] = None,
    ):
        super().__init__(
            supported_entity=supported_entity,
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            name=name,
        )
