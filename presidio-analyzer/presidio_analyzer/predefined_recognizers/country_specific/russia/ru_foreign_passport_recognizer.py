"""Detect Russian passports used for international travel."""

from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer


class RuForeignPassportRecognizer(PatternRecognizer):
    """
    Recognize a Russian international-passport series and number (2+7 digits).

    The Ministry of Foreign Affairs specification records the series and number
    as nine digits; the following MRZ check digit is a separate field:
    https://warsaw.kdmid.ru/documents/Prikaz_12.02.2020_%E2%84%962114.pdf

    Accept compact, 2+7 and locally observed 2+4+3 text representations. Do not
    infer validity from the series or invent a checksum for the nine digits.
    Full MRZ parsing and isolated components are excluded. The numeric shape
    alone cannot establish the issuing country or distinguish every document.

    :param patterns: Override the default patterns.
    :param context: Override passport-specific context words.
    :param supported_language: Language code, ru by default.
    :param supported_entity: Entity type returned for a passport.
    :param name: Optional recognizer instance name.
    """

    COUNTRY_CODE = "ru"

    _SPACE = r"[ \t\u00a0\u202f]"
    _SEPARATOR = (
        rf"(?:{_SPACE}{{1,3}}(?:№{_SPACE}{{0,3}})?"
        rf"|{_SPACE}{{0,3}}-{_SPACE}{{0,3}}|№{_SPACE}{{0,3}})"
    )
    PATTERNS = [
        Pattern(
            "Russian international passport, separated (weak)",
            rf"(?<![\w])[0-9]{{2}}{_SEPARATOR}"
            rf"(?:[0-9]{{7}}|[0-9]{{4}}(?:{_SPACE}{{1,3}}|-)[0-9]{{3}})"
            r"(?![\w])",
            0.2,
        ),
        Pattern(
            "Russian international passport, compact (very weak)",
            r"(?<![\w])[0-9]{9}(?![\w])",
            0.05,
        ),
    ]
    CONTEXT = [
        "загранпаспорт",
        "заграничный паспорт",
        "заграничного паспорта",
        "паспорт",
        "паспортные данные",
        "паспортные реквизиты",
        "foreign passport",
        "international passport",
        "passport",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: str = "RU_FOREIGN_PASSPORT",
        name: Optional[str] = None,
    ):
        super().__init__(
            supported_entity=supported_entity,
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            name=name,
        )
