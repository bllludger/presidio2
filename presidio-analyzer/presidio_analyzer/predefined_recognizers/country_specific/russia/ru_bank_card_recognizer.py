"""Russian-context bank-card PAN detection, including Mir."""

from typing import List, Optional

import regex as re

from presidio_analyzer import Pattern
from presidio_analyzer.predefined_recognizers.generic import CreditCardRecognizer


class RuBankCardRecognizer(CreditCardRecognizer):
    """
    Recognize full bank-card PANs with Luhn and Russian card context.

    Reuses CreditCardRecognizer's Luhn implementation, without confidence 1.0
    promotion. The global credit-card recognizer is unchanged.
    Length/Luhn reference (Sber):
    https://sbersova.ru/sections/economy/anatomiya-bankovskoj-karty-chto-i-zachem-na-nej-raspolozheno
    Mir's 2200-2204 prefix and 16-19 digits (bank acquiring guide):
    https://business.rsb.ru/upload/iblock/835/spravochnik-po-rabote-s-platezhnymi-kartami.pdf
    Mastercard's 2221-2720 and 51-55 ranges:
    https://www.mastercard.us/en-sg/frequently-asked-questions.html/

    Common card-prefix/length candidates have post-check score at least 0.4;
    other 13-19 digit candidates starting 1-6 stay weak without card context.
    This is not an issuer/BIN lookup or verification that a card exists.
    Expiry, CVV, PIN, bank accounts and partially masked PANs are not parsed.

    :param patterns: Override the default patterns.
    :param context: Override card-specific context words.
    :param supported_language: Language code, ru by default.
    :param supported_entity: Entity type returned for a card PAN.
    :param name: Optional recognizer instance name.
    """

    COUNTRY_CODE = "ru"
    _HORIZONTAL_SPACES = " \t\u00a0\u2009\u202f"
    _HSPACE = rf"[{_HORIZONTAL_SPACES}]"
    _SEPARATORS = _HORIZONTAL_SPACES + "-"
    _SEP = rf"(?:{_HSPACE}{{1,3}}|{_HSPACE}{{0,3}}-{_HSPACE}{{0,3}})"
    _BODY = rf"[1-6](?:{_SEP}?[0-9]){{12,18}}"
    _START = rf"(?<![\w*ХхXx•-])(?<![0-9*ХхXx•]{_SEP})"
    _END = rf"(?![\w*ХхXx•-])(?!{_SEP}[0-9*ХхXx•])"
    _LABEL = (
        rf"(?:номер{_HSPACE}{{1,3}}(?:банковской{_HSPACE}{{1,3}})?карты"
        rf"|реквизиты{_HSPACE}{{1,3}}карты"
        rf"|карта(?:{_HSPACE}{{1,3}}[«\"']?мир[»\"']?)?"
        r"|card_number|card|pan)"
    )
    PATTERNS = [
        Pattern(
            "Bank card PAN candidate (very weak)",
            rf"{_START}{_BODY}{_END}",
            0.1,
        ),
        Pattern(
            "Explicitly labelled bank card PAN (medium)",
            rf"(?<=\b{_LABEL}[\"']?{_HSPACE}{{0,3}}"
            rf"[:=]{_HSPACE}{{0,3}}[\"']?){_BODY}{_END}",
            0.4,
        ),
    ]
    CONTEXT = [
        "карта",
        "карточка",
        "card",
        "card_number",
        "visa",
        "mastercard",
        "maestro",
        "unionpay",
        "amex",
        "pan",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: str = "CREDIT_CARD",
        name: Optional[str] = None,
    ):
        if patterns == []:
            raise ValueError("Pattern recognizer should be initialized with patterns")
        super().__init__(
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            supported_entity=supported_entity,
            replacement_pairs=[(c, "") for c in self._SEPARATORS],
            name=name,
        )
        if context is not None:
            self.context = context

    @classmethod
    def compact(cls, value: str) -> str:
        """Remove only supported separators, leaving other characters invalid."""
        return re.sub(rf"[{cls._SEPARATORS}]", "", value)

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Require ASCII length and Luhn, without the base class's 1.0 boost."""
        digits = self.compact(pattern_text)
        if not re.fullmatch(r"[1-6][0-9]{12,18}", digits):
            return False
        return None if super().validate_result(pattern_text) else False

    @staticmethod
    def has_common_prefix(digits: str) -> bool:
        """Recognize broad card families, not individual assigned issuer BINs."""
        length = len(digits)
        first2, first3, first4 = int(digits[:2]), int(digits[:3]), int(digits[:4])
        return (
            (2200 <= first4 <= 2204 and 16 <= length <= 19)
            or (digits.startswith("4") and length in (13, 16, 19))
            or (length == 16 and (51 <= first2 <= 55 or 2221 <= first4 <= 2720))
            or (first2 in (34, 37) and length == 15)
            or (length == 14 and (300 <= first3 <= 305 or first2 in (36, 38, 39)))
            or (first2 == 35 and 16 <= length <= 19)
            or (first2 in (50, 56, 57, 58, 59) and 13 <= length <= 19)
            or (digits.startswith("6") and 13 <= length <= 19)
        )

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        """Use bounded post-Luhn evidence; context enhancement remains separate."""
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        for result in results:
            if self.has_common_prefix(self.compact(text[result.start : result.end])):
                result.score = max(result.score, 0.4)
            explanation = result.analysis_explanation
            explanation.original_score = result.score
            explanation.score = result.score
            explanation.textual_explanation += (
                "; Luhn passed; bounded card-format evidence, no issuer lookup"
            )
        return results
