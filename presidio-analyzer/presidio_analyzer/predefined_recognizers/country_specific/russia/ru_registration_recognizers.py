"""Checksum-based recognizers for Russian registration numbers."""

from presidio_analyzer import Pattern, PatternRecognizer


class _RuRegistrationRecognizer(PatternRecognizer):
    COUNTRY_CODE = "ru"

    def __init__(
        self,
        supported_language: str = "ru",
        name: str | None = None,
        supported_entity: str | None = None,
        context: list[str] | None = None,
    ):
        super().__init__(
            supported_entity=supported_entity or self.ENTITY,
            patterns=[Pattern(self.ENTITY, self.REGEX, 0.6)],
            supported_language=supported_language,
            name=name,
            context=context,
        )


class RuOgrnRecognizer(_RuRegistrationRecognizer):
    """Recognize a 13-digit primary registration number for a legal entity."""

    ENTITY = "RU_OGRN"
    REGEX = r"(?<!\w)[15][0-9]{12}(?!\w)"

    def validate_result(self, pattern_text: str) -> bool:
        return int(pattern_text[:-1]) % 11 % 10 == int(pattern_text[-1])


class RuOgrnipRecognizer(_RuRegistrationRecognizer):
    """Recognize a 15-digit primary registration number for an entrepreneur."""

    ENTITY = "RU_OGRNIP"
    REGEX = r"(?<!\w)3[0-9]{14}(?!\w)"

    def validate_result(self, pattern_text: str) -> bool:
        return int(pattern_text[:-1]) % 13 % 10 == int(pattern_text[-1])


class RuSnilsRecognizer(_RuRegistrationRecognizer):
    """Recognize compact and formatted individual insurance account numbers."""

    ENTITY = "RU_SNILS"
    _HYPHEN = r"[-\u2010\u2011]"
    _SEPARATOR = r"[- \t\u00a0\u202f\u2010\u2011]"
    REGEX = (
        rf"(?<!\w)(?:[0-9]{{11}}|"
        rf"[0-9]{{3}}{_HYPHEN}[0-9]{{3}}{_HYPHEN}[0-9]{{3}}{_SEPARATOR}[0-9]{{2}})(?!\w)"
    )

    def validate_result(self, pattern_text: str) -> bool:
        digits = [int(char) for char in pattern_text if "0" <= char <= "9"]
        if not any(digits[:9]):
            return False
        total = sum(digit * weight for digit, weight in zip(digits[:9], range(9, 0, -1)))
        return total % 101 % 100 == digits[9] * 10 + digits[10]
