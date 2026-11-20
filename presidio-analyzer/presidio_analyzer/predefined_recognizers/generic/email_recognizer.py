import re
from time import monotonic
from typing import List, Optional

import regex
import tldextract

from presidio_analyzer import Pattern, PatternRecognizer


class EmailRecognizer(PatternRecognizer):
    """
    Recognize email addresses using regex.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    """

    # The domain part allows internal hyphen groups inside each label, including
    # consecutive hyphens, so RFC 3490 punycode labels (e.g. "xn--80ak6aa92e")
    # and raw IDN labels (matched via the Unicode-aware "\w") are detected.
    # Each label still starts and ends with an alphanumeric, and at least one
    # dot is required, so no arbitrary non-email text is matched.
    _EMAIL_REGEX = (
        r"\b((([!#$%&'*+\-/=?^_`{|}~\w])"
        r"|([!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~\.\w]{0,}[!#$%&'*+\-/=?^_`{|}~\w]))"
        r"[@]\w+(?:-+\w+)*(?:\.\w+(?:-+\w+)*)+)\b"
    )
    _DELIMITER = re.compile(r"[ \t\r\n]")
    PATTERNS = [
        Pattern(
            "Email (Medium)",
            _EMAIL_REGEX,
            0.5,
        ),
    ]

    CONTEXT = ["email"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "EMAIL_ADDRESS",
        name: Optional[str] = None,
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name=name,
        )

    def _iter_pattern_matches(self, pattern, text, timeout):
        if (
            pattern.regex != self._EMAIL_REGEX
            or pattern.compiled_with_flags != regex.I | regex.M | regex.S
            or timeout <= 0
        ):
            yield from super()._iter_pattern_matches(pattern, text, timeout)
            return

        # An email must contain @ and cannot cross ASCII whitespace. The exact
        # matcher sees the original buffer so its offsets remain absolute.
        deadline = monotonic() + timeout
        previous_end = 0
        at = text.find("@")
        while at >= 0:
            start = 1 + max(text.rfind(c, previous_end, at) for c in " \t\r\n")
            start = max(start, previous_end)
            delimiter = self._DELIMITER.search(text, at + 1)
            end = delimiter.start() if delimiter else len(text)
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("Email pattern search timed out")
            yield from pattern.compiled_regex.finditer(
                text, start, end, timeout=remaining
            )
            previous_end = end
            at = text.find("@", end)

    def validate_result(self, pattern_text: str):  # noqa: D102
        result = tldextract.extract(pattern_text)
        return result.fqdn != ""
