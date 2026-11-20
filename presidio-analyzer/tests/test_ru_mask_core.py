"""Regression cases for the deployed RU masking profile."""

import random
import unittest
from unittest.mock import patch

import regex
from presidio_analyzer import Pattern
from presidio_analyzer.predefined_recognizers import EmailRecognizer
from presidio_analyzer.predefined_recognizers.country_specific.russia import (
    ru_person_names,
)
from presidio_analyzer.predefined_recognizers.generic import (
    gitleaks_secret_recognizer as gitleaks,
)


class RUMaskCoreTests(unittest.TestCase):
    """Check exact-match and offset compatibility with the production RU profile."""

    def test_email_candidate_windows_match_the_full_regex(self):
        """Compare all capture groups, including offsets after unusual whitespace."""
        recognizer = EmailRecognizer()
        pattern = Pattern("email", recognizer.PATTERNS[0].regex, 0.5)
        flags = regex.I | regex.M | regex.S
        pattern.compiled_with_flags = flags
        pattern.compiled_regex = regex.compile(pattern.regex, flags)
        randomizer = random.Random(306)
        words = [
            ".a",
            "x@xn--e1afmkfd.xn--p1ai",
            "я@почта.рф",
            "@@",
            "a@b.io@next.io",
            "'+a@b.co",
            "🙂",
            "\u0301",
            "\u00a0",
            "\v",
            "\n",
            "\r",
            " ",
            "\t",
            "123",
            "//",
        ]
        for _ in range(1000):
            text = "".join(randomizer.choices(words, k=12))
            original = [match.regs for match in pattern.compiled_regex.finditer(text)]
            narrowed = [
                match.regs
                for match in recognizer._iter_pattern_matches(pattern, text, 5)
            ]
            self.assertEqual(original, narrowed)

    def test_custom_email_rule_can_cross_a_space_and_omit_at(self):
        """Keep caller-supplied patterns on the generic path."""
        pattern = Pattern("custom", "a b", 0.5)
        recognizer = EmailRecognizer(patterns=[pattern])
        with patch.object(recognizer, "validate_result", return_value=True):
            results = recognizer.analyze("a b", ["EMAIL_ADDRESS"])
        self.assertEqual([(r.start, r.end) for r in results], [(0, 3)])

    def test_email_windows_share_one_deadline(self):
        """Use a single timeout budget across the candidate regions."""
        recognizer = EmailRecognizer()
        pattern = Pattern("email", recognizer.PATTERNS[0].regex, 0.5)
        pattern.compiled_with_flags = regex.I | regex.M | regex.S
        pattern.compiled_regex = regex.compile(
            pattern.regex, pattern.compiled_with_flags
        )
        with patch(
            "presidio_analyzer.predefined_recognizers.generic.email_recognizer.monotonic",
            side_effect=[0, 0, 4],
        ):
            matches = recognizer._iter_pattern_matches(pattern, "a@b.io c@d.org", 3)
            self.assertEqual(next(matches).group(), "a@b.io")
            with self.assertRaises(TimeoutError):
                next(matches)

    def test_matching_spans_for_entire_name_dictionary(self):
        """Prefer longer inflected forms when their prefixes coincide."""
        words = sorted(ru_person_names._all_forms, key=lambda word: (-len(word), word))
        legacy = "(?:" + "|".join(map(regex.escape, words)) + ")"
        current = ru_person_names.GIVEN_NAME
        text = " ".join(word.upper() + ", " + word.title() for word in words)
        self.assertEqual(
            [m.span() for m in regex.finditer(legacy, text, flags=regex.I)],
            [m.span() for m in regex.finditer(current, text, flags=regex.I)],
        )

    def test_byte_coordinates_on_line_boundaries(self):
        """Preserve the Gitleaks byte convention for empty and partial lines."""
        rows = [
            (b"abc", 0, 3, (0, 0, 1, 3, 0, 3)),
            (b"aa\nbb\ncc", 2, 2, (1, 1, 1, 2, 2, 5)),
            (b"aa\nbb\ncc", 2, 6, (1, 1, 1, 0, 2, 6)),
            (b"aa\nbb\ncc", 6, 7, (2, 2, 2, 2, 0, 8)),
            (b"aa\nbb\ncc", 1, 5, (0, 1, 2, 3, 0, 5)),
            (b"\n\r\n", 0, 0, (1, 1, 1, 0, 0, 2)),
            (b"", 0, 0, (1, 1, 1, 0, 0, 0)),
        ]
        for raw, start, end, expected in rows:
            with self.subTest(raw=raw, start=start, end=end):
                lines = [i for i, byte in enumerate(raw) if byte == 10] or [len(raw)]
                self.assertEqual(gitleaks._location(raw, start, end, lines), expected)

    def test_secret_offsets_after_ascii_and_multibyte_prefixes(self):
        """Return character positions for both UTF-8 and ASCII input."""
        token = "ghp_" + "Aj9Kdx4Fbz0Q3emcY1qv58tu7ZLgWpfahBRs"
        recognizer = gitleaks.GitleaksSecretRecognizer()
        for prefix in ("Status: OK\n", "Статус 🙂\r\n"):
            text = prefix + 'token = "' + token + '"\n'
            self.assertTrue(
                any(text[f.start : f.end] == token for f in recognizer.detect(text))
            )


if __name__ == "__main__":
    unittest.main()
