"""Explicitly labelled card expiry, holder name and verification code, without NER."""

from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer

_H = r"[ \t\u00a0\u202f\u2009]"
_JOIN = rf"[\"']?{_H}{{0,3}}(?:[:=,—–-]{_H}{{0,3}}[\"'«]?|{_H})"
_END = r"(?![\w/.-])"


class _RuLabelledCardField(PatternRecognizer):
    """Share the YAML-compatible constructor for three explicit field types."""

    COUNTRY_CODE = "ru"
    ENTITY = ""
    PATTERNS = []
    CONTEXT = []

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: Optional[str] = None,
        name: Optional[str] = None,
    ):
        super().__init__(
            supported_entity=self.ENTITY
            if supported_entity is None
            else supported_entity,
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            name=name,
        )


class RuCardExpiryRecognizer(_RuLabelledCardField):
    """
    Recognize a card expiry month/year after an explicit expiry label.

    Cardholder-data classification: https://www.pcisecuritystandards.org/faqs/1222/
    MM/YY and MM/YYYY (also dots/hyphens) are format heuristics, not a check
    of card validity. Expired dates remain sensitive and are not discarded.
    No checksum, current-date dependency or confidence 1.0 promotion is used.
    """

    ENTITY = "CARD_EXPIRY"
    _LABEL = (
        rf"(?:срок{_H}{{1,3}}действия(?:{_H}{{1,3}}карты)?"
        rf"|действует{_H}{{1,3}}до|годна{_H}{{1,3}}до"
        rf"|valid{_H}{{1,3}}(?:thru|through|until)|exp(?:iry)?"
        r"|card_expiry|expiry_date|expiration_date|valid_thru|expires|срок)"
    )
    PATTERNS = [
        Pattern(
            "Explicit card expiry month/year (medium)",
            rf"(?<=\b{_LABEL}{_JOIN})(?:0[1-9]|1[0-2]){_H}{{0,3}}"
            rf"[/.-]{_H}{{0,3}}(?:20[0-9]{{2}}|[0-9]{{2}})(?![\w/-]|\.[0-9])",
            0.4,
        )
    ]
    CONTEXT = ["карта", "card", "expiry", "exp", "card_expiry"]


class RuCardSecurityCodeRecognizer(_RuLabelledCardField):
    """
    Recognize explicitly labelled CVV/CVC/CID codes, three or four ASCII digits.

    Source: https://www.pcisecuritystandards.org/faqs/1280/
    A verification code has no public checksum. Do not infer it from arbitrary
    short numbers, PINs or OTPs. Generic 'security code' labels are ambiguous.
    """

    ENTITY = "CARD_SECURITY_CODE"
    _LABEL = (
        rf"(?:(?:cvv2?|cvc2?|cid|cav2|cvn2)(?:-код)?|код{_H}{{1,3}}(?:cvv2?|cvc2?)|код{_H}{{1,3}}"
        rf"(?:на{_H}{{1,3}}обороте(?:{_H}{{1,3}}карты)?"
        rf"|с{_H}{{1,3}}обратной{_H}{{1,3}}стороны(?:{_H}{{1,3}}карты)?|сзади(?:{_H}{{1,3}}карты)?|безопасности(?:{_H}{{1,3}}карты)?|защиты{_H}{{1,3}}карты))"
    )
    PATTERNS = [
        Pattern(
            "Explicit card verification code (medium)",
            rf"(?<=\b{_LABEL}{_JOIN})[0-9](?:{_H}?[0-9]){{2,3}}(?![\w]|{_H}[0-9]|[.-][0-9])",
            0.4,
        )
    ]
    CONTEXT = ["карта", "card", "cvv", "cvc", "cvv2", "cvc2", "cid"]


class RuCardholderRecognizer(_RuLabelledCardField):
    """
    Recognize a Latin/Cyrillic holder name after an explicit cardholder label.

    Source: https://www.pcisecuritystandards.org/faqs/1222/
    Names are bounded format heuristics, without NER, a dictionary or checksum.
    Names require title/upper case to avoid swallowing ordinary prose.
    """

    ENTITY = "CARDHOLDER_NAME"
    _LABEL = (
        rf"(?:владелец{_H}{{1,3}}карты|держатель{_H}{{1,3}}карты|на{_H}{{1,3}}карте{_H}{{1,3}}(?:написано|указано)|карта{_H}{{1,3}}оформлена{_H}{{1,3}}на"
        rf"|имя{_H}{{1,3}}(?:на{_H}{{1,3}}карте|держателя(?:{_H}{{1,3}}карты)?)"
        rf"|card{_H}{{0,1}}holder(?:{_H}{{1,3}}name)?|cardholder_name|holder_name)"
    )
    _PART = r"(?:[А-ЯЁ][а-яё]{1,39}|[А-ЯЁ]{2,40}|[A-Z][a-z]{1,39}|[A-Z]{2,40})"
    _WORD = (
        r"(?!(?:CVV2?|CVC2?|CID|PAN|EXP|VISA|MASTERCARD|не|нет|данные|"
        r"отсутствует|неизвестно|NOT|UNKNOWN|NONE|NULL|номер|срок|карта)\b)"
        rf"(?-i:(?:[A-Z]['’])?{_PART}(?:[-‑'’]{_PART})?)"
    )
    PATTERNS = [
        Pattern(
            "Explicit cardholder name (medium)",
            rf"(?<=\b{_LABEL}{_JOIN}){_WORD}(?:{_H}{{1,3}}{_WORD}){{0,3}}"
            r"(?![\w'’\-‑])",
            0.4,
        )
    ]
    PATTERNS.append(
        Pattern(
            "Unqualified holder role (very weak)",
            rf"(?<=\b(?:держатель|владелец|имя{_H}{{1,3}}владельца){_JOIN})"
            rf"{_WORD}(?:{_H}{{1,3}}{_WORD}){{0,3}}(?![\w'’\-‑])",
            0.1,
        )
    )
    CONTEXT = [
        "карта",
        "card",
        "cardholder",
        "cardholder_name",
    ]
