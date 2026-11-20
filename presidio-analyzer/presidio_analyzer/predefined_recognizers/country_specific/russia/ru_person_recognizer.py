"""Russian name heuristics with a small explicit lexicon, without NER."""

from typing import List, Optional

import regex as re

from presidio_analyzer import Pattern, PatternRecognizer

from .ru_person_names import (
    GIVEN_NAME,
    KNOWN_SURNAME,
    UNAMBIGUOUS_NAME,
)


class RuPersonRecognizer(PatternRecognizer):
    """
    Recognize Cyrillic names using bounded patterns and explicit name context.

    These are heuristics, not a universal specification of Russian names.
    Full-name patterns use patronymic endings; initials and explicitly labelled
    fields, introductions and age provide additional evidence. Lower-case full
    names require both surname and patronymic endings to pass alone.
    A small MIT-licensed uinames lexicon adds individual given names and pairs.
    Common-word homonyms remain weak alone; arbitrary title-case pairs are weak.
    No NER, morphology model or checksum is used. Lexicon provenance and license:
    ru_person_names.py (thm/uinames, pinned source and local case-form heuristics).

    Pattern/context/validation semantics follow Presidio's PatternRecognizer:
    https://github.com/data-privacy-stack/presidio/blob/main/docs/analyzer/adding_recognizers.md

    :param patterns: Override the default name patterns.
    :param context: Override name-specific context words.
    :param supported_language: Language code, ru by default.
    :param supported_entity: Entity type returned for a person.
    :param name: Optional recognizer instance name.
    """

    COUNTRY_CODE = "ru"
    _SPACE = r"[ \t\u00a0\u202f]{1,3}"
    _TITLE_PART = r"(?:[А-ЯЁ][а-яё]{1,39}|[А-ЯЁ]{2,40})"
    _TITLE = rf"(?-i:{_TITLE_PART}(?:[-‑]{_TITLE_PART})?)"
    _ANY = r"[А-ЯЁа-яё]{2,40}(?:[-‑][А-ЯЁа-яё]{2,40})?"
    _SURNAME = (
        r"[А-ЯЁа-яё]{2,30}(?:(?:ов|ев|ёв|ин|ын)(?:а|у|ым|ом|е|ой|ою)?"
        r"|(?:ск|цк)(?:ий|ого|ому|им|ом|ая|ой|ую|ою))"
    )
    _PATR = (
        r"(?:(?:[А-ЯЁа-яё]{2,30}(?:ович|евич)"
        r"|Ильич|Кузьмич|Лукич|Фомич|Саввич|Никитич)(?:а|у|ем|ом|е)?"
        r"|(?:[А-ЯЁа-яё]{2,30}(?:овн|евн)"
        r"|Ильиничн|Кузьминичн|Лукиничн|Фоминичн|Саввичн|Никитичн)"
        r"(?:а|ы|е|у|ой|ою))"
    )
    _INITIAL = r"(?-i:[А-ЯЁ])\."
    _INITIALS = rf"{_INITIAL}(?:[ \t\u00a0\u202f]{{0,3}}{_INITIAL})?"
    _START = (
        r"(?<![\w\-‑])"
        r"(?!(?:фио|клиент|получатель|заявитель|пациент|директор)\b)"
    )
    _END = r"(?![\w\-‑])"
    _FIELD_TITLE = rf"(?!(?:фио|фамилия|имя|отчество)\b){_TITLE}"
    _PAIR_SURNAME = rf"(?:{_SURNAME}|{KNOWN_SURNAME})"
    PATTERNS = [
        Pattern(
            "Russian known given name and surname (medium)",
            rf"{_START}(?:{GIVEN_NAME}{_SPACE}{_PAIR_SURNAME}"
            rf"|{_PAIR_SURNAME}{_SPACE}{GIVEN_NAME}){_END}",
            0.4,
        ),
        Pattern(
            "Russian known given name and patronymic (medium)",
            rf"{_START}{GIVEN_NAME}{_SPACE}{_PATR}{_END}",
            0.4,
        ),
        Pattern(
            "Russian unambiguous capitalized given name (medium)",
            rf"{_START}(?={_TITLE}{_END}){UNAMBIGUOUS_NAME}{_END}",
            0.4,
        ),
        Pattern(
            "Russian known given name (very weak)",
            rf"{_START}{GIVEN_NAME}{_END}",
            0.1,
        ),
        Pattern(
            "Russian full name with surname and patronymic endings (medium)",
            rf"{_START}(?:{_SURNAME}{_SPACE}{_ANY}{_SPACE}{_PATR}"
            rf"|{_ANY}{_SPACE}{_PATR}{_SPACE}{_SURNAME}){_END}",
            0.4,
        ),
        Pattern(
            "Russian name after explicit introduction (medium)",
            r"(?<=\b(?:фио|фамилия|имя|отчество|меня зовут|его зовут|её зовут"
            r"|пациент|пациентка|заявитель|заявительница)"
            r"[ \t\u00a0\u202f]{1,3})"
            rf"{_FIELD_TITLE}(?:{_SPACE}{_FIELD_TITLE}){{0,2}}{_END}",
            0.4,
        ),
        Pattern(
            "Russian client name with surname ending (medium)",
            r"(?<=\b(?:клиент|клиентка)[ \t\u00a0\u202f]{1,3})"
            rf"(?:{_TITLE}{_SPACE}(?={_TITLE}{_END}){_SURNAME}"
            rf"|(?={_TITLE}{_END}){_SURNAME}{_SPACE}{_TITLE}){_END}",
            0.4,
        ),
        Pattern(
            "Russian component field (medium)",
            r"(?<=\b(?:фамилия|имя|отчество)[\"']?[ \t]{0,3}"
            r"[:=][ \t]{0,3}[\"'«]?)"
            rf"{_ANY}{_END}",
            0.4,
        ),
        Pattern(
            "Russian name before age (medium)",
            rf"{_START}{_TITLE}(?:{_SPACE}{_TITLE}){{0,2}}{_END}"
            r"(?=,[ \t]{0,3}(?:[1-9]|[1-9][0-9]|1[01][0-9])[ \t]{1,3}"
            r"(?:год|года|лет)\b)",
            0.4,
        ),
        Pattern(
            "Russian surname name patronymic (medium)",
            rf"{_START}{_TITLE}{_SPACE}{_TITLE}{_SPACE}{_PATR}{_END}",
            0.4,
        ),
        Pattern(
            "Russian name patronymic surname (medium)",
            rf"{_START}{_TITLE}{_SPACE}{_PATR}{_SPACE}{_TITLE}{_END}",
            0.4,
        ),
        Pattern(
            "Russian surname initials (medium)",
            rf"{_START}{_TITLE}{_SPACE}{_INITIALS}{_END}",
            0.4,
        ),
        Pattern(
            "Russian initials surname (medium)",
            rf"{_START}{_INITIALS}{_SPACE}{_TITLE}{_END}",
            0.4,
        ),
        Pattern(
            "Russian two-part name (very weak)",
            rf"{_START}{_TITLE}{_SPACE}{_TITLE}{_END}",
            0.1,
        ),
        Pattern(
            "Russian mixed-case full name (very weak)",
            rf"{_START}(?:{_ANY}{_SPACE}{_ANY}{_SPACE}{_PATR}"
            rf"|{_ANY}{_SPACE}{_PATR}{_SPACE}{_ANY}){_END}",
            0.05,
        ),
        Pattern(
            "Russian explicitly labelled name (medium)",
            r"(?<=\b(?:ф\.?[ \t]{0,2}и\.?[ \t]{0,2}о\.?"
            r"|полное[ \t]имя|получатель|заявитель|пациент|fio|full_name)"
            r"[\"']?[ \t\u00a0\u202f]{0,3}"
            r"[:=][ \t\u00a0\u202f]{0,3}[\"'«]?)"
            rf"{_ANY}(?:{_SPACE}{_ANY}){{0,2}}{_END}"
            r"(?=[ \t\u00a0\u202f]{0,3}(?:[.,;\r\n\"'»}]|$))",
            0.4,
        ),
    ]
    CONTEXT = [
        "фио",
        "фамилия",
        "имя клиента",
        "полное имя",
        "получатель",
        "пациент",
        "заявитель",
        "меня зовут",
    ]
    _NON_NAMES = frozenset(
        {
            "фио",
            "фамилия",
            "имя",
            "отчество",
            "полное",
            "клиент",
            "клиентка",
            "получатель",
            "заявитель",
            "пациент",
            "пациентка",
            "заявительница",
            "директор",
            "компания",
            "общество",
            "ооо",
            "пао",
            "не",
            "нет",
            "данные",
            "сведения",
            "указано",
            "указаны",
            "неизвестно",
            "отсутствует",
            "отсутствуют",
            "пользователь",
            "версия",
            "раздел",
            "рисунок",
            "таблица",
            "приложение",
        }
    )

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "ru",
        supported_entity: str = "PERSON",
        name: Optional[str] = None,
    ):
        super().__init__(
            supported_entity=supported_entity,
            patterns=self.PATTERNS if patterns is None else patterns,
            context=self.CONTEXT if context is None else context,
            supported_language=supported_language,
            name=name,
        )

    def invalidate_result(self, pattern_text: str) -> bool:
        """Reject structural labels and explicit missing-value placeholders."""
        words = re.findall(r"[А-ЯЁа-яё]+", pattern_text.casefold())
        return any(word in self._NON_NAMES for word in words)
