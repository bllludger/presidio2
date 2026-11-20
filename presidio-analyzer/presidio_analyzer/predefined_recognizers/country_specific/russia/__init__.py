"""Recognizers for Russian identifiers."""

from .ru_bank_card_recognizer import RuBankCardRecognizer
from .ru_card_details_recognizer import (
    RuCardExpiryRecognizer,
    RuCardholderRecognizer,
    RuCardSecurityCodeRecognizer,
)
from .ru_foreign_passport_recognizer import RuForeignPassportRecognizer
from .ru_inn_recognizer import RuInnRecognizer
from .ru_passport_recognizer import RuPassportRecognizer
from .ru_person_recognizer import RuPersonRecognizer
from .ru_registration_recognizers import (
    RuOgrnRecognizer,
    RuOgrnipRecognizer,
    RuSnilsRecognizer,
)

__all__ = [
    "RuCardExpiryRecognizer",
    "RuCardholderRecognizer",
    "RuCardSecurityCodeRecognizer",

    "RuBankCardRecognizer",
    "RuInnRecognizer",
    "RuForeignPassportRecognizer",
    "RuPassportRecognizer",
    "RuPersonRecognizer",
    "RuOgrnRecognizer",
    "RuOgrnipRecognizer",
    "RuSnilsRecognizer",
]
