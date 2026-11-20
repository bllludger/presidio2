"""Small Russian given-name lexicon and deterministic case forms.

Names copied from thm/uinames, Russia, commit
 a9d1b530ed0dbd106eb1ca5b91cb02ff873cca1a (names.json).
https://github.com/thm/uinames/blob/a9d1b530ed0dbd106eb1ca5b91cb02ff873cca1a/names.json
The MIT license below applies to the copied name lists. Case-form heuristics
and ambiguity exclusions are local additions, not authoritative morphology.

This license applies EXCLUSIVELY to /names.json. Except where otherwise stated,
any code not covered by this license is published under exclusive copyright.

MIT License

Copyright (c) 2019 Thom van der Weerd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import regex as re

MALE_NAMES = (
    "Адам Александр Алексей Альберт Анатолий Андрей Антон Аркадий Артём Артур "
    "Богдан Борис Вадим Валентин Валерий Василий Виктор Виталий Влад Владимир "
    "Владислав Гена Геннадий Георгий Герман Глеб Григорий Давид Давыд Даниил "
    "Данил Денис Дмитрий Евгений Егор Ефим Иван Игорь Кирилл Константин Лев "
    "Леонид Макс Максим Марат Мирон Мирослав Михаил Назар Николай Никита Олег "
    "Оскар Павел Пётр Роман Святослав Семён Сергей Станислав Стас Степан "
    "Тарас Тимофей Трофим Фёдор Феликс Филипп Эдуард Эдгар Юрий Ян Ярослав "
)

FEMALE_NAMES = (
    "Аида Александра Алёна Алина Алиса Алла Альбина Анастасия Анжела Анна "
    "Арина Анфиса Валентина Валерия Варвара Василиса Вера Вероника Виктория "
    "Галина Дарья Ева Евгения Екатерина Елена Елизавета Жанна Зина Зинаида "
    "Зоя Инесса Инга Инна Ирина Катерина Кира Кристина Ксения Лариса Леся "
    "Лидия Лина Любовь Людмила Майя Маргарита Марина Мария Надежда Настасья "
    "Наталья Нина Оксана Олеся Ольга Полина Регина Рената Роза Сабина "
    "Светлана Слава Снежана София Софья Тамара Татьяна Ульяна Эльвира Эльза "
    "Юлия Яна "
)

SURNAMES = (
    "Абрамов Авдеев Александров Алексеев Андреев Баданин Базовкин Богданов "
    "Боков Буркавцов Васильев Веретенников Владимиров Волков Воробьёв "
    "Гаврилов Галкин Герасимов Голанов Григорьев Давыдов Данилов Дмитриев "
    "Долгих Дьячков Евдокимов Евсеев Егоров Ермаков Ермолин Жгилёв Жданов "
    "Жиганов Жуков Журавлёв Завьялов Зайцев Захаров Зимин Зуев Иванов Ивков "
    "Игнатьев Ильин Исаев Кабанов Казаков Калинин Кац Кузнецов Ковалев "
    "Лаврентьев Лавров Лазарев Лебедев Любушкин Макаров Максимов Мельник "
    "Михайлов Моисеенко Назаров Наумов Никитин Николаев Новиков Овчинников "
    "Окулов Орлов Осипов Ошуков Павлов Панов Петров Плотников Попов Рогачёв "
    "Романов Ротару Румянцев Рыбалко Савельев Савин Седых Семёнов Смирнов "
    "Соколов Соловьёв Степанов Тарасов Терехов Тимофеев Титов Ткаченко Уваров "
    "Углов Ульянов Уткин Ушаков Фадеев Федотов Фёдоров Фомин Фролов Харинов "
    "Харитонов Хватов Хромцов Худяков Царёв Цветков Цивилёв Цыганков Цыпченко "
    "Черкашин Чернов Черемнов Черноусов Чистяков Шадрин Шаповалов Шевченко "
    "Шестаков Шнайдер Щеглов Щербаков Щёголев Щукин Щуров Юдин Юрков Юрченко "
    "Юрьев Юшков Яблоков Яковлев Якушев Яшин "
)

# Local additions cover common names missing from the source.
MALE_NAMES += "Илья Яков Вячеслав Савелий Савва Платон Захар Фома Кузьма"

# Entire paradigms are weak alone if common words share their spelling.
AMBIGUOUS_NAMES = frozenset(
    "Вера Надежда Любовь Роман Лев Роза Марта Марк Герман Лилия "
    "Муза Лада Ника Слава Света Люба Мила Майя Оскар".casefold().split()
)


def name_forms(name: str, female: bool = False) -> set[str]:
    """Generate common singular case forms; unknown endings stay unchanged."""
    name = name.casefold()
    if name in {"пётр", "петр"}:
        return {"пётр", "петр", "петра", "петру", "петром", "петре"}
    if name in {"павел", "лев"}:
        stem = "павл" if name == "павел" else "льв"
        return {name} | {stem + ending for ending in ("а", "у", "ом", "е")}
    if name == "любовь":
        return {"любовь", "любови", "любовью"}
    if name.endswith("ия"):
        suffixes = ("я", "и", "ю", "ей", "ею")
    elif name.endswith("а"):
        suffixes = ("а", "и" if name[-2] in "гкхжчшщ" else "ы", "е", "у", "ой", "ою")
    elif name.endswith("я"):
        suffixes = ("я", "и", "е", "ю", "ей", "ею")
    elif name.endswith("й"):
        suffixes = ("й", "я", "ю", "ем", "и" if name.endswith("ий") else "е")
    elif name.endswith("ь"):
        suffixes = ("ь", "и", "ью") if female else ("ь", "я", "ю", "ем", "е")
    elif not female and name[-1] not in "аеёиоуыэюя":
        suffixes = ("", "а", "у", "ом", "е")
        name += "_"
    else:
        return {name, name.replace("ё", "е")}
    forms = {name[:-1] + suffix for suffix in suffixes}
    return forms | {form.replace("ё", "е") for form in forms}


def alternatives(words: set[str]) -> str:
    """Factor shared prefixes and try the longest matching word first."""
    tree = {}
    for word in words:
        node = tree
        for char in word:
            node = node.setdefault(char, {})
        node[""] = True

    def emit(node):
        branches = [
            re.escape(char) + emit(child)
            for char, child in sorted(node.items())
            if char
        ]
        if "" in node:
            branches.append("")
        if len(branches) == 1:
            return branches[0]
        return "(?:" + "|".join(branches) + ")"

    return emit(tree)


_all_forms = set()
_unambiguous_forms = set()
for _names, _female in ((MALE_NAMES, False), (FEMALE_NAMES, True)):
    for _name in _names.split():
        _forms = name_forms(_name, _female)
        _all_forms.update(_forms)
        if _name.casefold() not in AMBIGUOUS_NAMES:
            _unambiguous_forms.update(_forms)
# A spelling shared with any ambiguous paradigm is weak, even via another name.
_ambiguous_forms = {
    form
    for names, female in ((MALE_NAMES, False), (FEMALE_NAMES, True))
    for name in names.split()
    if name.casefold() in AMBIGUOUS_NAMES
    for form in name_forms(name, female)
}
GIVEN_NAME = alternatives(_all_forms)
UNAMBIGUOUS_NAME = alternatives(_unambiguous_forms - _ambiguous_forms)
KNOWN_SURNAME = alternatives({w.casefold() for w in SURNAMES.split()})
