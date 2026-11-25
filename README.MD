# presidio-ru-core

Русский форк Presidio Analyzer: библиотека распознавания персональных данных
и секретов. Возвращает позиции находок в исходном тексте. Маскирование,
восстановление, кеши и HTTP-очереди реализуются интеграциями, включая LiteLLM.

## Сборка для LiteLLM и OpenCode

Обе интеграции используют `2.2.366+ru.mask4`: базовую сборку mask3 и шесть изменений
отложенного импорта NLP. Базовый wheel — вход сборки в `release-inputs/`.
Скрипт формирует именно этот состав, не включая другие изменения рабочего SDK.

Сборка одной командой из корня репозитория:

```sh
bash scripts/build_mask4.sh
```

На Mac с Homebrew скрипт установит uv, если его нет. Python 3.13 при необходимости
загрузит uv. Без Homebrew заранее установите uv или задайте `PRESIDIO_UV`.
Каждая сборка получает новый staging-каталог; wheel записывается в `.local/dist/`.
Ниже приведены те же действия вручную; для них нужны Python 3.13 и uv.
Для установки готового порта или плагина собирать ядро самостоятельно не нужно:
проверенный wheel уже включён в каждый проект.

```sh
python3.13 presidio-analyzer/scripts/stage_mask4_release.py \
  --baseline-wheel release-inputs/presidio_analyzer-2.2.366+ru.mask3-py3-none-any.whl \
  --output .local/mask4
uv build .local/mask4 --wheel --out-dir .local/dist
```

Каталог staging должен быть новым. Готовый пакет устанавливается как
`presidio-analyzer`, импортируется как `presidio_analyzer`.
Версию для интеграции фиксирует её собственный runtime lock.

Прямой `uv build` из `presidio-analyzer/` собирает полное рабочее дерево SDK;
оно отличается от состава mask4. Не заменяйте им зафиксированный wheel порта
под тем же номером версии.

## Обновление интеграций

[Порт LiteLLM](https://github.com/bllludger/port-litellm) хранит wheel в
`profile/wheels/`, а ссылку на него — в `profile/runtime.lock.txt`.
[Плагин OpenCode](https://github.com/bllludger/opencode-pii-blur) хранит wheel
в `wheels/`, а ссылку — в `requirements/runtime.lock.txt`.
Оба проекта должны получать один и тот же файл wheel.

Новый изменённый состав ядра выпускайте под новым номером версии, затем
обновляйте wheel и runtime lock каждой интеграции. Нельзя менять содержимое
уже выпущенной версии: установщик может посчитать её установленной.
Mask3 в `release-inputs/` — только вход сборки, не версия рабочих интеграций.
Инструкции установки и перезапуска находятся в README соответствующего проекта.

## Полное сканирование

Для маскирования используйте строгую обработку неполного сканирования:

```python
from presidio_analyzer import strict_scan

with strict_scan():
    findings = engine.analyze(text=text, language="ru")
```

При `IncompleteScan` интеграция должна отклонить запрос или повторить анализ,
не передавая непроверенный текст модели. Настройки распознавателей и языка
задаются профилем интеграции.

## Лицензия

Основа — Presidio 2.2.366 и RU-сборка анализатора.
[MIT](LICENSE) · [Уведомления об авторских правах](NOTICE).
Для Docker Compose шаблон переменных образов находится в `.env.example`.
