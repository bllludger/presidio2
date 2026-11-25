# presidio-ru-core

Русский форк Presidio Analyzer: библиотека распознавания персональных данных
и секретов. Возвращает позиции находок в исходном тексте. Маскирование,
восстановление, кеши и HTTP-очереди реализуются интеграциями, включая LiteLLM.

## Сборка для LiteLLM

Порт использует `2.2.366+ru.mask4`: базовую сборку mask3 и шесть изменений
отложенного импорта NLP. Базовый wheel — вход сборки в `release-inputs/`.
Скрипт формирует именно этот состав, не включая другие изменения рабочего SDK.

```sh
python3 presidio-analyzer/scripts/stage_mask4_release.py \
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
