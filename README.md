# allupdsw — центральный реестр версий и обновлений

Общий публичный репозиторий, из которого все проекты узнают о новых версиях.
У каждого проекта здесь лежит один файл `<имя_проекта>.json`: номер последней версии,
история версий с описанием «Что нового» и команды для обновления.
Код каждого проекта хранится в его собственном репозитории.

Стандарт разработки, общий для всех проектов: [DEVELOPMENT_CONCEPT.md](DEVELOPMENT_CONCEPT.md).

## Структура

| Путь | Назначение |
|---|---|
| `<проект>.json` | Файл версий конкретного проекта |
| `_template.json` | Шаблон для нового проекта |
| `schema/project.schema.json` | JSON Schema формата (подсказки и проверка в редакторе) |
| `tools/validate.py` | Проверка файлов (без зависимостей) |
| `.github/workflows/validate.yml` | Автопроверка при каждом push и pull request |
| `DEVELOPMENT_CONCEPT.md` | Концепция разработки для всех проектов |

## Адрес для проектов

```
https://raw.githubusercontent.com/lumenods/allupdsw/main/<проект>.json
```

## Формат файла

| Поле | Обяз. | Описание |
|---|---|---|
| `project` | да | Имя проекта (`a-z 0-9 _ -`), совпадает с именем файла |
| `title` | нет | Человекочитаемое название |
| `repository` | да | Ссылка на репозиторий проекта |
| `latest` | да | Последняя версия; должна совпадать с `versions[0].version` |
| `update_commands` | да | Команды обновления по способу установки: `linux`, `docker`, `windows`… |
| `versions[]` | да | История версий, **от новой к старой** |
| `versions[].version` | да | `X.Y.Z` |
| `versions[].date` | да | `YYYY-MM-DD` |
| `versions[].type` | да | `initial` (1.0.0), `patch` (3-я цифра), `minor` (2-я), `major` (1-я) |
| `versions[].changes` | да | Список изменений («Что нового») |
| `versions[].breaking` | нет | Несовместимые изменения: перед обновлением показать предупреждение |
| `versions[].security` | нет | Исправления безопасности: пометить обновление как срочное |
| `versions[].min_upgrade_from` | нет | С какой минимальной версии можно обновиться напрямую |
| `versions[].update_commands` | нет | Особые команды для этой версии (заменяют общие) |

Правила версий: первая версия **1.0.0**; мелкие обновления меняют третью цифру,
крупные — вторую, первую — только несовместимые изменения.

## Как выпустить новую версию проекта

1. Поднять версию в коде проекта, обновить CHANGELOG и справку, создать git-тег `vX.Y.Z`.
2. В этом репозитории добавить запись **в начало** `versions` в `<проект>.json` и поменять `latest`.
3. Выполнить `python3 tools/validate.py` (то же самое проверит GitHub Actions).
4. Сделать commit и push. Проекты увидят новую версию при следующей проверке.

Новый проект: скопировать `_template.json` в `<проект>.json` и заменить значения.

## Как проект проверяет обновления (алгоритм клиента)

Встраивается в каждый проект как модуль `update checker`:

1. **Когда проверять:** при запуске (в фоне, не задерживая старт), по расписанию
   (по умолчанию раз в 24 ч) и по кнопке «Проверить обновления» в интерфейсе или через API.
2. **Запрос:** GET на адрес выше, таймаут 5 с, заголовок `User-Agent: <проект>/<версия>`.
   Хранить ответ и `ETag`; повторные запросы отправлять с `If-None-Match`.
3. **Сравнение:** версии сравниваются как числа (`1.10.0 > 1.9.0`), а не как строки.
4. **Что показать:** все версии новее текущей с их `changes`, отметки `breaking` и `security`,
   а также команды для способа установки этого экземпляра (`linux`, `docker`…).
   Если в одной из версий есть свои `update_commands`, показывать их.
   Если текущая версия ниже `min_upgrade_from`, предложить обновляться поэтапно.
5. **Ошибки:** если сеть недоступна или файл повреждён, пишется WARNING в журнал,
   показываются последние сохранённые данные, а работа системы не прерывается.
6. **Настройки:** включение и выключение проверки, интервал, адрес источника
   (можно указать зеркало или локальный файл для закрытых сетей), способ установки.
7. **API проекта:** `GET /api/v1/version` — текущая версия;
   `GET /api/v1/updates` — результат последней проверки;
   `POST /api/v1/updates/check` — проверить сейчас.
8. **Отладка:** в режиме debug в журнал пишутся адрес, HTTP-код, время ответа и разобранный результат.

### Пример клиента (Python, стандартная библиотека)

```python
import json, urllib.request

def vtuple(v): return tuple(int(x) for x in v.split("."))

def check_updates(project, current, install="linux", timeout=5):
    url = f"https://raw.githubusercontent.com/lumenods/allupdsw/main/{project}.json"
    req = urllib.request.Request(url, headers={"User-Agent": f"{project}/{current}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    cur = vtuple(current)
    newer = [v for v in data["versions"] if vtuple(v["version"]) > cur]
    if not newer:
        return {"update_available": False, "current": current}
    latest = newer[0]
    cmds = (latest.get("update_commands") or data["update_commands"]).get(install, [])
    return {
        "update_available": True,
        "current": current,
        "latest": data["latest"],
        "breaking": any(v.get("breaking") for v in newer),
        "security": any(v.get("security") for v in newer),
        "stepwise": "min_upgrade_from" in latest and cur < vtuple(latest["min_upgrade_from"]),
        "changes": [{"version": v["version"], "date": v["date"], "changes": v["changes"]} for v in newer],
        "commands": cmds,
    }
```

### Пример (bash)

```bash
curl -fsS --max-time 5 https://raw.githubusercontent.com/lumenods/allupdsw/main/<проект>.json | jq '{latest, changes: .versions[0].changes, cmd: .update_commands.linux}'
```

> Примечание: `raw.githubusercontent.com` кэширует файлы до ~5 минут, поэтому новая версия
> становится видна проектам не сразу после push.

## Проекты

| Проект | Последняя версия | Репозиторий |
|---|---|---|
| [netmap](netmap.json) — карта сети | 1.4.0 | https://github.com/lumenods/NetMap |

## Лицензия

Содержимое репозитория — открытые метаданные. Сторонних библиотек нет
(валидатор использует только стандартную библиотеку Python, лицензия PSF).
