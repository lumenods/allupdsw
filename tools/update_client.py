#!/usr/bin/env python3
"""Эталонный клиент проверки обновлений allupdsw (только стандартная библиотека).

Можно копировать в Python-проекты как есть или использовать как образец для других языков.

    from update_client import check_updates
    info = check_updates("myproject", "1.0.0", install="docker", lang="en")

CLI:
    python3 tools/update_client.py <project> <current_version> [--install linux] [--lang ru|en] [--source URL|PATH]
"""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

DEFAULT_SOURCE = "https://raw.githubusercontent.com/lumenods/allupdsw/main/{project}.json"
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class UpdateCheckError(Exception):
    """Ошибка проверки обновлений (сеть, формат). Проект должен залогировать и продолжить работу."""


def vtuple(v):
    m = _SEMVER.match(str(v).strip())
    if not m:
        raise UpdateCheckError(f"некорректная версия: {v!r}")
    return tuple(int(x) for x in m.groups())


def fetch(project, source=None, timeout=5, user_agent=None):
    """Загрузить JSON проекта. source: URL-шаблон с {project}, URL или путь к локальному файлу."""
    src = (source or DEFAULT_SOURCE).replace("{project}", project)
    try:
        if src.startswith(("http://", "https://", "file://")):
            req = urllib.request.Request(src, headers={"User-Agent": user_agent or f"{project}/update-check"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
        else:
            raw = Path(src).read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except UpdateCheckError:
        raise
    except Exception as e:  # noqa: BLE001 — сеть/файл/JSON: всё приводим к одной ошибке
        raise UpdateCheckError(f"не удалось получить {src}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("versions"), list):
        raise UpdateCheckError("неверный формат файла версий")
    return data


def evaluate(data, current, install="linux", lang="ru"):
    """Чистая функция: сравнить текущую версию с данными реестра."""
    cur = vtuple(current)
    newer = []
    for v in data["versions"]:
        try:
            if vtuple(v["version"]) > cur:
                newer.append(v)
        except (KeyError, TypeError, UpdateCheckError):
            continue  # битую запись пропускаем, а не падаем
    newer.sort(key=lambda v: vtuple(v["version"]), reverse=True)

    result = {
        "update_available": bool(newer),
        "current": current,
        "latest": newer[0]["version"] if newer else current,
        "ahead": bool(data.get("latest")) and _safe_gt(cur, data.get("latest")),
    }
    if not newer:
        return result

    target = newer[0]
    commands_map = target.get("update_commands") or data.get("update_commands") or {}
    min_from = target.get("min_upgrade_from")
    result.update({
        "breaking": any(v.get("breaking") for v in newer),
        "security": any(v.get("security") for v in newer),
        "stepwise": bool(min_from) and cur < vtuple(min_from),
        "min_upgrade_from": min_from,
        "changes": [
            {
                "version": v["version"],
                "date": v.get("date"),
                "changes": (lang == "en" and v.get("changes_en")) or v.get("changes") or [],
            }
            for v in newer
        ],
        "commands": commands_map.get(install, []),
        "install_methods": sorted(commands_map),
    })
    return result


def _safe_gt(cur, latest):
    try:
        return cur > vtuple(latest)
    except UpdateCheckError:
        return False


def check_updates(project, current, install="linux", lang="ru", source=None, timeout=5):
    data = fetch(project, source=source, timeout=timeout, user_agent=f"{project}/{current}")
    return evaluate(data, current, install=install, lang=lang)


def main(argv=None):
    p = argparse.ArgumentParser(description="Проверка обновлений через allupdsw")
    p.add_argument("project")
    p.add_argument("current")
    p.add_argument("--install", default="linux")
    p.add_argument("--lang", default="ru", choices=["ru", "en"])
    p.add_argument("--source")
    p.add_argument("--timeout", type=float, default=5)
    a = p.parse_args(argv)
    try:
        res = check_updates(a.project, a.current, a.install, a.lang, a.source, a.timeout)
    except UpdateCheckError as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
