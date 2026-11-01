#!/usr/bin/env python3
"""Проверка файлов версий проектов allupdsw (только стандартная библиотека).

Использование:
    python3 tools/validate.py            # проверить все *.json в корне
    python3 tools/validate.py proj.json  # проверить конкретные файлы
"""
import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
TOP_KEYS = {"$schema", "project", "title", "title_en", "repository", "latest", "update_commands", "versions"}
VER_KEYS = {"version", "date", "type", "changes", "changes_en", "breaking", "security", "min_upgrade_from", "update_commands"}
TYPES = {"initial", "patch", "minor", "major"}


def parse(v):
    m = SEMVER.match(v or "")
    return tuple(map(int, m.groups())) if m else None


def bump_type(newer, older):
    if newer[0] != older[0]:
        return "major"
    if newer[1] != older[1]:
        return "minor"
    return "patch"


def check(path: Path, warns=None):
    warns = [] if warns is None else warns
    errs = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [f"не читается JSON: {e}"]
    if not isinstance(data, dict):
        return ["корень должен быть объектом"]

    for k in sorted(set(data) - TOP_KEYS):
        errs.append(f"лишний ключ '{k}'")
    for k in ("project", "repository", "latest", "update_commands", "versions"):
        if k not in data:
            errs.append(f"нет обязательного ключа '{k}'")
    if errs:
        return errs

    proj = data["project"]
    if not NAME.match(str(proj)):
        errs.append(f"project '{proj}': только a-z 0-9 _ -")
    if not path.name.startswith("_") and path.stem != proj:
        errs.append(f"имя файла '{path.name}' не совпадает с project '{proj}'")
    if not str(data["repository"]).startswith("https://"):
        errs.append("repository должен начинаться с https://")

    uc = data["update_commands"]
    if not isinstance(uc, dict) or not uc:
        errs.append("update_commands: нужен непустой объект")
    else:
        for k, cmds in uc.items():
            if not isinstance(cmds, list) or not cmds or not all(isinstance(c, str) and c.strip() for c in cmds):
                errs.append(f"update_commands.{k}: нужен непустой список строк")

    vers = data["versions"]
    if not isinstance(vers, list) or not vers:
        return errs + ["versions: нужен непустой список"]

    seen = set()
    prev = None
    for i, v in enumerate(vers):
        where = f"versions[{i}]"
        if not isinstance(v, dict):
            errs.append(f"{where}: должен быть объектом")
            continue
        for k in sorted(set(v) - VER_KEYS):
            errs.append(f"{where}: лишний ключ '{k}'")
        pv = parse(v.get("version"))
        if not pv:
            errs.append(f"{where}: version '{v.get('version')}' не в формате X.Y.Z")
            continue
        where = f"версия {v['version']}"
        if pv in seen:
            errs.append(f"{where}: дубликат")
        seen.add(pv)
        try:
            date.fromisoformat(v.get("date", ""))
        except ValueError:
            errs.append(f"{where}: date должна быть YYYY-MM-DD")
        if v.get("type") not in TYPES:
            errs.append(f"{where}: type должен быть одним из {sorted(TYPES)}")
        ch = v.get("changes")
        if not isinstance(ch, list) or not ch or not all(isinstance(c, str) and c.strip() for c in ch):
            errs.append(f"{where}: changes — непустой список строк")
        if "changes_en" in v:
            ce = v["changes_en"]
            if not isinstance(ce, list) or not ce or not all(isinstance(c, str) and c.strip() for c in ce):
                errs.append(f"{where}: changes_en — непустой список строк")
        else:
            warns.append(f"{where}: нет changes_en (английский перевод)")
        for flag in ("breaking", "security"):
            if flag in v and not isinstance(v[flag], bool):
                errs.append(f"{where}: {flag} должен быть true/false")
        if "min_upgrade_from" in v:
            mu = parse(v["min_upgrade_from"])
            if not mu:
                errs.append(f"{where}: min_upgrade_from не в формате X.Y.Z")
            elif mu >= pv:
                errs.append(f"{where}: min_upgrade_from должна быть меньше самой версии")
        if prev is not None:
            pprev, vprev = prev
            if pv >= pprev:
                errs.append(f"{where}: список должен идти от новой версии к старой")
            else:
                expected = bump_type(pprev, pv)
                if vprev.get("type") not in (expected, None) and vprev.get("type") != "initial":
                    errs.append(f"версия {vprev['version']}: type '{vprev.get('type')}', а по номеру это '{expected}'")
                try:
                    if date.fromisoformat(vprev["date"]) < date.fromisoformat(v["date"]):
                        errs.append(f"версия {vprev['version']}: дата раньше, чем у {v['version']}")
                except (ValueError, KeyError, TypeError):
                    pass
        prev = (pv, v)

    last = vers[-1]
    if isinstance(last, dict) and parse(last.get("version")) == (1, 0, 0) and last.get("type") != "initial":
        errs.append("версия 1.0.0 должна иметь type 'initial'")
    if isinstance(vers[0], dict) and data["latest"] != vers[0].get("version"):
        errs.append(f"latest '{data['latest']}' не равен первой версии в списке '{vers[0].get('version')}'")
    return errs


def main(argv):
    files = [Path(a) for a in argv] if argv else sorted(ROOT.glob("*.json"))
    bad = 0
    for f in files:
        warns = []
        errs = check(f, warns)
        for w in warns:
            print(f"! {f.name}: {w}")
        if errs:
            bad += 1
            print(f"✗ {f.name}")
            for e in errs:
                print(f"    - {e}")
        else:
            print(f"✓ {f.name}")
    print(f"\nПроверено: {len(files)}, с ошибками: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
