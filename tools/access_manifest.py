#!/usr/bin/env python3
"""Проверка и краткая сводка манифеста прав доступа (только стандартная библиотека).

Манифест отдаёт каждый проект: GET /api/v1/access/manifest.
Формат: schema/access-manifest.schema.json, пример: examples/access-manifest.example.json.

CLI:
    python3 tools/access_manifest.py check   <файл|URL> [...]
    python3 tools/access_manifest.py summary <файл|URL> [--lang ru|en]

Как модуль (например, в тестах проекта или в центре авторизации):
    from access_manifest import check, summarize, expand_role
    errors, warnings = check(manifest)
"""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
PERM = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
ROLE_PERM = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
RISKS = ("low", "medium", "high", "critical")

TOP = {"$schema", "manifest_version", "project", "version", "title", "summary", "auth",
       "modules", "scopes", "permissions", "roles", "endpoints"}
REQ_TOP = ("manifest_version", "project", "version", "title", "summary", "permissions", "roles")
AUTH_KEYS = {"sso", "local_users", "groups_claim", "roles_claim", "scim"}
MOD_KEYS = {"code", "name", "description"}
SCOPE_KEYS = {"code", "name", "description", "values_endpoint"}
PERM_KEYS = {"code", "module", "name", "description", "risk", "requires", "conflicts", "scopable", "deprecated"}
ROLE_KEYS = {"code", "name", "description", "permissions", "system", "editable", "default"}

# Стандартные пути API управления доступом (раздел 14 концепции).
STANDARD_ENDPOINTS = {
    "manifest": "GET /api/v1/access/manifest",
    "summary": "GET /api/v1/access/summary?lang=ru|en",
    "permissions": "GET /api/v1/access/permissions",
    "roles": "GET|POST /api/v1/access/roles; GET|PATCH|DELETE /api/v1/access/roles/{id}",
    "role_permissions": "PUT /api/v1/access/roles/{id}/permissions",
    "groups": "GET|POST /api/v1/access/groups; GET|PATCH|DELETE /api/v1/access/groups/{id}",
    "group_roles": "PUT /api/v1/access/groups/{id}/roles",
    "group_members": "GET|PUT /api/v1/access/groups/{id}/members",
    "mappings": "GET|POST /api/v1/access/mappings; DELETE /api/v1/access/mappings/{id}",
    "users": "GET /api/v1/access/users; GET|PATCH /api/v1/access/users/{id}",
    "user_roles": "PUT /api/v1/access/users/{id}/roles",
    "user_effective": "GET /api/v1/access/users/{id}/effective",
    "check": "POST /api/v1/access/check",
    "sync": "POST /api/v1/access/sync",
    "audit": "GET /api/v1/access/audit?from=...&to=...",
}


class _Ctx:
    def __init__(self):
        self.errors, self.warnings = [], []

    def err(self, m):
        self.errors.append(m)

    def warn(self, m):
        self.warnings.append(m)


def _i18n(ctx, obj, where, required=True):
    if obj is None:
        if required:
            ctx.err(f"{where}: обязательно")
        return
    if not isinstance(obj, dict):
        ctx.err(f"{where}: нужен объект {{ru, en}}")
        return
    for k in sorted(set(obj) - {"ru", "en"}):
        ctx.err(f"{where}: лишний язык '{k}'")
    if not isinstance(obj.get("ru"), str) or not obj.get("ru", "").strip():
        ctx.err(f"{where}.ru: обязателен непустой текст")
    if "en" not in obj:
        ctx.warn(f"{where}: нет перевода en")
    elif not isinstance(obj["en"], str) or not obj["en"].strip():
        ctx.err(f"{where}.en: пустой текст")


def _extra(ctx, obj, allowed, where):
    for k in sorted(set(obj) - allowed):
        ctx.err(f"{where}: лишний ключ '{k}'")


def _list_of_str(ctx, v, where):
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        ctx.err(f"{where}: нужен список строк")
        return []
    return v


def match(pattern, codes):
    """Коды прав, подходящие под код или маску 'a.b.*'."""
    if pattern.endswith(".*"):
        prefix = pattern[:-1]
        return [c for c in codes if c.startswith(prefix)]
    return [pattern] if pattern in codes else []


def expand_role(role, perm_codes):
    out = set()
    for p in role.get("permissions", []):
        if isinstance(p, str):
            out.update(match(p, perm_codes))
    return out


def check(m):
    """Вернуть (errors, warnings) для манифеста-словаря."""
    ctx = _Ctx()
    if not isinstance(m, dict):
        return ["корень должен быть объектом"], []
    _extra(ctx, m, TOP, "манифест")
    for k in REQ_TOP:
        if k not in m:
            ctx.err(f"нет обязательного ключа '{k}'")
    if ctx.errors:
        return ctx.errors, ctx.warnings

    if not re.match(r"^1\.\d+$", str(m["manifest_version"])):
        ctx.err("manifest_version: поддерживается 1.x")
    if not PROJECT.match(str(m["project"])):
        ctx.err("project: только a-z 0-9 _ -")
    if not SEMVER.match(str(m["version"])):
        ctx.err("version: формат X.Y.Z")
    _i18n(ctx, m["title"], "title")
    _i18n(ctx, m["summary"], "summary")

    auth = m.get("auth")
    if auth is not None:
        if not isinstance(auth, dict):
            ctx.err("auth: нужен объект")
        else:
            _extra(ctx, auth, AUTH_KEYS, "auth")
            if "sso" in auth and auth["sso"] not in ("oidc", "saml", "none"):
                ctx.err("auth.sso: oidc | saml | none")
            for b in ("local_users", "scim"):
                if b in auth and not isinstance(auth[b], bool):
                    ctx.err(f"auth.{b}: true/false")
            if auth.get("sso") == "none" and auth.get("local_users") is False:
                ctx.err("auth: sso=none и local_users=false — войти будет невозможно")

    def codes_of(items, name, keys, pattern):
        seen = []
        if not isinstance(items, list):
            ctx.err(f"{name}: нужен список")
            return []
        for i, it in enumerate(items):
            w = f"{name}[{i}]"
            if not isinstance(it, dict):
                ctx.err(f"{w}: нужен объект")
                continue
            _extra(ctx, it, keys, w)
            c = it.get("code")
            if not isinstance(c, str) or not pattern.match(c):
                ctx.err(f"{w}: некорректный code {c!r}")
                continue
            if c in seen:
                ctx.err(f"{name}: дубликат code '{c}'")
            seen.append(c)
            _i18n(ctx, it.get("name"), f"{name} '{c}'.name")
            if "description" in it:
                _i18n(ctx, it["description"], f"{name} '{c}'.description")
        return seen

    modules = set(codes_of(m.get("modules", []), "modules", MOD_KEYS, CODE))
    scopes = set(codes_of(m.get("scopes", []), "scopes", SCOPE_KEYS, CODE))
    perms_list = m["permissions"]
    if isinstance(perms_list, list) and not perms_list:
        ctx.err("permissions: нужен хотя бы один элемент")
    perm_codes = codes_of(perms_list, "permissions", PERM_KEYS, PERM)
    pset = set(perm_codes)
    perms = {p["code"]: p for p in perms_list if isinstance(p, dict) and p.get("code") in pset}

    prefixes = {c.split(".")[0] for c in perm_codes}
    if len(prefixes) > 1:
        ctx.warn(f"permissions: разные префиксы кодов {sorted(prefixes)} — обычно один префикс на проект")

    for c, p in perms.items():
        w = f"право '{c}'"
        if p.get("risk") not in RISKS:
            ctx.err(f"{w}: risk — одно из {list(RISKS)}")
        if "module" in p:
            if not modules:
                ctx.err(f"{w}: указан module, но список modules пуст")
            elif p["module"] not in modules:
                ctx.err(f"{w}: неизвестный module '{p['module']}'")
        elif modules:
            ctx.warn(f"{w}: не указан module")
        if "deprecated" in p and not isinstance(p["deprecated"], bool):
            ctx.err(f"{w}: deprecated — true/false")
        req = _list_of_str(ctx, p.get("requires", []), f"{w}.requires")
        con = _list_of_str(ctx, p.get("conflicts", []), f"{w}.conflicts")
        for r in req:
            if r == c:
                ctx.err(f"{w}: требует само себя")
            elif r not in pset:
                ctx.err(f"{w}: requires неизвестное право '{r}'")
        for r in con:
            if r == c:
                ctx.err(f"{w}: конфликтует само с собой")
            elif r not in pset:
                ctx.err(f"{w}: conflicts неизвестное право '{r}'")
        for r in set(req) & set(con):
            ctx.err(f"{w}: '{r}' одновременно в requires и conflicts")
        for s in _list_of_str(ctx, p.get("scopable", []), f"{w}.scopable"):
            if s not in scopes:
                ctx.err(f"{w}: scopable неизвестный scope '{s}'")
        if p.get("risk") in ("high", "critical") and "description" not in p:
            ctx.warn(f"{w}: для risk={p.get('risk')} нужно описание, что именно даёт право")

    # Циклы в requires и конфликт через зависимости.
    closure = {}

    def deps(c, stack=()):
        if c in closure:
            return closure[c]
        if c in stack:
            ctx.err(f"цикл в requires: {' → '.join(stack + (c,))}")
            return set()
        out = set()
        for r in perms[c].get("requires", []) if isinstance(perms[c].get("requires", []), list) else []:
            if r in perms and r != c:
                out |= {r} | deps(r, stack + (c,))
        closure[c] = out
        return out

    for c in perms:
        deps(c)
    conflicts = {c: set(x for x in (p.get("conflicts") or []) if isinstance(x, str)) for c, p in perms.items()}
    for c in perms:
        for x in conflicts[c]:
            if c not in conflicts.get(x, set()) and x in perms:
                conflicts.setdefault(x, set()).add(c)  # конфликт симметричен
    for c, d in closure.items():
        for x in d:
            if x in conflicts.get(c, set()):
                ctx.err(f"право '{c}': требует '{x}', но конфликтует с ним")

    roles = m["roles"]
    role_codes = codes_of(roles, "roles", ROLE_KEYS, CODE)
    if isinstance(roles, list) and not roles:
        ctx.err("roles: нужна хотя бы одна роль")
    defaults = 0
    used = set()
    for r in roles if isinstance(roles, list) else []:
        if not isinstance(r, dict) or r.get("code") not in role_codes:
            continue
        w = f"роль '{r['code']}'"
        for b in ("system", "editable", "default"):
            if b in r and not isinstance(r[b], bool):
                ctx.err(f"{w}: {b} — true/false")
        if r.get("default") is True:
            defaults += 1
        plist = _list_of_str(ctx, r.get("permissions"), f"{w}.permissions")
        for p in plist:
            if not ROLE_PERM.match(p):
                ctx.err(f"{w}: некорректный код или маска '{p}'")
            elif not match(p, pset):
                ctx.err(f"{w}: '{p}' не соответствует ни одному праву")
        if len(plist) != len(set(plist)):
            ctx.warn(f"{w}: повторяющиеся права")
        eff = expand_role(r, pset)
        used |= eff
        if not eff:
            ctx.warn(f"{w}: роль без прав")
        for p in sorted(eff):
            missing = closure.get(p, set()) - eff
            for x in sorted(missing):
                ctx.err(f"{w}: право '{p}' требует '{x}', которого нет в роли")
            for x in sorted(conflicts.get(p, set()) & eff):
                if p < x:
                    ctx.err(f"{w}: несовместимые права '{p}' и '{x}'")
            if perms[p].get("deprecated"):
                ctx.warn(f"{w}: содержит устаревшее право '{p}'")
        if r.get("default") and any(perms[p].get("risk") in ("high", "critical") for p in eff):
            ctx.err(f"{w}: роль по умолчанию не должна давать права с risk high/critical")
    if defaults > 1:
        ctx.err("roles: ролью по умолчанию может быть только одна")
    for p in sorted(pset - used):
        if not perms[p].get("deprecated"):
            ctx.warn(f"право '{p}' не входит ни в одну роль")
    admin_like = [r for r in roles if isinstance(r, dict) and any(
        perms.get(p, {}).get("risk") == "critical" for p in expand_role(r, pset))]
    if not any(r.get("system") for r in admin_like) and any(perms[p].get("risk") == "critical" for p in perms):
        ctx.warn("нет системной роли с критичными правами (администратор): легко потерять доступ")

    eps = m.get("endpoints")
    if eps is not None:
        if not isinstance(eps, dict) or not all(isinstance(v, str) for v in eps.values()):
            ctx.err("endpoints: объект строк")
        else:
            for k in sorted(set(eps) - set(STANDARD_ENDPOINTS)):
                ctx.warn(f"endpoints: нестандартный ключ '{k}'")
    return ctx.errors, ctx.warnings


def _t(obj, lang):
    if not isinstance(obj, dict):
        return ""
    return (lang == "en" and obj.get("en")) or obj.get("ru", "")


RISK_LABEL = {
    "ru": {"low": "низкий", "medium": "средний", "high": "высокий", "critical": "критичный"},
    "en": {"low": "low", "medium": "medium", "high": "high", "critical": "critical"},
}
L = {
    "ru": {"version": "Версия", "roles": "Роли", "perms": "Права", "risk": "риск", "requires": "требует",
           "conflicts": "несовместимо с", "scope": "ограничивается по", "default": "по умолчанию",
           "system": "встроенная", "locked": "права не меняются", "sso": "Вход", "local": "локальные пользователи",
           "yes": "да", "no": "нет", "deprecated": "устарело", "scopes": "Ограничения (scope)"},
    "en": {"version": "Version", "roles": "Roles", "perms": "Permissions", "risk": "risk", "requires": "requires",
           "conflicts": "conflicts with", "scope": "scopable by", "default": "default",
           "system": "built-in", "locked": "permissions locked", "sso": "Sign-in", "local": "local users",
           "yes": "yes", "no": "no", "deprecated": "deprecated", "scopes": "Scopes"},
}


def summarize(m, lang="ru"):
    """Краткое человекочитаемое описание (Markdown): что даёт проект, роли и права.

    Именно это отдаёт GET /api/v1/access/summary?lang=..."""
    lang = "en" if lang == "en" else "ru"
    t = L[lang]
    perms = {p["code"]: p for p in m.get("permissions", []) if isinstance(p, dict) and "code" in p}
    pset = set(perms)
    mods = {x["code"]: x for x in m.get("modules", []) if isinstance(x, dict)}
    out = [f"# {_t(m.get('title'), lang)} ({m.get('project')})", "",
           f"{t['version']}: {m.get('version')}", "", _t(m.get("summary"), lang), ""]
    auth = m.get("auth") or {}
    if auth:
        out.append(f"{t['sso']}: {auth.get('sso', 'none')}; {t['local']}: "
                   f"{t['yes'] if auth.get('local_users') else t['no']}")
        out.append("")
    out += [f"## {t['roles']}", ""]
    for r in m.get("roles", []):
        if not isinstance(r, dict):
            continue
        flags = [t[k] for k in ("default", "system") if r.get(k)]
        if r.get("editable") is False:
            flags.append(t["locked"])
        head = f"- **{_t(r.get('name'), lang)}** (`{r.get('code')}`)" + (f" — {', '.join(flags)}" if flags else "")
        out.append(head)
        if r.get("description"):
            out.append(f"  {_t(r['description'], lang)}")
        names = [_t(perms[p].get("name"), lang) for p in sorted(expand_role(r, pset))]
        if names:
            out.append(f"  {t['perms']}: {'; '.join(names)}")
    out += ["", f"## {t['perms']}", ""]
    by_mod = {}
    for c, p in perms.items():
        by_mod.setdefault(p.get("module", ""), []).append(p)
    order = list(mods) + sorted(k for k in by_mod if k not in mods)
    for mod in [k for k in order if k in by_mod]:
        if mod:
            out.append(f"### {_t(mods.get(mod, {}).get('name'), lang) or mod}")
        for p in by_mod[mod]:
            extra = [f"{t['risk']}: {RISK_LABEL[lang].get(p.get('risk'), p.get('risk'))}"]
            if p.get("requires"):
                extra.append(f"{t['requires']} {', '.join(p['requires'])}")
            if p.get("conflicts"):
                extra.append(f"{t['conflicts']} {', '.join(p['conflicts'])}")
            if p.get("scopable"):
                extra.append(f"{t['scope']} {', '.join(p['scopable'])}")
            if p.get("deprecated"):
                extra.append(t["deprecated"])
            line = f"- `{p['code']}` — {_t(p.get('name'), lang)} ({'; '.join(extra)})"
            out.append(line)
            if p.get("description"):
                out.append(f"  {_t(p['description'], lang)}")
        out.append("")
    if m.get("scopes"):
        out += [f"## {t['scopes']}", ""]
        for s in m["scopes"]:
            if isinstance(s, dict):
                d = _t(s.get("description"), lang)
                out.append(f"- `{s.get('code')}` — {_t(s.get('name'), lang)}" + (f": {d}" if d else ""))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def load(src, timeout=10):
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(urllib.request.Request(src, headers={"User-Agent": "allupdsw-access-check"}),
                                    timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    return json.loads(Path(src).read_text(encoding="utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Манифест прав доступа: проверка и сводка")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("sources", nargs="+")
    s = sub.add_parser("summary")
    s.add_argument("source")
    s.add_argument("--lang", default="ru", choices=["ru", "en"])
    a = ap.parse_args(argv)

    if a.cmd == "summary":
        sys.stdout.write(summarize(load(a.source), a.lang))
        return 0
    bad = 0
    for src in a.sources:
        try:
            errs, warns = check(load(src))
        except Exception as e:  # noqa: BLE001
            errs, warns = [f"не удалось загрузить: {e}"], []
        for w in warns:
            print(f"! {src}: {w}")
        if errs:
            bad += 1
            print(f"✗ {src}")
            for e in errs:
                print(f"    - {e}")
        else:
            print(f"✓ {src}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
