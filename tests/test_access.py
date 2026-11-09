"""Тесты манифеста прав доступа: tools/access_manifest.py."""
import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import access_manifest as am  # noqa: E402

EXAMPLE = json.loads((ROOT / "examples/access-manifest.example.json").read_text(encoding="utf-8"))


def m(**patch):
    x = copy.deepcopy(EXAMPLE)
    x.update(patch)
    return x


def perm(x, code):
    return next(p for p in x["permissions"] if p["code"] == code)


def role(x, code):
    return next(r for r in x["roles"] if r["code"] == code)


class CheckTests(unittest.TestCase):
    def assertErr(self, data, fragment):
        e, _ = am.check(data)
        self.assertTrue(any(fragment in s for s in e), f"нет ошибки '{fragment}': {e}")

    def assertWarn(self, data, fragment):
        e, w = am.check(data)
        self.assertEqual(e, [])
        self.assertTrue(any(fragment in s for s in w), f"нет предупреждения '{fragment}': {w}")

    def test_example_clean(self):
        self.assertEqual(am.check(EXAMPLE), ([], []))

    def test_root(self):
        self.assertErr([], "корень")

    def test_required_and_extra(self):
        for k in am.REQ_TOP:
            x = m(); del x[k]
            self.assertErr(x, f"'{k}'")
        self.assertErr(m(foo=1), "лишний ключ 'foo'")

    def test_versions_and_names(self):
        self.assertErr(m(manifest_version="2.0"), "manifest_version")
        self.assertErr(m(version="1.0"), "X.Y.Z")
        self.assertErr(m(project="Bad Name"), "project")

    def test_i18n(self):
        self.assertErr(m(title={"en": "x"}), "title.ru")
        self.assertErr(m(title={"ru": ""}), "title.ru")
        self.assertErr(m(title={"ru": "x", "de": "y"}), "лишний язык")
        self.assertErr(m(summary="текст"), "summary")
        self.assertWarn(m(summary={"ru": "x"}), "summary: нет перевода en")
        x = m(); perm(x, "app.tickets.view")["name"] = {"ru": "x", "en": ""}
        self.assertErr(x, ".en: пустой")

    def test_auth(self):
        self.assertErr(m(auth={"sso": "ldap"}), "auth.sso")
        self.assertErr(m(auth={"sso": "none", "local_users": False}), "невозможно")
        self.assertErr(m(auth={"scim": "yes"}), "auth.scim")
        self.assertErr(m(auth={"x": 1}), "лишний ключ 'x'")

    def test_permission_codes(self):
        for bad in ("tickets", "App.x", "app..x", "app.x.", "1app.x"):
            x = m(); x["permissions"][0]["code"] = bad
            self.assertErr(x, "некорректный code")
        x = m(); x["permissions"][1]["code"] = "app.tickets.view"
        self.assertErr(x, "дубликат")

    def test_permissions_empty(self):
        self.assertErr(m(permissions=[]), "permissions")

    def test_risk(self):
        x = m(); perm(x, "app.tickets.view")["risk"] = "huge"
        self.assertErr(x, "risk")
        x = m(); del perm(x, "app.reports.finance")["description"]
        self.assertWarn(x, "нужно описание")

    def test_module(self):
        x = m(); perm(x, "app.tickets.view")["module"] = "nope"
        self.assertErr(x, "неизвестный module")
        x = m(); del perm(x, "app.tickets.view")["module"]
        self.assertWarn(x, "не указан module")
        x = m(modules=[])
        self.assertErr(x, "список modules пуст")

    def test_requires_conflicts_refs(self):
        x = m(); perm(x, "app.tickets.edit")["requires"] = ["app.nope.x"]
        self.assertErr(x, "requires неизвестное")
        x = m(); perm(x, "app.tickets.edit")["requires"] = ["app.tickets.edit"]
        self.assertErr(x, "требует само себя")
        x = m(); perm(x, "app.tickets.edit")["conflicts"] = ["app.tickets.edit"]
        self.assertErr(x, "само с собой")
        x = m(); perm(x, "app.tickets.edit")["conflicts"] = ["app.tickets.view"]
        self.assertErr(x, "одновременно в requires и conflicts")
        x = m(); perm(x, "app.tickets.edit")["requires"] = "app.tickets.view"
        self.assertErr(x, "список строк")

    def test_requires_cycle(self):
        x = m(); perm(x, "app.tickets.view")["requires"] = ["app.tickets.edit"]
        self.assertErr(x, "цикл в requires")

    def test_transitive_conflict(self):
        x = m()
        perm(x, "app.reports.finance")["requires"] = ["app.tickets.approve"]
        perm(x, "app.reports.finance")["conflicts"] = ["app.tickets.view"]
        self.assertErr(x, "требует 'app.tickets.view', но конфликтует")

    def test_scopable(self):
        x = m(); perm(x, "app.tickets.view")["scopable"] = ["city"]
        self.assertErr(x, "неизвестный scope")

    def test_role_unknown_perm_and_mask(self):
        x = m(); role(x, "viewer")["permissions"] = ["app.nope"]
        self.assertErr(x, "не соответствует ни одному")
        x = m(); role(x, "viewer")["permissions"] = ["app.nope.*"]
        self.assertErr(x, "не соответствует ни одному")
        x = m(); role(x, "viewer")["permissions"] = ["app.*.view"]
        self.assertErr(x, "некорректный код или маска")

    def test_mask_expands(self):
        r = role(EXAMPLE, "admin")
        self.assertEqual(am.expand_role(r, {p["code"] for p in EXAMPLE["permissions"]}),
                         {"app.admin.access", "app.admin.debug", "app.tickets.view"})
        self.assertEqual(am.match("app.tickets.*", ["app.tickets.view", "app.ticketsx.y"]), ["app.tickets.view"])

    def test_role_missing_requires(self):
        x = m(); role(x, "operator")["permissions"] = ["app.tickets.edit"]
        self.assertErr(x, "требует 'app.tickets.view', которого нет в роли")

    def test_role_conflict(self):
        x = m(); role(x, "operator")["permissions"].append("app.tickets.approve")
        self.assertErr(x, "несовместимые права")

    def test_conflict_is_symmetric(self):
        x = m()
        perm(x, "app.tickets.approve")["conflicts"] = []
        perm(x, "app.tickets.edit")["conflicts"] = ["app.tickets.approve"]
        role(x, "operator")["permissions"].append("app.tickets.approve")
        self.assertErr(x, "несовместимые права")

    def test_default_role_rules(self):
        x = m(); role(x, "operator")["default"] = True
        self.assertErr(x, "только одна")
        x = m(); role(x, "viewer")["permissions"].append("app.reports.finance")
        self.assertErr(x, "по умолчанию не должна")

    def test_role_flags(self):
        x = m(); role(x, "viewer")["system"] = "yes"
        self.assertErr(x, "system")

    def test_role_dupe_and_empty(self):
        x = m(); x["roles"][1]["code"] = "viewer"
        self.assertErr(x, "дубликат")
        self.assertErr(m(roles=[]), "roles")

    def test_warnings(self):
        x = m(); role(x, "supervisor")["permissions"] = ["app.tickets.view", "app.tickets.approve"]
        self.assertWarn(x, "не входит ни в одну роль")
        x = m(); perm(x, "app.tickets.view")["deprecated"] = True
        self.assertWarn(x, "устаревшее право")
        x = m(); role(x, "viewer")["permissions"] = ["app.tickets.view", "app.tickets.view"]
        self.assertWarn(x, "повторяющиеся")
        x = m(); role(x, "admin")["system"] = False
        self.assertWarn(x, "нет системной роли")
        x = m(); x["permissions"][0]["code"] = "other.tickets.view"
        for r in x["roles"]:
            r["permissions"] = ["other.tickets.view" if p == "app.tickets.view" else p for p in r["permissions"]]
        for p in x["permissions"]:
            p["requires"] = ["other.tickets.view" if c == "app.tickets.view" else c for c in p.get("requires", [])]
        self.assertWarn(x, "разные префиксы")

    def test_endpoints(self):
        self.assertWarn(m(endpoints={"weird": "/x"}), "нестандартный")
        self.assertErr(m(endpoints={"roles": 1}), "endpoints")
        self.assertEqual(am.check(m(endpoints={"roles": "/api/v2/roles"})), ([], []))


class SummaryTests(unittest.TestCase):
    def test_ru(self):
        s = am.summarize(EXAMPLE, "ru")
        self.assertIn("# Пример проекта (project-name)", s)
        self.assertIn("**Администратор** (`admin`) — встроенная, права не меняются", s)
        self.assertIn("Права: Финансовые отчёты", s)
        self.assertIn("несовместимо с app.tickets.edit", s)
        self.assertIn("риск: критичный", s)
        self.assertLess(s.index("### Заявки"), s.index("### Администрирование"))  # порядок модулей

    def test_en_and_fallback(self):
        s = am.summarize(EXAMPLE, "en")
        self.assertIn("Example project", s)
        self.assertIn("risk: critical", s)
        x = copy.deepcopy(EXAMPLE); del x["title"]["en"]
        self.assertIn("# Пример проекта", am.summarize(x, "en"))
        self.assertIn("# Пример проекта", am.summarize(EXAMPLE, "de"))  # неизвестный язык → ru

    def test_tolerates_minimal(self):
        s = am.summarize({"project": "p", "title": {"ru": "П"}, "permissions": [], "roles": []})
        self.assertIn("# П (p)", s)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = am.main(list(args))
        return code, buf.getvalue()

    def test_check_ok_and_bad(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text(json.dumps(m(version="x")), encoding="utf-8")
            broken = Path(d) / "broken.json"
            broken.write_text("{", encoding="utf-8")
            ok = str(ROOT / "examples/access-manifest.example.json")
            self.assertEqual(self.run_cli("check", ok)[0], 0)
            code, out = self.run_cli("check", ok, str(bad), str(broken))
            self.assertEqual(code, 1)
            self.assertIn("не удалось загрузить", out)

    def test_summary(self):
        code, out = self.run_cli("summary", str(ROOT / "examples/access-manifest.example.json"), "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn("## Roles", out)


class SchemaSyncTests(unittest.TestCase):
    def test_schema_matches_tool(self):
        sc = json.loads((ROOT / "schema/access-manifest.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(sc["properties"]), am.TOP)
        self.assertEqual(set(sc["required"]), set(am.REQ_TOP))
        self.assertEqual(set(sc["properties"]["auth"]["properties"]), am.AUTH_KEYS)
        self.assertEqual(set(sc["properties"]["permissions"]["items"]["properties"]), am.PERM_KEYS)
        self.assertEqual(set(sc["properties"]["roles"]["items"]["properties"]), am.ROLE_KEYS)
        self.assertEqual(set(sc["properties"]["modules"]["items"]["properties"]), am.MOD_KEYS)
        self.assertEqual(set(sc["properties"]["scopes"]["items"]["properties"]), am.SCOPE_KEYS)
        self.assertEqual(tuple(sc["properties"]["permissions"]["items"]["properties"]["risk"]["enum"]), am.RISKS)


if __name__ == "__main__":
    unittest.main()
