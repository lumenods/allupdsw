"""Тесты allupdsw: валидатор, эталонный клиент, реальные файлы репозитория.

Запуск: python3 -m unittest discover -s tests -v
"""
import copy
import http.server
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import update_client as uc  # noqa: E402
import validate as val  # noqa: E402

BASE = {
    "project": "demo",
    "title": "Демо",
    "title_en": "Demo",
    "repository": "https://github.com/lumenods/demo",
    "latest": "1.2.0",
    "update_commands": {"linux": ["git pull"], "docker": ["docker compose pull", "docker compose up -d"]},
    "versions": [
        {"version": "1.2.0", "date": "2026-11-10", "type": "minor", "changes": ["Новое"], "changes_en": ["New"]},
        {"version": "1.1.1", "date": "2026-11-05", "type": "patch", "changes": ["Исправлено"], "changes_en": ["Fixed"]},
        {"version": "1.1.0", "date": "2026-11-03", "type": "minor", "changes": ["Фича"], "changes_en": ["Feature"]},
        {"version": "1.0.0", "date": "2026-10-31", "type": "initial", "changes": ["Первый"], "changes_en": ["Initial"]},
    ],
}


class Tmp:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()

    def write(self, data, name="demo.json", raw=None):
        p = Path(self.dir.name) / name
        p.write_text(raw if raw is not None else json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return p


def d(**patch):
    x = copy.deepcopy(BASE)
    x.update(patch)
    return x


# ---------------------------------------------------------------- validator
class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.t = Tmp()

    def tearDown(self):
        self.t.dir.cleanup()

    def errs(self, data, name="demo.json", raw=None, warns=None):
        return val.check(self.t.write(data, name, raw), warns)

    def assertErr(self, data, fragment, **kw):
        e = self.errs(data, **kw)
        self.assertTrue(any(fragment in x for x in e), f"ожидалась ошибка с '{fragment}', получено: {e}")

    def test_valid(self):
        w = []
        self.assertEqual(self.errs(BASE, warns=w), [])
        self.assertEqual(w, [])

    def test_bad_json(self):
        self.assertErr(None, "не читается JSON", raw="{oops")

    def test_root_not_object(self):
        self.assertErr(None, "корень", raw="[]")

    def test_missing_required(self):
        for k in ("project", "repository", "latest", "update_commands", "versions"):
            x = d(); del x[k]
            self.assertErr(x, f"'{k}'")

    def test_extra_keys(self):
        self.assertErr(d(foo=1), "лишний ключ 'foo'")
        x = d(); x["versions"][0]["bar"] = 1
        self.assertErr(x, "лишний ключ 'bar'")

    def test_project_name_rules(self):
        self.assertErr(d(project="Demo"), "только a-z")
        self.assertErr(d(project="-demo"), "только a-z")
        self.assertErr(BASE, "не совпадает", name="other.json")

    def test_template_skips_filename_check(self):
        self.assertEqual(self.errs(BASE, name="_tpl.json"), [])

    def test_repository_https(self):
        self.assertErr(d(repository="http://x"), "https://")

    def test_update_commands(self):
        self.assertErr(d(update_commands={}), "непустой объект")
        self.assertErr(d(update_commands={"linux": []}), "update_commands.linux")
        self.assertErr(d(update_commands={"linux": [""]}), "update_commands.linux")
        self.assertErr(d(update_commands={"linux": "git pull"}), "update_commands.linux")

    def test_versions_empty(self):
        self.assertErr(d(versions=[]), "непустой список")

    def test_semver_format(self):
        for bad in ("1.0", "v1.0.0", "1.0.0-beta", "01.a.0", ""):
            x = d(); x["versions"][0]["version"] = bad
            self.assertErr(x, "X.Y.Z")

    def test_latest_mismatch(self):
        self.assertErr(d(latest="1.1.1"), "latest")

    def test_duplicate(self):
        x = d(); x["versions"][1]["version"] = "1.2.0"
        self.assertErr(x, "дубликат")

    def test_order(self):
        x = d(); x["versions"][1], x["versions"][2] = x["versions"][2], x["versions"][1]
        self.assertErr(x, "от новой версии к старой")

    def test_numeric_compare_not_string(self):
        x = d(latest="1.10.0")
        x["versions"].insert(0, {"version": "1.10.0", "date": "2026-11-20", "type": "minor", "changes": ["a"], "changes_en": ["a"]})
        self.assertEqual(self.errs(x), [])

    def test_type_matches_bump(self):
        x = d(); x["versions"][0]["type"] = "patch"
        self.assertErr(x, "по номеру это 'minor'")
        x = d(); x["versions"][1]["type"] = "minor"
        self.assertErr(x, "по номеру это 'patch'")
        x = d(latest="2.0.0")
        x["versions"].insert(0, {"version": "2.0.0", "date": "2026-12-01", "type": "minor", "changes": ["a"]})
        self.assertErr(x, "по номеру это 'major'")

    def test_type_enum(self):
        x = d(); x["versions"][0]["type"] = "big"
        self.assertErr(x, "type должен")

    def test_first_must_be_initial(self):
        x = d(); x["versions"][-1]["type"] = "patch"
        self.assertErr(x, "initial")

    def test_dates(self):
        x = d(); x["versions"][0]["date"] = "2026-13-01"
        self.assertErr(x, "YYYY-MM-DD")
        x = d(); x["versions"][0]["date"] = "2026-11-01"
        self.assertErr(x, "дата раньше")

    def test_same_date_allowed(self):
        x = d(); x["versions"][0]["date"] = x["versions"][1]["date"]
        self.assertEqual(self.errs(x), [])

    def test_changes(self):
        for bad in ([], [""], "текст", None):
            x = d(); x["versions"][0]["changes"] = bad
            self.assertErr(x, "changes")

    def test_changes_en(self):
        x = d(); x["versions"][0]["changes_en"] = []
        self.assertErr(x, "changes_en")
        x = d(); del x["versions"][0]["changes_en"]
        w = []
        self.assertEqual(self.errs(x, warns=w), [])
        self.assertTrue(any("changes_en" in s for s in w))

    def test_flags_bool(self):
        for f in ("breaking", "security"):
            x = d(); x["versions"][0][f] = "yes"
            self.assertErr(x, f)

    def test_min_upgrade_from(self):
        x = d(); x["versions"][0]["min_upgrade_from"] = "1.2.0"
        self.assertErr(x, "меньше")
        x = d(); x["versions"][0]["min_upgrade_from"] = "abc"
        self.assertErr(x, "min_upgrade_from")
        x = d(); x["versions"][0]["min_upgrade_from"] = "1.1.0"
        self.assertEqual(self.errs(x), [])

    def test_version_not_object(self):
        x = d(); x["versions"].append("1.0.0")
        self.assertErr(x, "объектом")

    def test_main_exit_codes(self):
        good = self.t.write(BASE)
        bad = self.t.write(d(latest="9.9.9"), name="demo2.json")
        self.assertEqual(val.main([str(good)]), 0)
        self.assertEqual(val.main([str(good), str(bad)]), 1)


# ---------------------------------------------------------------- client
class ClientEvaluateTests(unittest.TestCase):
    def test_up_to_date(self):
        r = uc.evaluate(BASE, "1.2.0")
        self.assertFalse(r["update_available"])
        self.assertFalse(r["ahead"])

    def test_ahead_of_registry(self):
        r = uc.evaluate(BASE, "1.3.0")
        self.assertFalse(r["update_available"])
        self.assertTrue(r["ahead"])

    def test_update_lists_all_newer(self):
        r = uc.evaluate(BASE, "1.0.0")
        self.assertTrue(r["update_available"])
        self.assertEqual(r["latest"], "1.2.0")
        self.assertEqual([c["version"] for c in r["changes"]], ["1.2.0", "1.1.1", "1.1.0"])
        self.assertEqual(r["commands"], ["git pull"])
        self.assertEqual(r["install_methods"], ["docker", "linux"])

    def test_numeric_compare(self):
        x = d(latest="1.10.0")
        x["versions"].insert(0, {"version": "1.10.0", "date": "2026-12-01", "type": "minor", "changes": ["a"]})
        r = uc.evaluate(x, "1.9.0")
        self.assertEqual(r["latest"], "1.10.0")

    def test_lang(self):
        self.assertEqual(uc.evaluate(BASE, "1.1.1", lang="en")["changes"][0]["changes"], ["New"])
        self.assertEqual(uc.evaluate(BASE, "1.1.1", lang="ru")["changes"][0]["changes"], ["Новое"])
        x = d(); del x["versions"][0]["changes_en"]
        self.assertEqual(uc.evaluate(x, "1.1.1", lang="en")["changes"][0]["changes"], ["Новое"])  # fallback

    def test_install_method(self):
        self.assertEqual(uc.evaluate(BASE, "1.0.0", install="docker")["commands"][0], "docker compose pull")
        self.assertEqual(uc.evaluate(BASE, "1.0.0", install="windows")["commands"], [])

    def test_per_version_commands_override(self):
        x = d(); x["versions"][0]["update_commands"] = {"linux": ["./migrate.sh"]}
        self.assertEqual(uc.evaluate(x, "1.0.0")["commands"], ["./migrate.sh"])

    def test_flags_aggregate(self):
        x = d(); x["versions"][2]["security"] = True; x["versions"][1]["breaking"] = True
        r = uc.evaluate(x, "1.0.0")
        self.assertTrue(r["security"]); self.assertTrue(r["breaking"])
        r = uc.evaluate(x, "1.1.1")  # старые флаги не тянутся
        self.assertFalse(r["security"]); self.assertFalse(r["breaking"])

    def test_stepwise(self):
        x = d(); x["versions"][0]["min_upgrade_from"] = "1.1.0"
        self.assertTrue(uc.evaluate(x, "1.0.0")["stepwise"])
        self.assertFalse(uc.evaluate(x, "1.1.0")["stepwise"])

    def test_bad_current(self):
        with self.assertRaises(uc.UpdateCheckError):
            uc.evaluate(BASE, "1.0")

    def test_broken_entries_skipped(self):
        x = d(); x["versions"].insert(0, {"version": "oops"}); x["versions"].insert(0, "junk")
        self.assertEqual(uc.evaluate(x, "1.0.0")["latest"], "1.2.0")

    def test_unsorted_registry(self):
        x = d(); x["versions"].reverse()
        self.assertEqual(uc.evaluate(x, "1.0.0")["latest"], "1.2.0")


class ClientFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Tmp()
        cls.tmp.write(BASE)
        cls.tmp.write(None, name="broken.json", raw="{not json")
        cls.tmp.write(None, name="wrongshape.json", raw='{"a":1}')
        directory = cls.tmp.dir.name

        class H(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=directory, **k)

            def log_message(self, *a):
                pass

        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/{{project}}.json"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.dir.cleanup()

    def test_http_ok(self):
        r = uc.check_updates("demo", "1.0.0", source=self.url)
        self.assertTrue(r["update_available"])

    def test_http_404(self):
        with self.assertRaises(uc.UpdateCheckError):
            uc.check_updates("missing", "1.0.0", source=self.url)

    def test_broken_json(self):
        with self.assertRaises(uc.UpdateCheckError):
            uc.check_updates("broken", "1.0.0", source=self.url)

    def test_wrong_shape(self):
        with self.assertRaises(uc.UpdateCheckError):
            uc.check_updates("wrongshape", "1.0.0", source=self.url)

    def test_local_file_source(self):
        r = uc.check_updates("demo", "1.2.0", source=str(Path(self.tmp.dir.name) / "{project}.json"))
        self.assertFalse(r["update_available"])

    def test_unreachable_host(self):
        with self.assertRaises(uc.UpdateCheckError):
            uc.check_updates("demo", "1.0.0", source="http://127.0.0.1:9/{project}.json", timeout=1)

    def test_cli(self):
        self.assertEqual(uc.main(["demo", "1.0.0", "--source", self.url]), 0)
        self.assertEqual(uc.main(["missing", "1.0.0", "--source", self.url]), 2)


# ---------------------------------------------------------------- repository files
class RepositoryFilesTests(unittest.TestCase):
    def test_all_registry_files_valid(self):
        files = sorted(ROOT.glob("*.json"))
        self.assertTrue(files)
        for f in files:
            with self.subTest(file=f.name):
                self.assertEqual(val.check(f), [])

    def test_schema_matches_validator_keys(self):
        schema = json.loads((ROOT / "schema/project.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["properties"]), val.TOP_KEYS)
        self.assertEqual(set(schema["properties"]["versions"]["items"]["properties"]), val.VER_KEYS)
        self.assertEqual(set(schema["properties"]["versions"]["items"]["properties"]["type"]["enum"]), val.TYPES)


if __name__ == "__main__":
    unittest.main()
