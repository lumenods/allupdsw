"""Тесты tools/cve_scan.py: парсеры, CVSS, системные пакеты, OSV (поддельный сервер), исключения, отчёты, CLI."""
import datetime as dt
import http.server
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import cve_scan as cs  # noqa: E402

# ---------------------------------------------------------------- поддельная база OSV

def vuln(vid, eco, name, fixed=None, severity=None, aliases=(), db_sev=None, withdrawn=None, modified="2026-01-01T00:00:00.123456789Z"):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    v = {"id": vid, "modified": modified, "aliases": list(aliases), "summary": f"<b>{vid}</b> summary",
         "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}
    if severity:
        v["severity"] = severity
    if db_sev:
        v["database_specific"] = {"severity": db_sev}
    if withdrawn:
        v["withdrawn"] = withdrawn
    return v


CVSS_HIGH = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}]  # 7.4
CVSS_CRIT = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]  # 9.8
CVSS_MED = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}]  # 6.1

DB = {
    ("npm", "lodash", "4.17.15"): [vuln("GHSA-lodash", "npm", "lodash", "4.17.19", CVSS_HIGH, ["CVE-2020-8203"])],
    ("npm", "jquery", "3.4.1"): [vuln("GHSA-jq", "npm", "jquery", "3.5.0", CVSS_MED, ["CVE-2020-11022"])],
    ("npm", "bootstrap", "4.3.0"): [vuln("GHSA-bs", "npm", "bootstrap", "4.3.1", None, ["CVE-2019-8331"], db_sev="MODERATE")],
    ("PyPI", "django", "3.2.0"): [
        vuln("PYSEC-dj", "PyPI", "django", "3.2.1", CVSS_CRIT, ["CVE-2021-1"]),
        vuln("GHSA-dj", "PyPI", "django", "3.2.1", CVSS_CRIT, ["CVE-2021-1"]),  # дубликат той же CVE
        vuln("GHSA-dj2", "PyPI", "django", "3.2.5", None, ["CVE-2021-2"]),  # без оценки → unknown
    ],
    ("PyPI", "requests", "2.19.0"): [vuln("GHSA-old", "PyPI", "requests", "2.20.0", CVSS_MED, withdrawn="2024-01-01T00:00:00Z")],
    ("crates.io", "smallvec", "0.6.9"): [vuln("RUSTSEC-1", "crates.io", "smallvec", None, CVSS_CRIT)],  # без исправления
    ("Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3"): [
        vuln("UBUNTU-CVE-1", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", CVSS_CRIT + [{"type": "Ubuntu", "score": "low"}], ["CVE-2024-1"]),
    ],
    ("Alpine:v3.20", "busybox", "1.36.1-r29"): [vuln("ALPINE-1", "Alpine:v3.20", "busybox", "1.36.1-r30", CVSS_HIGH)],
}
MANY = [vuln(f"GHSA-many-{i}", "npm", "many", "2.0.0", CVSS_MED) for i in range(5)]
DB[("npm", "many", "1.0.0")] = MANY
BY_ID = {v["id"]: v for vs in DB.values() for v in vs}


class FakeOSV(http.server.BaseHTTPRequestHandler):
    calls = []
    fail = False

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _key(q):
        return (q["package"]["ecosystem"], q["package"]["name"], q["version"])

    def do_POST(self):
        FakeOSV.calls.append(self.path)
        if FakeOSV.fail:
            return self._json(503, {})
        q = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/querybatch":
            res = []
            for one in q["queries"]:
                vs = DB.get(self._key(one), [])
                if self._key(one)[1] == "many":  # пагинация: первые 2 + токен
                    res.append({"vulns": [{"id": v["id"], "modified": v["modified"][:26] + "Z"} for v in vs[:2]], "next_page_token": "p2"})
                else:
                    res.append({"vulns": [{"id": v["id"], "modified": v["modified"][:26] + "Z"} for v in vs]} if vs else {})
            return self._json(200, {"results": res})
        if self.path == "/v1/query":
            vs = DB.get(self._key(q), [])
            if q.get("page_token") == "p2":
                return self._json(200, {"vulns": [{"id": v["id"], "modified": v["modified"]} for v in vs[2:4]], "next_page_token": "p3"})
            if q.get("page_token") == "p3":
                return self._json(200, {"vulns": [{"id": v["id"], "modified": v["modified"]} for v in vs[4:]]})
        return self._json(400, {})

    def do_GET(self):
        FakeOSV.calls.append(self.path)
        vid = self.path.rsplit("/", 1)[-1]
        if vid in BY_ID:
            return self._json(200, BY_ID[vid])
        return self._json(404, {})


def start_osv():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOSV)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

# ---------------------------------------------------------------- тестовый проект

def make_project(d):
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    (p / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/many": {"version": "1.0.0", "dev": True},
        "node_modules/@scope/pkg": {"version": "1.0.0"}, "node_modules/linked": {"link": True}}}))
    (p / "requirements.txt").write_text("Django==3.2.0  # web\nrequests==2.19.0\nflask>=2.0\n-r other.txt\n")
    (p / "poetry.lock").write_text('[[package]]\nname = "Jinja2"\nversion = "3.1.2"\ncategory = "dev"\n')
    (p / "Cargo.lock").write_text('[[package]]\nname = "smallvec"\nversion = "0.6.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                                  '[[package]]\nname = "local"\nversion = "0.1.0"\nsource = "git+https://x"\n')
    (p / "go.mod").write_text("module x\n\ngo 1.21.3\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/a/b v1.2.3+incompatible\n)\nrequire github.com/c/d v0.1.0\n")
    (p / "composer.lock").write_text(json.dumps({"packages": [{"name": "symfony/http-kernel", "version": "v5.4.1"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}))
    (p / "Gemfile.lock").write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.1.0)\n      actionpack (= 6.1.0)\n    nokogiri (1.13.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n")
    (p / "yarn.lock").write_text('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.0"\n\nleft-pad@^1.0.0:\n  version "1.3.0"\n')
    (p / "gradle.lockfile").write_text("# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\nempty=\n")
    (p / "packages.lock.json").write_text(json.dumps({"dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}, "MyProj": {"type": "Project"}}}}))
    static = p / "static" / "vendor"
    static.mkdir(parents=True)
    (static / "jquery-3.4.1.min.js").write_text("/*! jQuery v3.4.1 | (c) JS Foundation */\n!function(){}")
    (static / "bs.js").write_text("/*!\n  * Bootstrap v4.3.0 (https://getbootstrap.com/)\n  */\n")
    (static / "app.js").write_text("console.log('own code 1.2.3')\n")
    nm = p / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text("{}")  # node_modules пропускается
    return p


def make_rootfs(d, kind="ubuntu"):
    r = Path(d)
    (r / "etc").mkdir(parents=True)
    if kind == "ubuntu":
        (r / "etc/os-release").write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.5 LTS (Noble Numbat)"\nID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\n')
        (r / "var/lib/dpkg").mkdir(parents=True)
        (r / "var/lib/dpkg/status").write_text(
            "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.13-0ubuntu3\nDescription: x\n multi-line\n\n"
            "Package: openssl\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3\n\n"
            "Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
            "Package: libfoo\nStatus: install ok installed\nSource: foo (2.0-1)\nVersion: 2.0-1build1\n\n"
            "Package: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.8.0-1\n")
    elif kind == "alpine":
        (r / "etc/os-release").write_text('NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME="Alpine Linux v3.20"\n')
        (r / "lib/apk/db").mkdir(parents=True)
        (r / "lib/apk/db/installed").write_text("P:busybox-binsh\nV:1.36.1-r29\no:busybox\n\nP:musl\nV:1.2.5-r0\n\n")
    else:
        (r / "etc/os-release").write_text('NAME="Gentoo"\nID=gentoo\nPRETTY_NAME="Gentoo"\n')
    return r

# ---------------------------------------------------------------- тесты

class ParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = make_project(self.tmp.name)
        self.scan = cs.Scan()
        self.meta = cs.collect([self.p], self.scan)
        self.keys = {p.key() for p in self.scan.unique()}

    def tearDown(self):
        self.tmp.cleanup()

    def has(self, eco, name, ver):
        self.assertIn((eco, name, ver), self.keys, f"нет {eco} {name} {ver}: {sorted(self.keys)}")

    def test_npm(self):
        self.has("npm", "lodash", "4.17.15")
        self.has("npm", "@scope/pkg", "1.0.0")
        self.assertFalse(any(k[1] == "linked" for k in self.keys))
        many = next(p for p in self.scan.unique() if p.name == "many")
        self.assertTrue(many.dev)

    def test_package_lock_v1(self):
        s = cs.Scan()
        f = Path(self.tmp.name) / "v1" / "package-lock.json"
        f.parent.mkdir()
        f.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}}}}))
        cs.parse_package_lock(f, s, f.parent)
        self.assertEqual({p.key() for p in s.packages}, {("npm", "a", "1.0.0"), ("npm", "b", "2.0.0")})

    def test_yarn(self):
        self.has("npm", "@babel/core", "7.22.0")
        self.has("npm", "left-pad", "1.3.0")

    def test_pnpm(self):
        s = cs.Scan()
        f = Path(self.tmp.name) / "pnpm-lock.yaml"
        f.write_text("packages:\n\n  /lodash@4.17.21:\n    resolution: {}\n  '@types/node@20.1.0':\n    resolution: {}\n  /foo/1.0.0:\n")
        cs.parse_pnpm_lock(f, s, f.parent)
        self.assertEqual({p.key() for p in s.packages}, {("npm", "lodash", "4.17.21"), ("npm", "@types/node", "20.1.0"), ("npm", "foo", "1.0.0")})

    def test_requirements_and_unpinned_warning(self):
        self.has("PyPI", "django", "3.2.0")
        self.has("PyPI", "requests", "2.19.0")
        self.assertTrue(any("flask" in w and "не закреплена" in w for w in self.scan.warnings))
        self.assertFalse(any("other.txt" in w for w in self.scan.warnings))

    def test_poetry_cargo_go(self):
        self.has("PyPI", "jinja2", "3.1.2")
        self.has("crates.io", "smallvec", "0.6.9")
        self.assertFalse(any(k[1] == "local" for k in self.keys))
        self.has("Go", "stdlib", "1.21.3")
        self.has("Go", "golang.org/x/net", "0.17.0")
        self.has("Go", "github.com/a/b", "1.2.3")
        self.has("Go", "github.com/c/d", "0.1.0")

    def test_composer_gem_gradle_nuget(self):
        self.has("Packagist", "symfony/http-kernel", "5.4.1")
        self.has("Packagist", "phpunit/phpunit", "9.5.0")
        self.has("RubyGems", "rails", "6.1.0")
        self.has("RubyGems", "nokogiri", "1.13.0")
        self.assertFalse(any(k[1] == "actionpack" for k in self.keys))  # зависимость-ограничение, не spec
        self.has("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
        self.has("NuGet", "Newtonsoft.Json", "12.0.1")
        self.assertFalse(any(k[1] == "MyProj" for k in self.keys))

    def test_vendored(self):
        self.has("npm", "jquery", "3.4.1")
        self.has("npm", "bootstrap", "4.3.0")
        vend = [p for p in self.scan.unique() if p.kind == "vendored"]
        self.assertEqual({p.name for p in vend}, {"jquery", "bootstrap"})

    def test_skips_node_modules(self):
        self.assertFalse(any("node_modules" in f for f in self.meta["lockfiles"]))

    def test_broken_file_is_warning_not_crash(self):
        (self.p / "composer.lock").write_text("{broken")
        s = cs.Scan()
        cs.collect([self.p], s)
        self.assertTrue(any("composer.lock" in w and "не удалось разобрать" in w for w in s.warnings))
        self.assertTrue(any(p.name == "lodash" for p in s.packages))

    def test_single_file_path(self):
        s = cs.Scan()
        cs.collect([self.p / "requirements.txt"], s)
        self.assertEqual({p.name for p in s.packages}, {"django", "requests"})


class SystemTests(unittest.TestCase):
    def test_ubuntu_dpkg(self):
        with tempfile.TemporaryDirectory() as d:
            r = make_rootfs(d)
            s = cs.Scan()
            name = cs.scan_system(r, s)
            self.assertIn("Ubuntu:24.04:LTS", name)
            keys = {(p.name, p.version) for p in s.unique()}
            self.assertEqual(keys, {("openssl", "3.0.13-0ubuntu3"), ("foo", "2.0-1")})  # removed и linux-libc-dev исключены
            self.assertTrue(any("linux-libc-dev" in w for w in s.warnings))
            src = next(p for p in s.unique() if p.name == "openssl").source
            self.assertIn("system:libssl3t64", src)
            self.assertIn("system:openssl", src)
            s2 = cs.Scan()
            cs.scan_system(r, s2, kernel_headers=True)
            self.assertIn(("linux", "6.8.0-1"), {(p.name, p.version) for p in s2.unique()})

    def test_alpine(self):
        with tempfile.TemporaryDirectory() as d:
            s = cs.Scan()
            self.assertIn("Alpine:v3.20", cs.scan_system(make_rootfs(d, "alpine"), s))
            self.assertEqual({(p.name, p.version) for p in s.packages}, {("busybox", "1.36.1-r29"), ("musl", "1.2.5-r0")})

    def test_unsupported_os(self):
        with tempfile.TemporaryDirectory() as d:
            s = cs.Scan()
            cs.scan_system(make_rootfs(d, "gentoo"), s)
            self.assertTrue(any("не поддерживается" in w for w in s.warnings))

    def test_os_ecosystem(self):
        self.assertEqual(cs.os_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.10", "VERSION": "22.10"}), "Ubuntu:22.10")
        self.assertEqual(cs.os_ecosystem({"ID": "debian", "VERSION_ID": "12"}), "Debian:12")
        self.assertEqual(cs.os_ecosystem({"ID": "rocky", "VERSION_ID": "9.3"}), "Rocky Linux:9")
        self.assertEqual(cs.os_ecosystem({"ID": "almalinux", "VERSION_ID": "8.10"}), "AlmaLinux:8")
        self.assertIsNone(cs.os_ecosystem({"ID": "arch"}))


class ScoringTests(unittest.TestCase):
    def test_cvss3(self):
        self.assertEqual(cs.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cs.cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"), 7.4)
        self.assertEqual(cs.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cs.cvss3_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertEqual(cs.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"), 9.9)
        self.assertEqual(cs.cvss3_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(cs.cvss3_score("garbage"))
        self.assertIsNone(cs.cvss3_score("CVSS:3.1/AV:X/AC:L"))

    def test_levels(self):
        self.assertEqual([cs.score_to_level(x) for x in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9, None)],
                         ["critical", "high", "high", "medium", "medium", "low", "unknown"])

    def test_assess_priority(self):
        v = {"severity": CVSS_CRIT + [{"type": "Ubuntu", "score": "low"}]}
        self.assertEqual(cs.assess(v, distro=True)[0], "low")  # для ОС — оценка дистрибутива
        self.assertEqual(cs.assess(v, distro=False)[0], "critical")
        self.assertEqual(cs.assess({"database_specific": {"severity": "MODERATE"}}, False)[0], "medium")
        self.assertEqual(cs.assess({}, False)[0], "unknown")

    def test_versions(self):
        self.assertGreater(cs.vkey("1.10.0"), cs.vkey("1.9.0"))
        self.assertGreater(cs.vkey("1:1.0"), cs.vkey("9.9"))  # epoch
        self.assertLess(cs.vkey("1.0~rc1"), cs.vkey("1.0"))
        self.assertLess(cs.vkey("1.0.0-rc1"), cs.vkey("1.0.0"))
        self.assertLess(cs.vkey("1.0"), cs.vkey("1.0.1"))
        self.assertLess(cs.vkey("2.39-0ubuntu8.9"), cs.vkey("2.39-0ubuntu8.12"))
        self.assertLess(cs.vkey("13.3.0-6ubuntu2~24.04"), cs.vkey("13.3.0-6ubuntu2"))
        self.assertEqual(cs.needed_version("4.17.15", ["4.17.19", "3.0.0", "4.17.21"]), "4.17.19")
        self.assertIsNone(cs.needed_version("5.0.0", ["4.17.19"]))

    def test_norm_ts(self):
        self.assertEqual(cs.norm_ts("2026-11-13T21:13:31.601518481Z"), cs.norm_ts("2026-11-13T21:13:31.601518Z"))
        self.assertEqual(cs.norm_ts("2026-11-13T21:13:31Z"), "2026-11-13T21:13:31.000000")


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = start_osv()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeOSV.calls.clear()
        FakeOSV.fail = False
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(Path(self.tmp.name) / "proj")
        self.root = make_rootfs(Path(self.tmp.name) / "root")
        self.cache = Path(self.tmp.name) / "cache"

    def tearDown(self):
        self.tmp.cleanup()

    def run_scan(self, **kw):
        osv = cs.OSV(self.url, cache_dir=self.cache, timeout=5, workers=4)
        return cs.run_scan([self.proj], kw.pop("root", self.root), osv, **kw)

    def ids(self, res):
        return {(f["package"], f["id"]) for f in res["findings"]}

    def test_findings(self):
        res = self.run_scan()
        ids = self.ids(res)
        for pair in [("lodash", "GHSA-lodash"), ("jquery", "GHSA-jq"), ("bootstrap", "GHSA-bs"), ("smallvec", "RUSTSEC-1"),
                     ("openssl", "UBUNTU-CVE-1")]:
            self.assertIn(pair, ids)
        self.assertFalse(any(p == "requests" for p, _ in ids), "отозванная (withdrawn) уязвимость не должна попадать")

    def test_dedupe_aliases(self):
        res = self.run_scan()
        dj = [f for f in res["findings"] if f["package"] == "django"]
        self.assertEqual(len(dj), 2, "PYSEC и GHSA для одной CVE — одна запись")
        first = next(f for f in dj if "CVE-2021-1" in f["cve"])
        self.assertIn("PYSEC-dj", first["aliases"])
        self.assertIn("GHSA-dj", first["aliases"])

    def test_pagination(self):
        res = self.run_scan()
        self.assertEqual(len([f for f in res["findings"] if f["package"] == "many"]), 5)
        self.assertIn("/v1/query", FakeOSV.calls)

    def test_severity_and_fix(self):
        res = self.run_scan()
        f = {x["id"]: x for x in res["findings"]}
        self.assertEqual(f["GHSA-lodash"]["severity"], "high")
        self.assertEqual(f["GHSA-lodash"]["cvss"], 7.4)
        self.assertEqual(f["GHSA-lodash"]["fixed"], ["4.17.19"])
        self.assertEqual(f["GHSA-bs"]["severity"], "medium")
        self.assertEqual(f["UBUNTU-CVE-1"]["severity"], "low")
        self.assertEqual(f["RUSTSEC-1"]["fixed"], [])
        self.assertEqual(res["findings"][0]["severity"], "critical")

    def test_recommendations_and_commands(self):
        res = self.run_scan()
        recs = {(g["ecosystem"], g["package"]): g for g in res["recommendations"]}
        self.assertEqual(recs[("npm", "lodash")]["command"], "npm install lodash@4.17.19")
        self.assertEqual(recs[("PyPI", "django")]["target"], "3.2.5")  # максимум из нужных исправлений
        self.assertIn("apt-get install --only-upgrade libssl3t64 openssl", recs[("Ubuntu:24.04:LTS", "openssl")]["command"])
        self.assertIn("заменить файл static/vendor/jquery-3.4.1.min.js", recs[("npm", "jquery")]["command"])
        self.assertIsNone(recs[("crates.io", "smallvec")]["command"])
        order = [g["target"] is None for g in res["recommendations"]]
        self.assertEqual(order, sorted(order), "сначала то, что можно обновить")

    def test_alpine_command(self):
        with tempfile.TemporaryDirectory() as d:
            res = self.run_scan(root=make_rootfs(d, "alpine"))
            g = next(g for g in res["recommendations"] if g["package"] == "busybox")
            self.assertEqual(g["command"], "apk update && apk upgrade busybox-binsh")

    def test_no_dev(self):
        res = self.run_scan(include_dev=False)
        self.assertFalse(any(f["package"] == "many" for f in res["findings"]))

    def test_cache(self):
        self.run_scan()
        first = len([c for c in FakeOSV.calls if c.startswith("/v1/vulns/")])
        FakeOSV.calls.clear()
        self.run_scan()
        second = len([c for c in FakeOSV.calls if c.startswith("/v1/vulns/")])
        self.assertGreater(first, 0)
        self.assertEqual(second, 0, "при неизменном modified подробности берутся из кэша")
        for p in self.cache.iterdir():  # запись изменилась в OSV → перезапрос
            data = json.loads(p.read_text())
            data["modified"] = "2000-01-01T00:00:00Z"
            p.write_text(json.dumps(data))
        FakeOSV.calls.clear()
        self.run_scan()
        self.assertEqual(len([c for c in FakeOSV.calls if c.startswith("/v1/vulns/")]), first)

    def test_osv_down(self):
        FakeOSV.fail = True
        with self.assertRaises(cs.OSVError):
            cs.run_scan([self.proj], None, cs.OSV(self.url, timeout=2, workers=2))

    def test_ignores(self):
        today = dt.date(2026, 11, 16)
        ign = Path(self.tmp.name) / "ign.json"
        ign.write_text(json.dumps([
            {"id": "CVE-2020-8203", "reason": "не используется zipObjectDeep", "until": "2026-12-31"},
            {"id": "GHSA-jq", "package": "other", "reason": "x", "until": "2026-12-31"},
            {"id": "GHSA-bs", "reason": "старое", "until": "2026-01-01"},
        ]))
        res = self.run_scan(ignore_file=ign, today=today)
        ids = self.ids(res)
        self.assertNotIn(("lodash", "GHSA-lodash"), ids)
        self.assertEqual(res["ignored"][0]["ignored"]["reason"], "не используется zipObjectDeep")
        self.assertIn(("jquery", "GHSA-jq"), ids, "исключение для другого пакета не действует")
        self.assertIn(("bootstrap", "GHSA-bs"), ids, "истёкшее исключение не действует")
        self.assertTrue(any("истекло" in w for w in res["warnings"]))

    def test_ignore_validation(self):
        today = dt.date(2026, 11, 16)
        ign = Path(self.tmp.name) / "bad.json"
        for bad, msg in [({"id": "X", "until": "2026-12-01"}, "причина"), ({"id": "X", "reason": "r"}, "until"),
                         ({"id": "X", "reason": "r", "until": "2028-01-01"}, "не больше года"), ({"reason": "r"}, "нужен id")]:
            ign.write_text(json.dumps([bad]))
            with self.assertRaisesRegex(ValueError, msg):
                cs.load_ignores(ign, today)
        ign.write_text("{}")
        with self.assertRaisesRegex(ValueError, "список"):
            cs.load_ignores(ign, today)
        self.assertEqual(cs.load_ignores(Path(self.tmp.name) / "none.json"), ([], []))

    def test_passed_rules(self):
        F = lambda sev, fix="1.0": {"severity": sev, "fix_target": fix}  # noqa: E731
        self.assertFalse(cs.passed([F("high")], "high"))
        self.assertTrue(cs.passed([F("medium")], "high"))
        self.assertTrue(cs.passed([F("critical", None)], "high"), "без исправления по умолчанию не блокирует")
        self.assertFalse(cs.passed([F("critical", None)], "high", fail_unfixed=True))
        self.assertFalse(cs.passed([F("unknown")], "medium"), "unknown считается как medium")
        self.assertTrue(cs.passed([F("unknown")], "high"))
        self.assertFalse(cs.passed([F("low")], "unknown"))
        self.assertTrue(cs.passed([F("critical")], "never"))
        self.assertTrue(cs.passed([], "low"))


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = start_osv()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        FakeOSV.fail = False
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.proj = make_project(self.d / "proj")
        self.root = make_rootfs(self.d / "root")

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cs.main(list(args) + ["--osv-url", self.url, "--no-cache", "--timeout", "5"])
        return code, out.getvalue(), err.getvalue()

    def test_full_run_reports_sbom(self):
        out = self.d / "rep"
        sbom = self.d / "sbom.json"
        code, text, _ = self.cli(str(self.proj), "--system", "--root", str(self.root), "--out", str(out), "--sbom", str(sbom),
                                 "--ignore", str(self.d / "none.json"))
        self.assertEqual(code, 1)
        self.assertIn("npm install lodash@4.17.19", text)
        self.assertIn("Ubuntu 24.04.5 LTS", text)
        rep = json.loads((out / "report.json").read_text())
        self.assertFalse(rep["passed"])
        self.assertGreater(rep["stats"]["packages"], 20)
        html_text = (out / "report.html").read_text()
        self.assertNotIn("<b>GHSA-lodash</b>", html_text, "summary из OSV должен экранироваться")
        self.assertIn("&lt;b&gt;GHSA-lodash&lt;/b&gt;", html_text)
        bom = json.loads(sbom.read_text())
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        purls = {c["purl"] for c in bom["components"]}
        self.assertIn("pkg:npm/lodash@4.17.15", purls)
        self.assertIn("pkg:deb/openssl@3.0.13-0ubuntu3", purls)
        self.assertIn("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", purls)

    def test_fail_on_levels(self):
        self.assertEqual(self.cli(str(self.proj), "--out", str(self.d / "a"), "--fail-on", "never")[0], 0)
        self.assertEqual(self.cli(str(self.proj), "--out", str(self.d / "b"), "--fail-on", "critical")[0], 1)  # django 9.8 с исправлением

    def test_english(self):
        code, text, _ = self.cli(str(self.proj), "--out", str(self.d / "en"), "--lang", "en")
        self.assertIn("Packages scanned", text)
        self.assertIn("Vulnerability scan", (self.d / "en" / "report.html").read_text())

    def test_errors(self):
        self.assertEqual(self.cli(str(self.d / "missing"))[0], 2)
        self.assertEqual(self.cli(str(self.proj), "--workers", "0")[0], 2)
        FakeOSV.fail = True
        code, _, err = self.cli(str(self.proj), "--out", str(self.d / "x"))
        self.assertEqual(code, 2)
        self.assertIn("OSV", err)
        FakeOSV.fail = False
        bad = self.d / "ign.json"
        bad.write_text(json.dumps([{"id": "X"}]))
        code, _, err = self.cli(str(self.proj), "--out", str(self.d / "y"), "--ignore", str(bad))
        self.assertEqual(code, 2)
        self.assertIn("причина", err)

    def test_clean_project_passes(self):
        clean = self.d / "clean"
        clean.mkdir()
        (clean / "requirements.txt").write_text("safe==1.0.0\n")
        code, text, _ = self.cli(str(clean), "--out", str(self.d / "c"))
        self.assertEqual(code, 0)
        self.assertIn("critical 0", text)


if __name__ == "__main__":
    unittest.main()
