#!/usr/bin/env python3
"""Проверка библиотек и системы на известные уязвимости (CVE) по базе OSV.dev.

Только стандартная библиотека Python 3.11+. База OSV объединяет CVE (NVD), GitHub Advisories,
PyPA, RustSec, Go, а также бюллетени Debian, Ubuntu, Alpine и других дистрибутивов.

Что проверяется:
  * зависимости по lock-файлам: npm (package-lock.json, yarn.lock, pnpm-lock.yaml), PyPI (requirements*.txt,
    poetry.lock, Pipfile.lock, uv.lock), Go (go.mod), crates.io (Cargo.lock), Packagist (composer.lock),
    RubyGems (Gemfile.lock), Maven (gradle.lockfile), NuGet (packages.lock.json);
  * библиотеки, лежащие в проекте файлами (jquery-3.4.1.min.js, bootstrap.bundle.js с заголовком "Bootstrap v4.3.1" и т.п.);
  * системные пакеты сервера (--system): Debian/Ubuntu (dpkg), Alpine (apk), AlmaLinux/Rocky (rpm).

Примеры:
  python3 tools/cve_scan.py .                       # проект в текущей папке
  python3 tools/cve_scan.py . --system              # проект + пакеты этого сервера
  python3 tools/cve_scan.py --system --root /mnt/img  # пакеты образа/копии ФС
  python3 tools/cve_scan.py . --fail-on critical --out cve-report --sbom sbom.json

Коды выхода: 0 — нет уязвимостей уровня --fail-on и выше; 1 — есть; 2 — ошибка (нет связи с OSV и т.п.).
"""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
OSV_URL = "https://api.osv.dev"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "vendor/bundle", ".tox", "dist", "build", "target", ".next"}

# ------------------------------------------------------------------ модель

class Pkg:
    __slots__ = ("ecosystem", "name", "version", "source", "dev", "kind")

    def __init__(self, ecosystem, name, version, source, dev=False, kind="library"):
        self.ecosystem, self.name, self.version, self.source, self.dev, self.kind = ecosystem, name, version, source, dev, kind

    def key(self):
        return (self.ecosystem, self.name, self.version)

    def as_dict(self):
        return {"ecosystem": self.ecosystem, "name": self.name, "version": self.version, "source": self.source, "dev": self.dev, "kind": self.kind}


class Scan:
    def __init__(self):
        self.packages = []
        self.warnings = []

    def add(self, *a, **k):
        p = Pkg(*a, **k)
        if p.name and p.version:
            self.packages.append(p)

    def warn(self, msg):
        self.warnings.append(msg)

    def unique(self):
        seen = {}
        for p in self.packages:
            if p.key() not in seen:
                seen[p.key()] = p
            else:
                q = seen[p.key()]
                q.dev = q.dev and p.dev  # если хоть где-то не dev — считаем рабочей зависимостью
                if p.source not in q.source.split(", "):
                    q.source += ", " + p.source
        return list(seen.values())


def rel(path, base):
    try:
        return str(Path(path).relative_to(base))
    except ValueError:
        return str(path)

# ------------------------------------------------------------------ парсеры lock-файлов

def parse_package_lock(path, scan, base):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    src = rel(path, base)
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for key, info in pkgs.items():
            if not key or info.get("link") or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            scan.add("npm", name, info.get("version"), src, dev=bool(info.get("dev") or info.get("devOptional")))
        return
    def walk(deps):  # lockfileVersion 1
        for name, info in (deps or {}).items():
            scan.add("npm", name, info.get("version"), src, dev=bool(info.get("dev")))
            walk(info.get("dependencies"))
    walk(data.get("dependencies"))


def parse_yarn_lock(path, scan, base):
    src = rel(path, base)
    names = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            names = first.rsplit("@", 1)[0] if first.count("@") > (1 if first.startswith("@") else 0) else first
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and names:
            scan.add("npm", names, m.group(1), src)
            names = None


def parse_pnpm_lock(path, scan, base):
    src = rel(path, base)
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s{2}'?/?((?:@[^/@\s]+/)?[^/@\s(]+)[@/](\d[^:('\s]*)", line)
        if m:
            scan.add("npm", m.group(1), m.group(2), src)


def parse_requirements(path, scan, base):
    src = rel(path, base)
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)\s*(;.*)?$", line)
        if m:
            scan.add("PyPI", m.group(1).lower().replace("_", "-"), m.group(3), src)
        else:
            name = re.split(r"[<>=!~;\[ ]", line, 1)[0]
            scan.warn(f"{src}: версия «{name}» не закреплена (==), проверить на CVE нельзя — закрепите версию")


def parse_poetry_like(path, scan, base, eco):
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    for p in data.get("package", []):
        name = p.get("name", "")
        if eco == "PyPI":
            name = name.lower().replace("_", "-")
        if eco == "crates.io" and str(p.get("source", "")).startswith("git+"):
            continue
        scan.add(eco, name, p.get("version"), rel(path, base), dev=p.get("category") == "dev")


def parse_pipfile_lock(path, scan, base):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            v = str(info.get("version", "")).lstrip("=")
            scan.add("PyPI", name.lower().replace("_", "-"), v, rel(path, base), dev=dev)


def parse_go_mod(path, scan, base):
    src = rel(path, base)
    text = Path(path).read_text(encoding="utf-8")
    m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", text, re.M)
    if m:
        scan.add("Go", "stdlib", m.group(1), src)
    block = False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            block = True
            continue
        if block and s == ")":
            block = False
            continue
        mm = re.match(r"^(?:require\s+)?(\S+)\s+v(\d[^\s]*)$", s) if (block or s.startswith("require ")) else None
        if mm:
            scan.add("Go", mm.group(1), mm.group(2).split("+")[0], src)


def parse_composer_lock(path, scan, base):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            scan.add("Packagist", p.get("name"), str(p.get("version", "")).lstrip("v"), rel(path, base), dev=dev)


def parse_gemfile_lock(path, scan, base):
    in_specs = False
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^ {4}([A-Za-z0-9_.-]+) \(([^)\s-]+)(?:-[^)]+)?\)$", line) if in_specs else None
        if m:
            scan.add("RubyGems", m.group(1), m.group(2), rel(path, base))


def parse_gradle_lockfile(path, scan, base):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([^#:\s]+):([^:\s]+):([^=\s]+)=", line)
        if m:
            scan.add("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), rel(path, base))


def parse_nuget_lock(path, scan, base):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for deps in (data.get("dependencies") or {}).values():
        for name, info in deps.items():
            if info.get("type") != "Project":
                scan.add("NuGet", name, info.get("resolved"), rel(path, base))


LOCKFILES = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "poetry.lock": lambda p, s, b: parse_poetry_like(p, s, b, "PyPI"),
    "uv.lock": lambda p, s, b: parse_poetry_like(p, s, b, "PyPI"),
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": lambda p, s, b: parse_poetry_like(p, s, b, "crates.io"),
    "go.mod": parse_go_mod,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "gradle.lockfile": parse_gradle_lockfile,
    "packages.lock.json": parse_nuget_lock,
}

# ------------------------------------------------------------------ библиотеки файлами (vendored)

# Имя в заголовке/файле → пакет npm в OSV
VENDORED = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery ui": "jquery-ui", "bootstrap": "bootstrap",
    "lodash": "lodash", "underscore": "underscore", "moment": "moment", "vue": "vue", "vue.js": "vue",
    "react": "react", "react-dom": "react-dom", "angular": "angular", "angularjs": "angular", "leaflet": "leaflet",
    "chart": "chart.js", "chart.js": "chart.js", "d3": "d3", "axios": "axios", "handlebars": "handlebars",
    "dompurify": "dompurify", "select2": "select2", "datatables": "datatables.net", "highlight.js": "highlight.js",
    "marked": "marked", "socket.io": "socket.io-client", "pdf.js": "pdfjs-dist", "pdfjs": "pdfjs-dist",
    "tinymce": "tinymce", "ckeditor": "ckeditor4", "sweetalert2": "sweetalert2", "popper": "@popperjs/core",
    "knockout": "knockout", "backbone": "backbone", "mustache": "mustache", "plotly": "plotly.js",
    "swiper": "swiper", "summernote": "summernote", "codemirror": "codemirror", "quill": "quill",
}
_V = r"v?(\d+\.\d+\.\d+)"
FILE_RX = re.compile(r"^([a-z][a-z0-9.\-]*?)[-._@]" + _V + r"(?:[-.][a-z0-9]+)*\.js$", re.I)
HEADER_RX = re.compile(r"(?:/\*!?|//!?)\s*\**\s*(?:@license\s+)?([A-Za-z][A-Za-z0-9.\- ]{0,30}?)\s+(?:JavaScript Library\s+)?" + _V, re.I)


def scan_vendored(path, scan, base):
    name = Path(path).name
    found = None
    m = FILE_RX.match(name)
    if m and m.group(1).lower() in VENDORED:
        found = (VENDORED[m.group(1).lower()], m.group(2))
    else:
        try:
            with open(path, "rb") as f:
                head = f.read(600).decode("utf-8", "replace")
        except OSError:
            return
        h = HEADER_RX.search(head)
        if h:
            key = h.group(1).strip().lower()
            if key in VENDORED:
                found = (VENDORED[key], h.group(2))
    if found:
        scan.add("npm", found[0], found[1], rel(path, base), kind="vendored")

# ------------------------------------------------------------------ системные пакеты

def read_os_release(root):
    info = {}
    for cand in ("etc/os-release", "usr/lib/os-release"):
        p = Path(root) / cand
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
            break
    return info


def os_ecosystem(info):
    osid = info.get("ID", "").lower()
    ver = info.get("VERSION_ID", "")
    if osid == "ubuntu":
        return f"Ubuntu:{ver}:LTS" if "LTS" in info.get("VERSION", "") else f"Ubuntu:{ver}"
    if osid == "debian":
        return f"Debian:{ver.split('.')[0]}" if ver else None
    if osid == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if osid == "almalinux":
        return f"AlmaLinux:{ver.split('.')[0]}"
    if osid == "rocky":
        return f"Rocky Linux:{ver.split('.')[0]}"
    return None


def parse_dpkg_status(path):
    """Пакеты из /var/lib/dpkg/status: (исходный пакет, версия исходника, бинарный пакет)."""
    out = []
    block = {}
    def flush():
        if block.get("Status", "").endswith(" installed") and block.get("Package") and block.get("Version"):
            src, src_ver = block["Package"], block["Version"]
            if block.get("Source"):
                m = re.match(r"^(\S+)(?:\s+\((\S+)\))?", block["Source"])
                src = m.group(1)
                if m.group(2):
                    src_ver = m.group(2)
            out.append((src, src_ver, block["Package"]))
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            flush()
            block = {}
            continue
        if line[0] not in " \t" and ":" in line:
            k, v = line.split(":", 1)
            block[k] = v.strip()
    flush()
    return out


def parse_apk_installed(path):
    out, cur = [], {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() + [""]:
        if not line:
            if cur.get("P") and cur.get("V"):
                out.append((cur.get("o") or cur["P"], cur["V"], cur["P"]))
            cur = {}
        elif len(line) > 2 and line[1] == ":":
            cur[line[0]] = line[2:]
    return out


KERNEL_HEADERS = {"linux-libc-dev", "linux-headers", "kernel-headers"}


def scan_system(root, scan, kernel_headers=False):
    info = read_os_release(root)
    eco = os_ecosystem(info)
    name = info.get("PRETTY_NAME", "неизвестная ОС")
    if not eco:
        scan.warn(f"ОС «{name}» не поддерживается для проверки системных пакетов (поддерживаются Debian, Ubuntu, Alpine, AlmaLinux, Rocky)")
        return name
    r = Path(root)
    dpkg = r / "var/lib/dpkg/status"
    apk = r / "lib/apk/db/installed"
    pkgs = []
    if dpkg.exists():
        pkgs = parse_dpkg_status(dpkg)
    elif apk.exists():
        pkgs = parse_apk_installed(apk)
    elif str(root) == "/" and eco.startswith(("AlmaLinux", "Rocky")):
        try:
            res = subprocess.run(["rpm", "-qa", "--qf", "%{SOURCERPM} %{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"],
                                 capture_output=True, text=True, timeout=120, check=True)
            for line in res.stdout.splitlines():
                srpm, name_, ver = line.split(" ", 2)
                src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) or name_
                pkgs.append((src, ver.removeprefix("0:"), name_))
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            scan.warn(f"rpm: {e}")
    else:
        scan.warn(f"не найдена база пакетов в {root} (dpkg/apk/rpm)")
    by_src = {}
    for src, ver, binary in pkgs:
        by_src.setdefault((src, ver), []).append(binary)
    for (src, ver), binaries in by_src.items():
        if not kernel_headers and all(b in KERNEL_HEADERS or b.startswith("linux-headers-") for b in binaries):
            scan.warn(f"{', '.join(binaries)} ({src} {ver}) пропущен: это заголовки ядра для сборки, уязвимости ядра к ним не относятся. "
                      f"Работающее ядро проверяйте на хосте (uname -r) или флагом --kernel-headers")
            continue
        for binary in binaries:
            scan.add(eco, src, ver, f"system:{binary}", kind="system")
    return f"{name} ({eco})"

# ------------------------------------------------------------------ обход проекта

def collect(paths, scan, system_root=None, max_js_bytes=8_000_000, kernel_headers=False):
    meta = {"os": None, "lockfiles": [], "vendored_dirs": []}
    for base in paths:
        base = Path(base).resolve()
        if base.is_file():
            files = [base]
            base = base.parent
        else:
            files = []
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
                files += [Path(dirpath) / f for f in filenames]
        for f in files:
            parser = LOCKFILES.get(f.name) or (parse_requirements if re.match(r"^requirements.*\.txt$", f.name) else None)
            if parser:
                try:
                    parser(f, scan, base)
                    meta["lockfiles"].append(rel(f, base))
                except Exception as e:  # noqa: BLE001 — битый файл не должен останавливать проверку остальных
                    scan.warn(f"{rel(f, base)}: не удалось разобрать ({e})")
            elif f.suffix == ".js" and f.stat().st_size <= max_js_bytes:
                scan_vendored(f, scan, base)
    if system_root:
        meta["os"] = scan_system(system_root, scan, kernel_headers)
    return meta

# ------------------------------------------------------------------ CVSS

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Базовая оценка CVSS v3.0/3.1 по вектору; None, если вектор не разобран."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError, AttributeError):
        return None


def score_to_level(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


WORD_LEVEL = {"critical": "critical", "high": "high", "important": "high", "moderate": "medium", "medium": "medium",
              "low": "low", "negligible": "low", "unimportant": "low", "minor": "low"}


def assess(vuln, distro):
    """(уровень, оценка CVSS или None, откуда взят уровень)."""
    score = None
    for s in vuln.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss3_score(s.get("score", ""))
    distro_word = None
    for s in vuln.get("severity") or []:
        if s.get("type") in ("Ubuntu", "Debian", "Alpine") and str(s.get("score", "")).lower() in WORD_LEVEL:
            distro_word = str(s["score"]).lower()
    db = (vuln.get("database_specific") or {}).get("severity")
    if distro and distro_word:  # для пакетов ОС оценка дистрибутива точнее (учитывает сборку и настройки)
        return WORD_LEVEL[distro_word], score, f"{distro_word} (дистрибутив)"
    if score is not None:
        return score_to_level(score), score, f"CVSS {score}"
    if isinstance(db, str) and db.lower() in WORD_LEVEL:
        return WORD_LEVEL[db.lower()], None, db
    if distro_word:
        return WORD_LEVEL[distro_word], None, distro_word
    return "unknown", None, "нет оценки"


def sev_rank(s):
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)

# ------------------------------------------------------------------ OSV

class OSVError(Exception):
    pass


def norm_ts(s):
    """OSV отдаёт modified с разной точностью (6 и 9 знаков) — приводим к микросекундам."""
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", str(s or ""))
    return f"{m.group(1)}.{(m.group(2) or '').ljust(6, '0')[:6]}" if m else str(s or "")


class OSV:
    def __init__(self, url=OSV_URL, cache_dir=None, timeout=30, workers=16, ttl_hours=24):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.workers = workers
        self.cache = Path(cache_dir) if cache_dir else None
        self.ttl = ttl_hours * 3600
        self.requests = 0

    def _req(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, headers={"Content-Type": "application/json", "User-Agent": f"allupdsw-cve-scan/{VERSION}"})
        last = None
        for attempt in range(4):
            try:
                self.requests += 1
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None
                last = e
                if e.code < 500 and e.code != 429:
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = e
            time.sleep(min(2 ** attempt, 8) if attempt < 3 else 0)
        raise OSVError(f"OSV {path}: {last}")

    def query_ids(self, pkgs):
        """Список id уязвимостей для каждого пакета (порядок как в pkgs)."""
        result = [[] for _ in pkgs]
        for start in range(0, len(pkgs), 1000):
            chunk = pkgs[start:start + 1000]
            body = {"queries": [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]}
            resp = self._req("/v1/querybatch", body) or {}
            for i, r in enumerate(resp.get("results", [])):
                ids = [(v["id"], v.get("modified", "")) for v in r.get("vulns", [])]
                token = r.get("next_page_token")
                p = chunk[i]
                while token:  # у пакета больше уязвимостей, чем помещается в ответ
                    more = self._req("/v1/query", {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version, "page_token": token}) or {}
                    ids += [(v["id"], v.get("modified", "")) for v in more.get("vulns", [])]
                    token = more.get("next_page_token")
                result[start + i] = ids
        return result

    def _cache_path(self, vid):
        return self.cache / (hashlib.sha256(vid.encode()).hexdigest()[:32] + ".json")

    def vuln(self, vid, modified=""):
        """Подробности уязвимости. Кэш действителен, пока не изменилась дата modified в OSV (или TTL, если даты нет)."""
        if self.cache:
            p = self._cache_path(vid)
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    if (modified and norm_ts(data.get("modified")) == norm_ts(modified)) or (not modified and time.time() - p.stat().st_mtime < self.ttl):
                        return data
                except ValueError:
                    pass
        data = self._req(f"/v1/vulns/{vid}")
        if data is not None and self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)
            self._cache_path(vid).write_text(json.dumps(data), encoding="utf-8")
        return data

    def vulns(self, pairs):
        """pairs: [(id, modified)] → {id: данные}."""
        out = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            for (vid, _), data in zip(pairs, ex.map(lambda x: self.vuln(*x), pairs)):
                if data:
                    out[vid] = data
        return out

# ------------------------------------------------------------------ исключения

def load_ignores(path, today=None):
    """Исключения: [{id, package?, reason, until}] — причина и срок обязательны (не дольше года)."""
    today = today or dt.date.today()
    if not path:
        return [], []
    p = Path(path)
    if not p.exists():
        return [], []
    data = json.loads(p.read_text(encoding="utf-8"))
    rules, problems = [], []
    if not isinstance(data, list):
        raise ValueError(f"{path}: нужен список правил")
    for i, r in enumerate(data):
        w = f"{path}[{i}]"
        if not isinstance(r, dict) or not r.get("id"):
            raise ValueError(f"{w}: нужен id")
        if not str(r.get("reason", "")).strip():
            raise ValueError(f"{w} ({r['id']}): обязательна причина (reason)")
        try:
            until = dt.date.fromisoformat(r.get("until", ""))
        except ValueError:
            raise ValueError(f"{w} ({r['id']}): обязателен срок until в формате YYYY-MM-DD") from None
        if until > today + dt.timedelta(days=366):
            raise ValueError(f"{w} ({r['id']}): срок исключения не больше года")
        if until < today:
            problems.append(f"исключение {r['id']} истекло {until} — уязвимость снова учитывается")
            continue
        rules.append(r)
    return rules, problems


def ignored(rules, vuln_ids, pkg):
    for r in rules:
        if r["id"] in vuln_ids and (not r.get("package") or r["package"] == pkg.name):
            return r
    return None

# ------------------------------------------------------------------ основной проход

def fixed_versions(vuln, pkg):
    out = []
    for a in vuln.get("affected", []):
        ap = a.get("package", {})
        if ap.get("name") != pkg.name:
            continue
        aeco = ap.get("ecosystem", "")
        if aeco != pkg.ecosystem and aeco.split(":")[:2] != pkg.ecosystem.split(":")[:2]:
            continue
        for rg in a.get("ranges", []):
            for ev in rg.get("events", []):
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


PRERELEASE = {"alpha", "beta", "rc", "pre", "preview", "dev", "a", "b"}


def vkey(v):
    """Приблизительное сравнение версий (semver, PEP 440, Debian): числа как числа, epoch учитывается."""
    v = str(v)
    epoch = 0
    if re.match(r"^\d+:", v):
        e, v = v.split(":", 1)
        epoch = int(e)
    parts = []
    for tok in re.findall(r"\d+|[A-Za-z]+|~", v):
        if tok == "~" or tok.lower() in PRERELEASE:
            parts.append((-2, tok.lower()))  # ~ (Debian) и alpha/beta/rc — раньше выпуска
        elif tok.isdigit():
            parts.append((1, int(tok)))
        else:
            parts.append((0, tok.lower()))
    parts.append((-1, ""))  # конец версии: позже «~»/rc, раньше любого продолжения
    return (epoch, parts)


def needed_version(current, fixes):
    """Наименьшая исправленная версия, которая новее текущей."""
    cands = [f for f in fixes if vkey(f) > vkey(current)]
    return min(cands, key=vkey) if cands else None


def recommendations(findings):
    """Сводка по пакетам: сколько уязвимостей, до какой версии обновить, какой командой."""
    groups = {}
    for f in findings:
        g = groups.setdefault((f["ecosystem"], f["package"], f["version"]), {
            "ecosystem": f["ecosystem"], "package": f["package"], "version": f["version"], "kind": f["kind"],
            "source": f["source"], "dev": f["dev"], "counts": {s: 0 for s in SEVERITIES}, "worst": "unknown",
            "target": None, "unfixed": 0, "ids": []})
        g["counts"][f["severity"]] += 1
        g["ids"].append(f["id"])
        if sev_rank(f["severity"]) < sev_rank(g["worst"]):
            g["worst"] = f["severity"]
        need = needed_version(f["version"], f["fixed"])
        f["fix_target"] = need
        if need is None:
            g["unfixed"] += 1
        elif g["target"] is None or vkey(need) > vkey(g["target"]):
            g["target"] = need
    out = sorted(groups.values(), key=lambda g: (g["target"] is None, sev_rank(g["worst"]), g["package"]))
    for g in out:
        g["command"] = update_command(g)
    return out


def update_command(g):
    t, n, eco = g["target"], g["package"], g["ecosystem"]
    if not t:
        return None
    if g["kind"] == "system":
        binaries = sorted({s.split(":", 1)[1] for s in g["source"].split(", ") if s.startswith("system:")})
        if eco.startswith(("Ubuntu", "Debian")):
            return "sudo apt-get update && sudo apt-get install --only-upgrade " + " ".join(binaries)
        if eco.startswith("Alpine"):
            return "apk update && apk upgrade " + " ".join(binaries)
        return "sudo dnf upgrade " + " ".join(binaries)
    if g["kind"] == "vendored":
        return f"заменить файл {g['source']} на {n} {t} (и обновить THIRD_PARTY_LICENSES.md)"
    return {
        "npm": f"npm install {n}@{t}",
        "PyPI": f"pip install '{n}=={t}'  # и закрепить в requirements/lock",
        "Go": f"go get {n}@v{t} && go mod tidy" if n != "stdlib" else f"обновить Go до {t}",
        "crates.io": f"cargo update -p {n} --precise {t}",
        "Packagist": f"composer require {n}:^{t}",
        "RubyGems": f"bundle update {n}  # до {t}",
        "Maven": f"обновить {n} до {t} в build.gradle и пересоздать gradle.lockfile",
        "NuGet": f"dotnet add package {n} --version {t}",
    }.get(eco, f"обновить {n} до {t}")


def run_scan(paths, system_root=None, osv=None, ignore_file=None, include_dev=True, today=None, kernel_headers=False):
    scan = Scan()
    meta = collect(paths, scan, system_root, kernel_headers=kernel_headers)
    pkgs = [p for p in scan.unique() if include_dev or not p.dev]
    rules, ignore_warnings = load_ignores(ignore_file, today)
    scan.warnings += ignore_warnings
    osv = osv or OSV()
    ids_per_pkg = osv.query_ids(pkgs) if pkgs else []
    pairs = sorted({i for ids in ids_per_pkg for i in ids})
    details = osv.vulns(pairs)
    findings, ignored_list = [], []
    for p, ids in zip(pkgs, ids_per_pkg):
        for vid, _ in ids:
            v = details.get(vid)
            if not v or v.get("withdrawn"):
                continue
            aliases = sorted(set([vid] + (v.get("aliases") or []) + (v.get("upstream") or [])))
            cves = [a for a in aliases if a.startswith("CVE-")]
            level, score, basis = assess(v, p.kind == "system")
            f = {
                "id": vid, "cve": cves, "aliases": aliases, "severity": level, "cvss": score, "basis": basis,
                "package": p.name, "version": p.version, "ecosystem": p.ecosystem, "source": p.source,
                "dev": p.dev, "kind": p.kind, "summary": (v.get("summary") or (v.get("details") or "")[:200]).strip(),
                "fixed": fixed_versions(v, p), "url": f"https://osv.dev/vulnerability/{vid}",
                "published": v.get("published", ""),
            }
            rule = ignored(rules, aliases, p)
            if rule:
                f["ignored"] = {"reason": rule["reason"], "until": rule["until"]}
                ignored_list.append(f)
            else:
                findings.append(f)
    # Одна и та же уязвимость в нескольких базах (GHSA + CVE + PYSEC) — оставляем одну запись на пакет.
    findings = dedupe(findings)
    findings.sort(key=lambda f: (sev_rank(f["severity"]), f["kind"] != "system", f["package"], f["id"]))
    recs = recommendations(findings)
    return {"meta": meta, "packages": pkgs, "warnings": scan.warnings, "findings": findings,
            "recommendations": recs, "ignored": dedupe(ignored_list), "osv_requests": osv.requests}


def dedupe(items):
    out, index = [], {}
    for f in items:
        key = (f["ecosystem"], f["package"], f["version"])
        hit = None
        for a in f["aliases"]:
            hit = index.get((key, a))
            if hit:
                break
        if hit:
            hit["aliases"] = sorted(set(hit["aliases"]) | set(f["aliases"]))
            hit["cve"] = sorted(set(hit["cve"]) | set(f["cve"]))
            if sev_rank(f["severity"]) < sev_rank(hit["severity"]):
                hit.update(severity=f["severity"], cvss=f["cvss"], basis=f["basis"])
            for x in f["fixed"]:
                if x not in hit["fixed"]:
                    hit["fixed"].append(x)
            for a in hit["aliases"]:
                index[(key, a)] = hit
            continue
        out.append(f)
        for a in f["aliases"]:
            index[(key, a)] = f
    return out

# ------------------------------------------------------------------ отчёты

T = {
    "ru": {"title": "Проверка на уязвимости (CVE)", "pkgs": "Пакетов проверено", "found": "Уязвимостей", "ign": "Исключено",
           "pkg": "Пакет", "ver": "Версия", "fix": "Исправлено в", "src": "Где", "sev": "Уровень", "none": "Известных уязвимостей не найдено",
           "warn": "Предупреждения", "os": "Система", "lock": "Lock-файлы", "result": "Итог", "ok": "пройдено", "bad": "есть уязвимости",
           "upd": "обновить до", "nofix": "исправления нет", "dev": "dev", "recs": "Что обновить", "cmd": "Команда", "nofix_pkgs": "Без исправления, отслеживать"},
    "en": {"title": "Vulnerability scan (CVE)", "pkgs": "Packages scanned", "found": "Vulnerabilities", "ign": "Ignored",
           "pkg": "Package", "ver": "Version", "fix": "Fixed in", "src": "Where", "sev": "Severity", "none": "No known vulnerabilities",
           "warn": "Warnings", "os": "System", "lock": "Lockfiles", "result": "Result", "ok": "passed", "bad": "vulnerabilities found",
           "upd": "upgrade to", "nofix": "no fix yet", "dev": "dev", "recs": "What to upgrade", "cmd": "Command", "nofix_pkgs": "No fix yet, monitor"},
}


def counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    return c


def passed(findings, fail_on, fail_unfixed=False):
    """Уязвимости без исправления по умолчанию не блокируют (обновиться некуда), но показываются в отчёте."""
    if not fail_unfixed:
        findings = [f for f in findings if f.get("fix_target")]
    if fail_on == "never":
        return True
    if fail_on == "unknown":  # строже всего: любая находка
        return not findings
    # «unknown» (нет оценки) считаем как medium: неизвестно — не значит безопасно.
    limit = sev_rank(fail_on)
    return not any(sev_rank("medium" if f["severity"] == "unknown" else f["severity"]) <= limit for f in findings)


def render_recs(rep, t):
    e = html.escape
    recs = rep.get("recommendations") or []
    if not recs:
        return ""
    rows = "".join(
        f"<tr><td><span class='sev {e(g['worst'])}'>{e(g['worst'])}</span></td><td><b>{e(g['package'])}</b> {e(g['version'])}<br><small>{e(g['ecosystem'])}</small></td>"
        f"<td>{' · '.join(e(k) + ' ' + str(v) for k, v in g['counts'].items() if v)}</td>"
        f"<td>{e(g['target'] or t['nofix'])}{('<br><small>' + str(g['unfixed']) + ' ' + t['nofix'] + '</small>') if g['target'] and g['unfixed'] else ''}</td>"
        f"<td><code>{e(g['command'] or '')}</code></td></tr>" for g in recs)
    return (f"<h2>{t['recs']} ({len(recs)})</h2><div class='tw'><table><thead><tr><th>{t['sev']}</th><th>{t['pkg']}</th>"
            f"<th>{t['found']}</th><th>{t['upd']}</th><th>{t['cmd']}</th></tr></thead><tbody>{rows}</tbody></table></div>")


def render_html(rep, lang):
    t = T[lang]
    e = html.escape
    rows = "".join(
        f"<tr data-sev='{e(f['severity'])}'><td><span class='sev {e(f['severity'])}'>{e(f['severity'])}</span>"
        f"{'<br><small>CVSS ' + e(str(f['cvss'])) + '</small>' if f['cvss'] is not None else ''}</td>"
        f"<td><b>{e(f['package'])}</b> {e(f['version'])}<br><small>{e(f['ecosystem'])}{' · ' + t['dev'] if f['dev'] else ''}</small></td>"
        f"<td><a href='{e(f['url'])}' target='_blank' rel='noreferrer noopener'>{e(f['id'])}</a><br><small>{e(', '.join(f['cve']))}</small><br>{e(f['summary'])}</td>"
        f"<td>{e(', '.join(f['fixed'])) or t['nofix']}</td><td><small>{e(f['source'])}</small></td></tr>"
        for f in rep["findings"])
    warns = "".join(f"<li>{e(w)}</li>" for w in rep["warnings"])
    c = rep["counts"]
    return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t['title']}</title><style>
:root{{--bg:#fff;--fg:#1d2330;--mut:#5c6578;--line:#dfe3ea;--card:#f6f7f9;--critical:#b3261e;--high:#d0541b;--medium:#a77700;--low:#2f6db5;--unknown:#5c6578;--ok:#1d7a3e}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b313b;--card:#1b1f26;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b23a;--low:#6ea8ff;--unknown:#9aa3b2;--ok:#4cc27a}}}}
:root[data-theme=dark]{{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b313b;--card:#1b1f26;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b23a;--low:#6ea8ff;--unknown:#9aa3b2;--ok:#4cc27a}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}main{{max-width:1200px;margin:0 auto;padding:16px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px}}.meta div{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px}}
.meta span{{display:block;color:var(--mut);font-size:12px}}.tw{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;word-break:break-word}}small{{color:var(--mut)}}a{{color:var(--low)}}
.sev{{display:inline-block;border-radius:4px;padding:0 6px;font-size:12px;font-weight:600;color:#fff;text-transform:uppercase}}
.sev.critical{{background:var(--critical)}}.sev.high{{background:var(--high)}}.sev.medium{{background:var(--medium)}}.sev.low{{background:var(--low)}}.sev.unknown{{background:var(--unknown)}}
.ok{{color:var(--ok);font-weight:600}}code{{font-size:12px;word-break:break-all}}.bad{{color:var(--critical);font-weight:600}}
</style></head><body><main><h1>{t['title']}</h1><div class="meta">
<div><span>{t['pkgs']}</span>{rep['stats']['packages']}</div>
<div><span>{t['found']}</span>critical {c['critical']} · high {c['high']} · medium {c['medium']} · low {c['low']} · unknown {c['unknown']}</div>
<div><span>{t['ign']}</span>{len(rep['ignored'])}</div>
<div><span>{t['os']}</span>{e(rep['meta']['os'] or '—')}</div>
<div><span>{t['result']} (fail-on {e(rep['fail_on'])})</span><span class="{'ok' if rep['passed'] else 'bad'}">{t['ok'] if rep['passed'] else t['bad']}</span></div>
<div><span>OSV.dev · {e(rep['generated'])}</span>allupdsw-cve-scan {VERSION}</div></div>
{f'<h2>{t["warn"]}</h2><ul>{warns}</ul>' if warns else ''}
{render_recs(rep, t)}
<h2>{t['found']} ({len(rep['findings'])})</h2>
{f'<div class="tw"><table><thead><tr><th>{t["sev"]}</th><th>{t["pkg"]}</th><th>ID</th><th>{t["fix"]}</th><th>{t["src"]}</th></tr></thead><tbody>{rows}</tbody></table></div>' if rows else f'<p class="ok">{t["none"]}</p>'}
</main></body></html>
"""


def sbom(pkgs, meta):
    """CycloneDX 1.5 (JSON) — перечень всех компонентов для справки и аудита."""
    purl_type = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo", "Packagist": "composer",
                 "RubyGems": "gem", "Maven": "maven", "NuGet": "nuget"}
    comps = []
    for p in pkgs:
        t = purl_type.get(p.ecosystem) or ("deb" if p.ecosystem.startswith(("Debian", "Ubuntu")) else "apk" if p.ecosystem.startswith("Alpine") else "rpm" if p.kind == "system" else "generic")
        name = p.name.replace(":", "/") if t == "maven" else p.name
        comps.append({"type": "library", "name": p.name, "version": p.version,
                      "purl": f"pkg:{t}/{name}@{p.version}", "properties": [{"name": "allupdsw:source", "value": p.source}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                         "tools": [{"name": "allupdsw-cve-scan", "version": VERSION}]},
            "components": comps}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Проверка библиотек и системы на CVE (OSV.dev)")
    ap.add_argument("paths", nargs="*", help="папки или lock-файлы проекта (по умолчанию — ничего, если указан только --system)")
    ap.add_argument("--system", action="store_true", help="проверить и системные пакеты (dpkg/apk/rpm)")
    ap.add_argument("--root", default="/", help="корень ФС для --system (образ, копия сервера)")
    ap.add_argument("--kernel-headers", action="store_true", help="проверять и пакет заголовков ядра (linux-libc-dev)")
    ap.add_argument("--out", default="cve-report", help="папка отчёта")
    ap.add_argument("--lang", choices=["ru", "en"], default="ru")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "unknown", "never"])
    ap.add_argument("--ignore", default=".cve-ignore.json", help="файл исключений с причиной и сроком")
    ap.add_argument("--no-dev", action="store_true", help="не проверять dev-зависимости (по умолчанию проверяются)")
    ap.add_argument("--fail-unfixed", action="store_true", help="блокировать и уязвимостями, для которых ещё нет исправления")
    ap.add_argument("--sbom", help="записать перечень компонентов CycloneDX JSON")
    ap.add_argument("--osv-url", default=os.environ.get("OSV_URL", OSV_URL))
    ap.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "allupdsw-cve"))
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)
    if not a.paths and not a.system:
        a.paths = ["."]
    for p in a.paths:
        if not Path(p).exists():
            print(f"Ошибка: нет такого пути {p}", file=sys.stderr)
            return 2
    if a.workers < 1 or a.timeout <= 0:
        print("Ошибка: --workers ≥ 1, --timeout > 0", file=sys.stderr)
        return 2
    osv = OSV(a.osv_url, None if a.no_cache else a.cache, a.timeout, a.workers)
    try:
        res = run_scan(a.paths, a.root if a.system else None, osv, a.ignore, include_dev=not a.no_dev, kernel_headers=a.kernel_headers)
    except (OSVError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    rep = {
        "tool": "allupdsw-cve-scan", "version": VERSION, "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "fail_on": a.fail_on, "meta": res["meta"], "warnings": res["warnings"],
        "stats": {"packages": len(res["packages"]), "osv_requests": res["osv_requests"]},
        "counts": counts(res["findings"]), "findings": res["findings"], "ignored": res["ignored"],
    }
    rep["recommendations"] = res["recommendations"]
    rep["fail_unfixed"] = a.fail_unfixed
    rep["passed"] = passed(res["findings"], a.fail_on, a.fail_unfixed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.html").write_text(render_html(rep, a.lang), encoding="utf-8")
    if a.sbom:
        Path(a.sbom).write_text(json.dumps(sbom(res["packages"], res["meta"]), ensure_ascii=False, indent=2), encoding="utf-8")

    t = T[a.lang]
    c = rep["counts"]
    print(f"{t['pkgs']}: {len(res['packages'])}" + (f"; {t['os']}: {res['meta']['os']}" if res["meta"]["os"] else ""))
    print(f"{t['found']}: critical {c['critical']}, high {c['high']}, medium {c['medium']}, low {c['low']}, unknown {c['unknown']}; {t['ign']}: {len(res['ignored'])}")
    for w in res["warnings"]:
        print(f"! {w}")
    recs = res["recommendations"]
    fixable = [g for g in recs if g["target"]]
    unfixed = [g for g in recs if not g["target"]]
    for g in fixable:
        cnt = ", ".join(f"{k} {v}" for k, v in g["counts"].items() if v)
        tail = f"{t['upd']} {g['target']}" + (f" ({g['unfixed']} {t['nofix']})" if g["unfixed"] else "")
        print(f"  [{g['worst']}] {g['package']} {g['version']} ({g['ecosystem']}): {cnt} → {tail}")
        print(f"      $ {g['command']}")
    if unfixed:
        names = ", ".join(f"{g['package']} [{g['worst']}]" for g in unfixed[:12])
        more = f" … +{len(unfixed) - 12}" if len(unfixed) > 12 else ""
        print(f"  {t['nofix_pkgs']} ({len(unfixed)}): {names}{more}")
    print(f"{t['result']}: {t['ok'] if rep['passed'] else t['bad']} — {out / 'report.html'}")
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
