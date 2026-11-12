#!/usr/bin/env node
// Краулер проверки проектов: функциональность, все формы, безопасность, мобильная версия.
// ЗАПУСКАТЬ ТОЛЬКО НА ТЕСТОВОМ СТЕНДЕ: краулер отправляет формы с тестовыми и атакующими данными.
//
//   node crawl.mjs --url http://localhost:8080 [--config crawl.json] [--out report]
//   node crawl.mjs --help
//
// Документация: README.md в этой папке.

import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { chromium, devices, request as pwRequest } from 'playwright';
import {
  CHECKS, checkInfo, sevRank, RX, XSS_PAYLOAD, SSTI_PAYLOAD, SQLI_PAYLOADS, TRAVERSAL_PAYLOAD, SENSITIVE_PATHS,
} from './checks.mjs';
import { renderHtml } from './report.mjs';

export const VERSION = '1.0.0';

export const DEFAULTS = {
  url: null,
  out: 'crawl-report',
  lang: 'ru',
  maxPages: 300,
  maxDepth: 6,
  maxVariants: 3, // сколько разных query-строк одного пути обходить
  maxForms: 100,
  maxMobilePages: 60,
  delay: 0, // мс между запросами
  timeout: 15000,
  forms: 'full', // none | safe | full
  allowDestructive: false,
  include: null, // RegExp-строка: обходить только подходящие URL
  exclude: null, // RegExp-строка: не обходить
  public: null, // RegExp-строка: страницы, которые и должны быть доступны без входа
  versionRegex: String.raw`\bv?\d+\.\d+\.\d+\b`,
  mobile: true,
  security: true,
  authCheck: true,
  bruteforce: 0, // число неверных попыток входа для проверки защиты от перебора (0 — не проверять)
  checkExternal: false,
  insecure: false, // игнорировать ошибки TLS (самоподписанный сертификат на стенде)
  failOn: 'high',
  debug: false,
  login: null, // { url, user, pass, userSelector, passSelector, submitSelector, successSelector }
  storageState: null,
  protectedProbes: ['/api/v1/debug/status', '/api/v1/access/users', '/api/v1/access/audit'],
};

const HELP = `Краулер проверки проектов ${VERSION}

  --url URL                адрес стенда (обязательно)
  --config FILE            JSON с настройками (те же ключи, что ниже, в camelCase)
  --out DIR                папка отчёта (report.json, report.html, screenshots/)   [crawl-report]
  --lang ru|en             язык отчёта                                             [ru]
  --max-pages N            предел страниц                                          [300]
  --max-depth N            глубина обхода                                          [6]
  --forms none|safe|full   формы: не трогать / допустимые+граничные / + атаки      [full]
  --allow-destructive      отправлять и формы удаления/выхода (по умолчанию нет)
  --include RE / --exclude RE   фильтр URL
  --public RE              страницы, открытые без входа намеренно
  --version-regex RE       как выглядит номер версии в меню
  --no-mobile --no-security --no-auth-check   отключить разделы
  --bruteforce N           проверить защиту от перебора N неверными входами        [0]
  --check-external         проверять внешние ссылки
  --insecure               игнорировать ошибки TLS
  --fail-on LEVEL          код выхода 1 при находках этого уровня и выше           [high]
  --delay MS               пауза между запросами                                   [0]
  --debug                  подробный вывод
  Вход: --login-url URL, логин/пароль из переменных CRAWL_USER / CRAWL_PASS
        (селекторы полей — в config.login), или --storage-state FILE.

Коды выхода: 0 — ок, 1 — есть находки уровня --fail-on и выше, 2 — ошибка запуска.
`;

// ------------------------------------------------------------------ утилиты
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// У page.evaluate/page.content нет собственного тайм-аута: ограничиваем сами, чтобы краулер не зависал.
export function withTimeout(promise, ms, fallback) {
  let t;
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise((r) => { t = setTimeout(() => r(fallback), ms); }),
  ]).finally(() => clearTimeout(t));
}

export function normalizeUrl(u, base) {
  try {
    const x = new URL(u, base);
    x.hash = '';
    if ((x.protocol === 'http:' && x.port === '80') || (x.protocol === 'https:' && x.port === '443')) x.port = '';
    return x.toString();
  } catch {
    return null;
  }
}

class Findings {
  constructor(lang) {
    this.lang = lang;
    this.items = [];
    this.keys = new Set();
  }

  add(id, url, detail = '', extra = {}) {
    const key = extra.dedupe ?? `${id}|${url}|${detail}`;
    if (this.keys.has(key)) return null;
    this.keys.add(key);
    const { severity, title } = checkInfo(id, this.lang);
    const f = { id, severity, title, url, detail: String(detail).slice(0, 2000), ...extra };
    delete f.dedupe;
    this.items.push(f);
    return f;
  }

  sorted() {
    return [...this.items].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id));
  }

  counts() {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.items) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }
}

// ------------------------------------------------------------------ краулер
export class Crawler {
  constructor(opts) {
    this.o = { ...DEFAULTS, ...opts };
    if (!this.o.url) throw new Error('--url обязателен');
    this.base = new URL(this.o.url);
    this.origin = this.base.origin;
    this.https = this.base.protocol === 'https:';
    this.f = new Findings(this.o.lang);
    this.pages = new Map(); // url → {status, depth, from, title, html}
    this.forms = new Map(); // signature → {pageUrl, form}
    this.variants = new Map();
    this.include = this.o.include ? new RegExp(this.o.include) : null;
    this.exclude = this.o.exclude ? new RegExp(this.o.exclude) : null;
    this.publicRe = this.o.public ? new RegExp(this.o.public) : null;
    this.versionRe = new RegExp(this.o.versionRegex);
    this.shots = path.join(this.o.out, 'screenshots');
    this.loginPath = null;
    this.stats = { requests: 0, formsTested: 0, formSubmits: 0, started: new Date().toISOString() };
    this.headerSeen = new Set();
  }

  log(...a) {
    if (this.o.debug) console.error('[crawl]', ...a);
  }

  sameOrigin(u) {
    try {
      return new URL(u).origin === this.origin;
    } catch {
      return false;
    }
  }

  allowed(u) {
    if (!this.sameOrigin(u)) return false;
    const x = new URL(u);
    if (RX.staticExt.test(x.pathname)) return false;
    if (this.include && !this.include.test(u)) return false;
    if (this.exclude && this.exclude.test(u)) return false;
    if (!this.o.allowDestructive && RX.destructive.test(decodeURIComponent(x.pathname + x.search))) return false;
    const key = x.origin + x.pathname;
    const set = this.variants.get(key) || new Set();
    if (!set.has(x.search) && set.size >= this.o.maxVariants) return false;
    return true;
  }

  markVariant(u) {
    const x = new URL(u);
    const key = x.origin + x.pathname;
    if (!this.variants.has(key)) this.variants.set(key, new Set());
    this.variants.get(key).add(x.search);
  }

  async run() {
    fs.mkdirSync(this.shots, { recursive: true });
    this.browser = await chromium.launch();
    try {
      const ctxOpts = { ignoreHTTPSErrors: this.o.insecure, locale: this.o.lang === 'en' ? 'en-US' : 'ru-RU' };
      if (this.o.storageState) ctxOpts.storageState = this.o.storageState;
      this.ctx = await this.browser.newContext({ ...ctxOpts, viewport: { width: 1440, height: 900 } });
      this.ctx.setDefaultTimeout(this.o.timeout);
      if (this.o.login) await this.doLogin();
      this.state = await this.ctx.storageState();

      await this.crawl();
      if (this.o.forms !== 'none') await this.testForms();
      if (this.o.security) {
        await this.probeQueryXss();
        await this.recheckStoredXss();
        await this.checkCookies();
        await this.probeSensitive();
        await this.probeOpenRedirect();
        if (this.o.authCheck && (this.o.login || this.o.storageState)) await this.checkAuth();
        if (this.o.bruteforce > 0 && this.o.login) await this.checkBruteforce();
      }
      if (this.o.mobile) await this.checkMobile();
      if (this.o.checkExternal) await this.checkExternalLinks();
    } finally {
      await this.browser.close();
    }
    return this.report();
  }

  // ---------------------------------------------------------------- вход
  async doLogin() {
    const L = {
      userSelector: 'input[name=username], input[name=login], input[name=email], input[type=email], input[name=user]',
      passSelector: 'input[type=password]',
      submitSelector: 'button[type=submit], input[type=submit], button:not([type])',
      ...this.o.login,
    };
    const user = L.user ?? process.env.CRAWL_USER;
    const pass = L.pass ?? process.env.CRAWL_PASS;
    if (!user || !pass) throw new Error('Для входа задайте CRAWL_USER и CRAWL_PASS');
    const loginUrl = new URL(L.url || this.o.url, this.o.url).toString();
    this.loginPath = new URL(loginUrl).pathname;
    this.loginCfg = { ...L, url: loginUrl };
    const page = await this.ctx.newPage();
    await page.goto(loginUrl);
    // Форму входа проверяем сразу: после входа краулер её уже не увидит.
    const data = await withTimeout(page.evaluate(extractPage), 10000, { forms: [] });
    for (const form of data.forms) this.registerForm(page.url(), form);
    await page.locator(L.userSelector).first().fill(user);
    await page.locator(L.passSelector).first().fill(pass);
    await Promise.all([
      page.waitForLoadState('networkidle').catch(() => {}),
      page.locator(L.submitSelector).first().click(),
    ]);
    await page.waitForLoadState('networkidle').catch(() => {});
    let ok;
    if (L.successSelector) ok = await page.locator(L.successSelector).count() > 0;
    else ok = (await page.locator(L.passSelector).count()) === 0;
    if (!ok) {
      await page.screenshot({ path: path.join(this.shots, 'login-failed.png') }).catch(() => {});
      await this.closePage(page);
      throw new Error(`Вход не выполнен (${loginUrl}). Скриншот: ${this.shots}/login-failed.png`);
    }
    this.log('вход выполнен', page.url());
    await this.closePage(page);
  }

  // ---------------------------------------------------------------- обход
  watch(page, sink) {
    page.on('console', (m) => {
      // «Failed to load resource» уже учтено проверками http.* — не дублируем.
      if (m.type() === 'error' && !/^Failed to load resource/.test(m.text())) sink.console.push(m.text());
    });
    page.on('pageerror', (e) => sink.errors.push(String(e && e.message ? e.message : e)));
    page.on('response', (r) => {
      this.stats.requests++;
      sink.responses.push({ url: r.url(), status: r.status(), type: r.request().resourceType(), method: r.request().method() });
    });
    page.on('requestfailed', (r) => {
      const err = r.failure()?.errorText || '';
      if (!/ERR_ABORTED|NS_BINDING_ABORTED/.test(err)) sink.failed.push({ url: r.url(), error: err });
    });
  }

  async crawl() {
    const queue = [{ url: normalizeUrl(this.o.url), depth: 0, from: null }];
    const seen = new Set([queue[0].url]);
    this.markVariant(queue[0].url);
    while (queue.length && this.pages.size < this.o.maxPages) {
      const item = queue.shift();
      const links = await this.visit(item);
      for (const l of links) {
        if (seen.has(l) || item.depth + 1 > this.o.maxDepth) continue;
        if (!this.allowed(l)) continue;
        seen.add(l);
        this.markVariant(l);
        queue.push({ url: l, depth: item.depth + 1, from: item.url });
      }
      if (this.o.delay) await sleep(this.o.delay);
    }
  }

  async visit({ url, depth, from }) {
    const page = await this.ctx.newPage();
    const sink = { console: [], errors: [], responses: [], failed: [] };
    this.watch(page, sink);
    let resp;
    try {
      resp = await page.goto(url, { waitUntil: 'load' });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    } catch (e) {
      this.f.add('http.request_failed', url, e.message.split('\n')[0], { from });
      await this.closePage(page);
      return [];
    }
    const status = resp ? resp.status() : 0;
    const finalUrl = page.url();
    const info = { status, depth, from, finalUrl };
    this.pages.set(url, info);
    this.log(status, url);

    if (status >= 500) {
      const shot = await this.shot(page, 'http5xx');
      this.f.add('http.5xx', url, `HTTP ${status}`, { from, screenshot: shot });
    } else if (status >= 400) {
      this.f.add('http.4xx', url, `HTTP ${status}`, { from });
    }

    const headers = resp ? await resp.allHeaders() : {};
    const ctype = headers['content-type'] || '';
    const isHtml = /html/i.test(ctype);
    info.html = isHtml;

    if (isHtml) {
      this.checkHeaders(url, headers);
      this.checkLeaks(url, await withTimeout(page.content(), 5000, ''));
    }
    for (const e of sink.errors) this.f.add('js.error', url, e);
    for (const c of sink.console) this.f.add('js.console_error', url, c);
    for (const r of sink.responses) {
      if (r.type === 'document' && r.url === resp?.url()) continue;
      if (this.sameOrigin(r.url) && r.status >= 400) this.f.add('http.resource_error', url, `${r.method} ${r.url} → ${r.status}`);
      if (this.https && r.url.startsWith('http://')) this.f.add('sec.mixed_content', url, r.url);
    }
    for (const r of sink.failed) if (this.sameOrigin(r.url)) this.f.add('http.request_failed', url, `${r.url}: ${r.error}`);

    let links = [];
    if (isHtml && status < 400) {
      if (await this.xssMarker(page)) this.f.add('sec.xss_stored', url, 'метка XSS найдена при обходе');
      const text = await withTimeout(page.evaluate(() => (document.body ? document.body.innerText : '')), 5000, '');
      if (!this.versionRe.test(text)) this.f.add('ux.version_missing', url, `desktop: ${this.versionRe}`);
      info.title = await withTimeout(page.title(), 3000, '');
      const data = await withTimeout(page.evaluate(extractPage), 10000, { links: [], forms: [] });
      links = data.links.map((l) => normalizeUrl(l, finalUrl)).filter(Boolean);
      info.links = links.length;
      for (const form of data.forms) this.registerForm(finalUrl, form);
    }
    await this.closePage(page);
    return [...new Set(links)];
  }

  async shot(page, tag) {
    const name = `${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}.png`;
    try {
      await page.screenshot({ path: path.join(this.shots, name), fullPage: false });
      return `screenshots/${name}`;
    } catch {
      return null;
    }
  }

  checkHeaders(url, h) {
    // Заголовки обычно общие для всего сайта — сообщаем один раз на проверку.
    const once = (id, detail) => {
      if (this.headerSeen.has(id)) return;
      this.headerSeen.add(id);
      this.f.add(id, url, detail);
    };
    const csp = h['content-security-policy'] || '';
    if (!csp) once('hdr.csp', 'Content-Security-Policy отсутствует');
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp)) once('hdr.clickjacking', 'нет X-Frame-Options и CSP frame-ancestors');
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') once('hdr.nosniff', h['x-content-type-options'] || 'отсутствует');
    if (!h['referrer-policy']) once('hdr.referrer', 'Referrer-Policy отсутствует');
    if (this.https && !h['strict-transport-security']) once('hdr.hsts', 'Strict-Transport-Security отсутствует');
    for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
      if (h[k] && RX.versionHeader.test(h[k])) once('hdr.version_disclosure', `${k}: ${h[k]}`);
    }
  }

  checkLeaks(url, html) {
    const m = html.match(RX.stackTrace);
    if (m) this.f.add('leak.stack_trace', url, m[0]);
    if (RX.dirListing.test(html)) this.f.add('leak.dir_listing', url, 'Index of /');
    const s = html.match(RX.sqlError);
    if (s) this.f.add('sec.sql_error', url, s[0]);
  }

  async xssMarker(page) {
    await page.waitForTimeout(150);
    return withTimeout(page.evaluate(() => window.__crawlerXss === 1 || !!document.querySelector('[data-crawler-xss]')), 3000, false);
  }

  registerForm(pageUrl, form) {
    // Статические проверки формы
    const action = form.action || pageUrl;
    if (form.fields.some((x) => x.type === 'password') && form.method === 'get') {
      this.f.add('sec.password_get', pageUrl, `form → ${action}`);
    }
    if (this.https && action.startsWith('http://')) this.f.add('sec.insecure_form', pageUrl, action);
    if (form.method === 'post' && !form.fields.some((x) => x.hidden && RX.csrfField.test(x.name))) {
      this.f.add('sec.csrf_missing', pageUrl, `POST ${action}`, { dedupe: `csrf|${action}` });
    }
    for (const x of form.fields) {
      if (!x.hidden && !x.hasLabel) this.f.add('form.no_label', pageUrl, `${x.name} (${x.type})`, { dedupe: `label|${action}|${x.name}` });
      if (x.type === 'password' && !/current-password|new-password|off/.test(x.autocomplete || '')) {
        this.f.add('form.password_autocomplete', pageUrl, `${x.name}: autocomplete="${x.autocomplete || ''}"`, { dedupe: `ac|${action}|${x.name}` });
      }
    }
    const sig = `${form.method} ${action.split('?')[0]} ${form.fields.map((x) => x.name).sort().join(',')}`;
    if (this.forms.has(sig) || this.forms.size >= this.o.maxForms) return;
    this.forms.set(sig, { pageUrl, form, action });
  }

  // ---------------------------------------------------------------- формы
  formCases() {
    const cases = [
      { name: 'valid', gen: (x) => validValue(x), validate: true },
      { name: 'empty', gen: () => '', novalidate: true },
      { name: 'long', gen: (x) => (textual(x) ? 'Ж'.repeat(5000) + '😀' : validValue(x)), novalidate: true },
      { name: 'unicode', gen: (x) => (textual(x) ? ' ‮тест\u0000 😀 ' + "O'Brien" : validValue(x)), novalidate: true },
      { name: 'numbers', gen: (x) => (numeric(x) ? '-99999999999999999999' : validValue(x)), novalidate: true },
      { name: 'invalid_format', gen: (x) => (formatted(x) ? 'not-valid-%%' : validValue(x)), novalidate: true },
    ];
    if (this.o.forms === 'full' && this.o.security) {
      cases.push(
        { name: 'xss', gen: (x) => (choice(x) ? validValue(x) : XSS_PAYLOAD), novalidate: true, xss: true },
        { name: 'ssti', gen: (x) => (choice(x) ? validValue(x) : SSTI_PAYLOAD), novalidate: true, ssti: true },
        ...SQLI_PAYLOADS.map((p, i) => ({ name: `sqli${i + 1}`, gen: (x) => (choice(x) ? validValue(x) : p), novalidate: true })),
        { name: 'traversal', gen: (x) => (choice(x) ? validValue(x) : TRAVERSAL_PAYLOAD), novalidate: true },
      );
    }
    return cases;
  }

  isDestructive(entry) {
    const { form, action } = entry;
    return RX.destructive.test(`${action} ${form.submitText} ${form.id} ${form.name}`);
  }

  async testForms() {
    for (const entry of this.forms.values()) {
      if (!this.o.allowDestructive && this.isDestructive(entry)) {
        this.f.add('form.skipped_destructive', entry.pageUrl, `${entry.form.method.toUpperCase()} ${entry.action} «${entry.form.submitText.trim()}»`);
        continue;
      }
      if (entry.form.fields.some((x) => x.type === 'password') && this.loginPath && new URL(entry.pageUrl).pathname === this.loginPath) {
        continue; // форму входа проверяет checkBruteforce, чтобы не заблокировать тестового пользователя
      }
      this.stats.formsTested++;
      for (const c of this.formCases()) {
        await this.submitCase(entry, c);
        if (this.o.delay) await sleep(this.o.delay);
      }
    }
  }

  async submitCase(entry, c) {
    const page = await this.ctx.newPage();
    const sink = { console: [], errors: [], responses: [], failed: [] };
    const t0 = Date.now();
    try {
      await page.goto(entry.pageUrl, { waitUntil: 'load' });
      await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
      const values = {};
      for (const x of entry.form.fields) if (!x.hidden && x.type !== 'file') values[x.name] = c.gen(x);
      const before = (await withTimeout(page.content(), 5000, '')).match(RX.ssti) ? 1 : 0;
      this.watch(page, sink); // считаем только ответы после отправки
      this.stats.formSubmits++;
      await this.submitAndWait(page, { index: entry.form.index, values, novalidate: !!c.novalidate });
      const where = `${entry.form.method.toUpperCase()} ${entry.action} [${c.name}]`;
      for (const r of sink.responses) {
        if (this.sameOrigin(r.url) && r.status >= 500 && ['document', 'xhr', 'fetch'].includes(r.type)) {
          const shot = await this.shot(page, 'form5xx');
          this.f.add('form.server_error', entry.pageUrl, `${where} → ${r.status}`, { screenshot: shot, dedupe: `f5|${entry.action}|${c.name}` });
        }
      }
      for (const e of sink.errors) this.f.add('js.error', entry.pageUrl, `${where}: ${e}`, { dedupe: `fjs|${entry.action}|${e}` });
      const html = await withTimeout(page.content(), 5000, '');
      const sql = html.match(RX.sqlError);
      if (sql) this.f.add('sec.sql_error', entry.pageUrl, `${where}: ${sql[0]}`, { dedupe: `fsql|${entry.action}` });
      const st = html.match(RX.stackTrace);
      if (st) this.f.add('leak.stack_trace', entry.pageUrl, `${where}: ${st[0]}`, { dedupe: `fst|${entry.action}` });
      if (RX.passwd.test(html)) this.f.add('sec.path_traversal', entry.pageUrl, where, { dedupe: `fpt|${entry.action}` });
      if (c.ssti && !before && RX.ssti.test(html)) this.f.add('sec.ssti', entry.pageUrl, where, { dedupe: `fssti|${entry.action}` });
      if (c.xss && (await this.xssMarker(page))) {
        const shot = await this.shot(page, 'xss');
        this.f.add('sec.xss_reflected', entry.pageUrl, where, { screenshot: shot, dedupe: `fxss|${entry.action}` });
      }
      const after = page.url();
      if (this.sameOrigin(after) && !this.pages.has(normalizeUrl(after))) this.extraPages.add(normalizeUrl(after));
    } catch (e) {
      this.log('form case error', c.name, e.message);
    } finally {
      this.log('form', entry.action, c.name, `${Date.now() - t0}ms`);
      await this.closePage(page);
    }
  }

  // Отправить форму и дождаться результата. Если началась навигация — ждём загрузки новой страницы:
  // закрытие вкладки посреди перехода вешает браузер.
  async submitAndWait(page, args) {
    let navigating = false;
    const onReq = (r) => {
      if (r.isNavigationRequest() && r.frame() === page.mainFrame()) navigating = true;
    };
    page.on('request', onReq);
    const loaded = page.waitForEvent('load', { timeout: this.o.timeout }).catch(() => null);
    await withTimeout(page.evaluate(fillAndSubmit, args), 5000, null);
    await sleep(300);
    if (navigating) await loaded;
    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    page.off('request', onReq);
  }

  // Закрыть вкладку безопасно: дождаться окончания загрузки и не ждать бесконечно.
  async closePage(page) {
    await page.waitForLoadState('load', { timeout: 5000 }).catch(() => {});
    await withTimeout(page.close(), 10000, null);
  }

  extraPages = new Set();

  // ---------------------------------------------------------------- безопасность
  async probeQueryXss() {
    if (this.o.forms !== 'full') return;
    const urls = [...this.pages.keys()].filter((u) => new URL(u).search).slice(0, 50);
    for (const u of urls) {
      const x = new URL(u);
      for (const key of [...x.searchParams.keys()]) {
        if (RX.redirectParam.test(key)) continue;
        const y = new URL(u);
        y.searchParams.set(key, XSS_PAYLOAD);
        const page = await this.ctx.newPage();
        try {
          await page.goto(y.toString(), { waitUntil: 'load' });
          if (await this.xssMarker(page)) {
            const shot = await this.shot(page, 'xss');
            this.f.add('sec.xss_reflected', u, `параметр ${key}`, { screenshot: shot });
          }
          const yy = new URL(u);
          yy.searchParams.set(key, SSTI_PAYLOAD);
          await page.goto(yy.toString(), { waitUntil: 'load' });
          if (RX.ssti.test(await withTimeout(page.content(), 5000, ''))) this.f.add('sec.ssti', u, `параметр ${key}`);
          const yt = new URL(u);
          yt.searchParams.set(key, TRAVERSAL_PAYLOAD);
          await page.goto(yt.toString(), { waitUntil: 'load' });
          if (RX.passwd.test(await withTimeout(page.content(), 5000, ''))) this.f.add('sec.path_traversal', u, `параметр ${key}`);
        } catch (e) {
          this.log('query probe', e.message);
        } finally {
          await this.closePage(page);
        }
      }
    }
  }

  async recheckStoredXss() {
    if (this.o.forms !== 'full') return;
    // Страницы, куда ведёт отправка формы с атакующей строкой в URL, — это отражённый XSS (уже проверен), не хранимый.
    const payloadInUrl = (u) => /data-crawler-xss|1337\*7331|etc\/passwd|OR '1'='1/.test(decodeURIComponent(u.replace(/\+/g, ' ')));
    const extra = [...this.extraPages].filter((u) => !payloadInUrl(u));
    const urls = [...new Set([...this.pages.entries()].filter(([, v]) => v.html && v.status < 400).map(([k]) => k).concat(extra))];
    for (const u of urls.slice(0, this.o.maxPages)) {
      const page = await this.ctx.newPage();
      try {
        await page.goto(u, { waitUntil: 'load' });
        if (await this.xssMarker(page)) {
          const shot = await this.shot(page, 'xss-stored');
          this.f.add('sec.xss_stored', u, 'сохранённые данные из форм выводятся без экранирования', { screenshot: shot });
        }
      } catch (e) {
        this.log('stored xss', e.message);
      } finally {
        await this.closePage(page);
      }
    }
  }

  async checkCookies() {
    const cookies = await this.ctx.cookies(this.origin);
    for (const c of cookies) {
      if (RX.sessionCookie.test(c.name) && !c.httpOnly) this.f.add('sec.cookie_httponly', this.origin, c.name);
      if (this.https && !c.secure) this.f.add('sec.cookie_secure', this.origin, c.name);
      if (c.sameSite === 'None') this.f.add('sec.cookie_samesite', this.origin, c.name);
    }
  }

  async anon() {
    if (!this._anon) this._anon = await pwRequest.newContext({ ignoreHTTPSErrors: this.o.insecure, baseURL: this.origin });
    return this._anon;
  }

  async probeSensitive() {
    const rq = await this.anon();
    for (const [p, sign] of SENSITIVE_PATHS) {
      try {
        const r = await rq.get(p, { maxRedirects: 0, timeout: this.o.timeout });
        if (r.status() === 200) {
          const body = (await r.body()).toString('latin1').slice(0, 20000);
          if (sign.test(body)) this.f.add('sec.sensitive_file', this.origin + p, `HTTP 200, ${body.slice(0, 60).replace(/\s+/g, ' ')}`);
        }
      } catch (e) {
        this.log('probe', p, e.message);
      }
    }
    for (const p of this.o.protectedProbes) {
      try {
        const r = await rq.get(p, { maxRedirects: 0, timeout: this.o.timeout });
        if (r.status() === 200 && !/type=["']?password/i.test((await r.text()).slice(0, 50000))) {
          this.f.add('sec.no_auth', this.origin + p, 'служебный API отвечает без авторизации');
        }
      } catch (e) {
        this.log('probe', p, e.message);
      }
    }
  }

  async probeOpenRedirect() {
    const rq = await this.ctx.request;
    const evil = 'https://crawler-redirect.invalid/x';
    const tried = new Set();
    for (const u of this.pages.keys()) {
      const x = new URL(u);
      for (const key of [...x.searchParams.keys()]) {
        if (!RX.redirectParam.test(key)) continue;
        const sig = `${x.pathname}|${key}`;
        if (tried.has(sig)) continue;
        tried.add(sig);
        for (const val of [evil, '//crawler-redirect.invalid/x']) {
          const y = new URL(u);
          y.searchParams.set(key, val);
          try {
            const r = await rq.get(y.toString(), { maxRedirects: 0, timeout: this.o.timeout });
            const loc = r.headers()['location'] || '';
            if (r.status() >= 300 && r.status() < 400 && /crawler-redirect\.invalid/.test(loc)) {
              this.f.add('sec.open_redirect', u, `${key}=${val} → Location: ${loc}`, { dedupe: `or|${sig}` });
              break;
            }
          } catch (e) {
            this.log('redirect', e.message);
          }
        }
      }
    }
  }

  async checkAuth() {
    const rq = await this.anon();
    for (const [u, info] of this.pages) {
      if (!info.html || info.status >= 400) continue;
      const p = new URL(u).pathname;
      if (this.loginPath && p === this.loginPath) continue;
      if (this.publicRe && this.publicRe.test(u)) continue;
      try {
        const r = await rq.get(u, { maxRedirects: 0, timeout: this.o.timeout });
        if (r.status() !== 200) continue;
        const body = (await r.text()).slice(0, 200000);
        if (/type=["']?password/i.test(body)) continue; // показали форму входа
        this.f.add('sec.no_auth', u, 'HTTP 200 без cookie сессии');
      } catch (e) {
        this.log('auth', e.message);
      }
    }
  }

  async checkBruteforce() {
    const L = this.loginCfg;
    const ctx = await this.browser.newContext({ ignoreHTTPSErrors: this.o.insecure });
    const page = await ctx.newPage();
    let blocked = false;
    const fakeUser = `crawler-bruteforce-${Date.now()}`;
    try {
      for (let i = 0; i < this.o.bruteforce && !blocked; i++) {
        const resp = await page.goto(L.url);
        if (resp && resp.status() === 429) { blocked = true; break; }
        if ((await page.locator(L.passSelector).count()) === 0) { blocked = true; break; } // капча/блокировка вместо формы
        await page.locator(L.userSelector).first().fill(fakeUser);
        await page.locator(L.passSelector).first().fill(`wrong-${i}`);
        const [r] = await Promise.all([
          page.waitForResponse((x) => x.request().resourceType() === 'document' || x.request().method() === 'POST', { timeout: this.o.timeout }).catch(() => null),
          page.locator(L.submitSelector).first().click(),
        ]);
        if (r && r.status() === 429) blocked = true;
        const text = await withTimeout(page.evaluate(() => document.body.innerText), 5000, '');
        if (/captcha|капч|слишком много|too many|заблокир|locked|try again later|повторите позже/i.test(text)) blocked = true;
      }
      if (!blocked) this.f.add('sec.no_bruteforce_protection', L.url, `${this.o.bruteforce} неверных попыток подряд без 429/капчи/блокировки`);
    } finally {
      await ctx.close();
    }
  }

  // ---------------------------------------------------------------- мобильная версия
  async checkMobile() {
    const ctx = await this.browser.newContext({
      ...devices['Pixel 7'],
      ignoreHTTPSErrors: this.o.insecure,
      storageState: this.state,
      locale: this.o.lang === 'en' ? 'en-US' : 'ru-RU',
    });
    ctx.setDefaultTimeout(this.o.timeout);
    const urls = [...this.pages.entries()].filter(([, v]) => v.html && v.status < 400).map(([k]) => k).slice(0, this.o.maxMobilePages);
    for (const u of urls) {
      const page = await ctx.newPage();
      try {
        await page.goto(u, { waitUntil: 'load' });
        await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
        const m = await withTimeout(page.evaluate(mobileMetrics), 10000, null);
        if (!m) continue;
        if (!m.viewport) this.f.add('mobile.no_viewport', u, '<meta name="viewport"> отсутствует');
        if (m.scrollWidth > m.innerWidth + 1) {
          const shot = await this.shot(page, 'mobile-overflow');
          this.f.add('mobile.overflow', u, `ширина страницы ${m.scrollWidth}px > экрана ${m.innerWidth}px`, { screenshot: shot });
        }
        if (m.small.length) this.f.add('mobile.small_targets', u, `${m.small.length}: ${m.small.slice(0, 5).join(', ')}`);
        if (m.zoomInputs.length) this.f.add('mobile.input_zoom', u, m.zoomInputs.slice(0, 5).join(', '));
        if (!this.versionRe.test(m.text)) this.f.add('ux.version_missing', u, `mobile: ${this.versionRe}`);
      } catch (e) {
        this.log('mobile', e.message);
      } finally {
        await this.closePage(page);
      }
    }
    await ctx.close();
  }

  async checkExternalLinks() {
    // Внешние ссылки собираются заново с уже посещённых страниц (без повторного обхода).
    const rq = await pwRequest.newContext({ ignoreHTTPSErrors: true });
    const page = await this.ctx.newPage();
    const ext = new Map();
    for (const u of [...this.pages.keys()].slice(0, 100)) {
      try {
        await page.goto(u, { waitUntil: 'load' });
        const links = await withTimeout(page.evaluate(() => [...document.querySelectorAll('a[href^="http"]')].map((a) => a.href)), 5000, []);
        for (const l of links) if (!this.sameOrigin(l) && !ext.has(l)) ext.set(l, u);
      } catch { /* пропуск */ }
    }
    await this.closePage(page);
    for (const [l, from] of ext) {
      try {
        const r = await rq.get(l, { timeout: this.o.timeout, maxRedirects: 5 });
        if (r.status() >= 400 && r.status() !== 403 && r.status() !== 429) this.f.add('http.4xx', from, `внешняя ссылка ${l} → ${r.status()}`);
      } catch (e) {
        this.f.add('http.request_failed', from, `внешняя ссылка ${l}: ${e.message.split('\n')[0]}`);
      }
    }
    await rq.dispose();
  }

  // ---------------------------------------------------------------- отчёт
  report() {
    const findings = this.f.sorted();
    const counts = this.f.counts();
    const failRank = sevRank(this.o.failOn);
    const failed = this.o.failOn !== 'never' && findings.some((x) => sevRank(x.severity) <= failRank);
    const rep = {
      tool: 'allupdsw-crawler',
      version: VERSION,
      target: this.o.url,
      lang: this.o.lang,
      started: this.stats.started,
      finished: new Date().toISOString(),
      options: { ...this.o, login: this.o.login ? { ...this.o.login, user: undefined, pass: undefined } : null },
      stats: { ...this.stats, pages: this.pages.size, forms: this.forms.size },
      counts,
      failOn: this.o.failOn,
      passed: !failed,
      pages: [...this.pages.entries()].map(([url, v]) => ({ url, status: v.status, title: v.title || '', from: v.from })),
      findings,
    };
    fs.mkdirSync(this.o.out, { recursive: true });
    fs.writeFileSync(path.join(this.o.out, 'report.json'), JSON.stringify(rep, null, 2));
    fs.writeFileSync(path.join(this.o.out, 'report.html'), renderHtml(rep, CHECKS));
    return rep;
  }
}

// ------------------------------------------------------------------ код в браузере
function extractPage() {
  const links = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const h = a.getAttribute('href');
    if (!h || /^(javascript:|mailto:|tel:|data:|#)/i.test(h)) continue;
    const text = (a.innerText || '') + ' ' + (a.getAttribute('aria-label') || '');
    links.push({ href: a.href, text });
  }
  const forms = [...document.forms].map((f, index) => {
    const attrAction = f.getAttribute('action');
    const action = new URL(attrAction || location.href, location.href).href;
    const fields = [...f.elements]
      .filter((e) => e.name && !['submit', 'button', 'reset', 'image'].includes((e.type || '').toLowerCase()))
      .map((e) => ({
        name: e.name,
        tag: e.tagName.toLowerCase(),
        type: (e.type || 'text').toLowerCase(),
        required: !!e.required,
        min: e.min || '',
        max: e.max || '',
        minLength: e.minLength > 0 ? e.minLength : 0,
        maxLength: e.maxLength > 0 ? e.maxLength : 0,
        pattern: e.pattern || '',
        autocomplete: e.getAttribute('autocomplete') || '',
        options: e.tagName === 'SELECT' ? [...e.options].map((o) => o.value) : undefined,
        hidden: (e.type || '').toLowerCase() === 'hidden',
        hasLabel: !!((e.labels && e.labels.length) || e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') || e.title),
      }));
    const submitText = [...f.querySelectorAll('button, input[type=submit]')].map((b) => b.innerText || b.value || '').join(' ');
    return {
      index,
      method: (f.getAttribute('method') || 'get').toLowerCase(),
      action,
      id: f.id || '',
      name: f.getAttribute('name') || '',
      submitText,
      fields,
    };
  });
  // Ссылки, ведущие к разрушающим действиям по тексту («Выход», «Удалить»), не обходим.
  const destructive = /(logout|log out|sign out|выход|выйти|удалить|delete|remove|очистить|сбросить)/i;
  return { links: links.filter((l) => !destructive.test(l.text)).map((l) => l.href), forms };
}

function fillAndSubmit({ index, values, novalidate }) {
  const f = document.forms[index];
  if (!f) return 'no-form';
  if (novalidate) f.noValidate = true;
  for (const [name, val] of Object.entries(values)) {
    const el = f.elements.namedItem(name);
    if (!el) continue;
    const list = el instanceof RadioNodeList ? [...el] : [el];
    const first = list[0];
    const type = (first.type || '').toLowerCase();
    if (type === 'radio') {
      const pick = list.find((r) => r.value === val) || list[0];
      pick.checked = true;
    } else if (type === 'checkbox') {
      for (const c of list) c.checked = !!val;
    } else if (first.tagName === 'SELECT') {
      const opts = [...first.options].map((o) => o.value);
      if (opts.includes(val)) first.value = val;
      else if (novalidate) {
        const o = document.createElement('option'); // сервер должен отвергнуть значение не из списка
        o.value = val; o.textContent = 'crawler'; first.appendChild(o); first.value = val;
      }
    } else {
      for (const e of list) {
        try { e.value = val; } catch { /* например, type=number с текстом */ }
        if (e.value !== val && novalidate && ['number', 'date', 'email', 'url', 'range', 'time', 'month', 'week', 'datetime-local', 'color', 'tel'].includes(type)) {
          try { e.type = 'text'; e.value = val; } catch { /* оставить как есть */ }
        }
      }
    }
    for (const e of list) {
      e.dispatchEvent(new Event('input', { bubbles: true }));
      e.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }
  const btn = f.querySelector('button[type=submit], input[type=submit], button:not([type])');
  try {
    if (f.requestSubmit) btn ? f.requestSubmit(btn) : f.requestSubmit();
    else f.submit();
  } catch {
    f.submit();
  }
  return 'submitted';
}

function mobileMetrics() {
  const small = [];
  const zoomInputs = [];
  for (const el of document.querySelectorAll('a, button, input, select, textarea, [role=button]')) {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    if (r.width === 0 || r.height === 0 || st.visibility === 'hidden' || st.display === 'none') continue;
    if (el.closest('p, li, td') && el.tagName === 'A') continue; // ссылки внутри текста — исключение по WCAG
    if (['checkbox', 'radio', 'hidden'].includes(el.type)) continue;
    if (r.width < 24 || r.height < 24) small.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}(${Math.round(r.width)}×${Math.round(r.height)})`);
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName) && parseFloat(st.fontSize) < 16) {
      zoomInputs.push(`${el.tagName.toLowerCase()}[name=${el.name || ''}] ${st.fontSize}`);
    }
  }
  return {
    viewport: !!document.querySelector('meta[name=viewport]'),
    // clientWidth — ширина области вёрстки; innerWidth на мобильном «растёт» при автоуменьшении масштаба.
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: document.documentElement.clientWidth,
    small,
    zoomInputs,
    text: document.body ? document.body.innerText : '',
  };
}

// ------------------------------------------------------------------ генерация значений
const TEXTUAL = new Set(['text', 'search', 'textarea', 'email', 'url', 'tel', 'password']);
function textual(x) { return TEXTUAL.has(x.type) || x.tag === 'textarea'; }
function numeric(x) { return x.type === 'number' || x.type === 'range'; }
function formatted(x) { return ['email', 'url', 'date', 'datetime-local', 'time', 'month', 'week', 'tel', 'number', 'color'].includes(x.type); }
function choice(x) { return ['checkbox', 'radio', 'select-one', 'select-multiple'].includes(x.type) || x.tag === 'select'; }

export function validValue(x) {
  switch (x.type) {
    case 'email': return 'crawler@example.com';
    case 'url': return 'https://example.com/';
    case 'tel': return '+70000000000';
    case 'number':
    case 'range': {
      let v = x.min !== '' ? Number(x.min) : 1;
      if (x.max !== '' && v > Number(x.max)) v = Number(x.max);
      return String(Number.isFinite(v) ? v : 1);
    }
    case 'date': return '2026-01-15';
    case 'datetime-local': return '2026-01-15T10:00';
    case 'time': return '10:00';
    case 'month': return '2026-01';
    case 'week': return '2026-W03';
    case 'color': return '#336699';
    case 'password': return 'Crawler#Passw0rd2026';
    case 'checkbox': return 'on';
    case 'radio': return '';
    default:
      if (x.options) return x.options.find((o) => o !== '') ?? x.options[0] ?? '';
      {
        let v = 'Тест crawler';
        if (x.minLength && v.length < x.minLength) v = v.padEnd(x.minLength, 'x');
        if (x.maxLength && v.length > x.maxLength) v = v.slice(0, x.maxLength);
        return v;
      }
  }
}

// ------------------------------------------------------------------ CLI
function camel(s) { return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase()); }

export function parseCli(argv) {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: false,
    options: {
      url: { type: 'string' }, config: { type: 'string' }, out: { type: 'string' }, lang: { type: 'string' },
      'max-pages': { type: 'string' }, 'max-depth': { type: 'string' }, 'max-forms': { type: 'string' },
      forms: { type: 'string' }, 'allow-destructive': { type: 'boolean' },
      include: { type: 'string' }, exclude: { type: 'string' }, public: { type: 'string' },
      'version-regex': { type: 'string' }, 'no-mobile': { type: 'boolean' }, 'no-security': { type: 'boolean' },
      'no-auth-check': { type: 'boolean' }, bruteforce: { type: 'string' }, 'check-external': { type: 'boolean' },
      insecure: { type: 'boolean' }, 'fail-on': { type: 'string' }, delay: { type: 'string' }, timeout: { type: 'string' },
      'login-url': { type: 'string' }, 'storage-state': { type: 'string' }, debug: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
    },
  });
  if (values.help) return { help: true };
  if (values.version) return { version: true };
  let cfg = {};
  if (values.config) cfg = JSON.parse(fs.readFileSync(values.config, 'utf8'));
  const o = { ...cfg };
  for (const [k, v] of Object.entries(values)) {
    if (['config', 'help', 'version', 'login-url'].includes(k) || k.startsWith('no-')) continue;
    o[camel(k)] = v;
  }
  for (const k of ['maxPages', 'maxDepth', 'maxForms', 'bruteforce', 'delay', 'timeout']) if (typeof o[k] === 'string') o[k] = Number(o[k]);
  if (values['no-mobile']) o.mobile = false;
  if (values['no-security']) o.security = false;
  if (values['no-auth-check']) o.authCheck = false;
  if (values['login-url']) o.login = { ...(o.login || {}), url: values['login-url'] };
  return validateOptions(o);
}

export function validateOptions(o) {
  const errs = [];
  if (!o.url) errs.push('--url обязателен');
  else {
    try {
      const u = new URL(o.url);
      if (!/^https?:$/.test(u.protocol)) errs.push('--url: только http/https');
    } catch { errs.push(`--url: некорректный адрес ${o.url}`); }
  }
  if (o.forms && !['none', 'safe', 'full'].includes(o.forms)) errs.push('--forms: none | safe | full');
  if (o.lang && !['ru', 'en'].includes(o.lang)) errs.push('--lang: ru | en');
  if (o.failOn && !['critical', 'high', 'medium', 'low', 'info', 'never'].includes(o.failOn)) errs.push('--fail-on: critical|high|medium|low|info|never');
  for (const k of ['maxPages', 'maxDepth', 'maxForms', 'bruteforce', 'delay', 'timeout']) {
    if (o[k] !== undefined && (!Number.isInteger(o[k]) || o[k] < 0)) errs.push(`${k}: целое число ≥ 0`);
  }
  if (o.maxPages === 0) errs.push('maxPages: минимум 1');
  for (const k of ['include', 'exclude', 'public', 'versionRegex']) {
    if (o[k]) { try { new RegExp(o[k]); } catch (e) { errs.push(`${k}: неверное регулярное выражение (${e.message})`); } }
  }
  // Противоречивые сочетания опций
  if (o.bruteforce > 0 && !o.login) errs.push('--bruteforce требует настроенного входа (--login-url / config.login)');
  if (o.security === false && o.forms === 'full') o.forms = 'safe'; // атакующие данные — часть проверки безопасности
  if (o.login && o.storageState) errs.push('укажите либо login, либо storage-state, а не оба');
  if (o.authCheck === false && o.public) errs.push('--public имеет смысл только с проверкой доступа без входа');
  if (errs.length) {
    const e = new Error(errs.join('\n'));
    e.code = 'BAD_OPTIONS';
    throw e;
  }
  return o;
}

export async function main(argv = process.argv.slice(2)) {
  let o;
  try {
    o = parseCli(argv);
  } catch (e) {
    console.error(e.message);
    console.error('Справка: node crawl.mjs --help');
    return 2;
  }
  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log(VERSION); return 0; }
  let rep;
  try {
    rep = await new Crawler(o).run();
  } catch (e) {
    console.error(`Ошибка: ${e.message}`);
    return 2;
  }
  const c = rep.counts;
  console.log(`Страниц: ${rep.stats.pages}, форм: ${rep.stats.forms} (проверено ${rep.stats.formsTested}, отправок ${rep.stats.formSubmits})`);
  console.log(`Находки: critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info}`);
  for (const x of rep.findings.filter((f) => sevRank(f.severity) <= sevRank('medium')).slice(0, 50)) {
    console.log(`  [${x.severity}] ${x.title} — ${x.url}${x.detail ? ` (${x.detail.slice(0, 120)})` : ''}`);
  }
  console.log(`Отчёт: ${path.join(o.out || DEFAULTS.out, 'report.html')}`);
  if (o.failOn === 'never') return 0;
  return rep.passed ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().then((code) => process.exit(code));
}
