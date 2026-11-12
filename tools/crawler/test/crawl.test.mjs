// Тесты краулера: node --test --test-concurrency=1 test/
// Проверяют, что краулер находит КАЖДУЮ заложенную в «уязвимый» сайт проблему,
// не находит проблем на «безопасном» сайте и не нажимает разрушающие действия.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startVulnerable, startSecure } from './fixtures/sites.mjs';
import { Crawler, validateOptions, parseCli, validValue, normalizeUrl, withTimeout, main } from '../crawl.mjs';
import { CHECKS, SEVERITY, checkInfo } from '../checks.mjs';
import { renderHtml } from '../report.mjs';

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), `crawl-${name}-`));
const LOGIN = { url: '/login', user: 'admin', pass: 'secret' };

describe('уязвимый сайт: краулер находит все проблемы', { timeout: 300000 }, () => {
  let site;
  let rep;
  let out;
  before(async () => {
    site = await startVulnerable();
    out = tmp('vuln');
    rep = await new Crawler({ url: site.url, out, login: LOGIN, bruteforce: 8, timeout: 5000 }).run();
  });
  after(() => site.close());

  const has = (id, urlPart = '') => rep.findings.some((f) => f.id === id && f.url.includes(urlPart));

  const EXPECTED = [
    ['http.5xx', '/err'], ['http.4xx', '/missing'], ['js.error', '/js-error'], ['js.console_error', '/js-error'],
    ['leak.stack_trace', '/err'],
    ['form.server_error', '/sql'], ['form.no_label', '/login'], ['form.password_autocomplete', '/login'],
    ['form.skipped_destructive', '/danger'],
    ['sec.xss_reflected', '/search'], ['sec.xss_stored', '/comments'], ['sec.sql_error', '/sql'], ['sec.ssti', '/search'],
    ['sec.path_traversal', '/file'], ['sec.open_redirect', '/go'], ['sec.csrf_missing', '/comments'],
    ['sec.password_get', '/login'], ['sec.sensitive_file', '/.git/HEAD'], ['sec.no_auth', '/admin'],
    ['sec.no_auth', '/api/v1/debug/status'], ['sec.no_bruteforce_protection', '/login'], ['sec.cookie_httponly', ''],
    ['hdr.csp', ''], ['hdr.clickjacking', ''], ['hdr.nosniff', ''], ['hdr.referrer', ''], ['hdr.version_disclosure', ''],
    ['ux.version_missing', '/wide'], ['mobile.overflow', '/wide'], ['mobile.no_viewport', '/'],
    ['mobile.small_targets', '/'], ['mobile.input_zoom', '/comments'],
  ];
  for (const [id, part] of EXPECTED) {
    test(`находит ${id} ${part}`, () => assert.ok(has(id, part), `не найдено ${id} на ${part}\n${rep.findings.map((f) => `${f.id} ${f.url}`).join('\n')}`));
  }

  test('не нажимает выход и удаление', () => {
    assert.equal(site.state.hits.logout, 0, 'краулер перешёл по ссылке выхода');
    assert.equal(site.state.hits.deleteAll, 0, 'краулер отправил форму удаления');
  });

  test('отражённый XSS из URL не выдаётся за хранимый', () => {
    assert.ok(!rep.findings.some((f) => f.id === 'sec.xss_stored' && /crawler-xss/.test(decodeURIComponent(f.url))));
  });

  test('итог «не пройдено», счётчики совпадают', () => {
    assert.equal(rep.passed, false);
    const total = Object.values(rep.counts).reduce((a, b) => a + b, 0);
    assert.equal(total, rep.findings.length);
  });

  test('находки отсортированы по важности', () => {
    const ranks = rep.findings.map((f) => SEVERITY.indexOf(f.severity));
    assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  });

  test('отчёты записаны, атакующие строки экранированы, пароль не попал в отчёт', () => {
    const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
    const json = fs.readFileSync(path.join(out, 'report.json'), 'utf8');
    assert.ok(!html.includes('<img src=x data-crawler-xss'), 'в HTML-отчёте неэкранированная метка XSS');
    assert.ok(!/<script>window\.__crawlerXss/.test(html));
    assert.ok(!json.includes('"secret"'), 'пароль попал в report.json');
    assert.ok(JSON.parse(json).findings.length > 0);
  });

  test('скриншоты находок существуют', () => {
    const withShot = rep.findings.filter((f) => f.screenshot);
    assert.ok(withShot.length > 0);
    for (const f of withShot) assert.ok(fs.existsSync(path.join(out, f.screenshot)), f.screenshot);
  });
});

describe('безопасный сайт: ложных срабатываний нет', { timeout: 300000 }, () => {
  let site;
  let rep;
  before(async () => {
    site = await startSecure();
    rep = await new Crawler({ url: site.url, out: tmp('sec'), login: { ...LOGIN }, bruteforce: 8, timeout: 5000 }).run();
  });
  after(() => site.close());

  test('нет находок', () => {
    assert.deepEqual(rep.findings.map((f) => `${f.severity} ${f.id} ${f.url} ${f.detail}`), []);
    assert.equal(rep.passed, true);
  });
  test('обойдены все страницы и формы', () => {
    const paths = rep.pages.map((p) => new URL(p.url).pathname).sort();
    assert.deepEqual(paths, ['/', '/items', '/search']);
    assert.equal(rep.stats.formsTested, 2);
    assert.ok(rep.stats.formSubmits >= 20);
  });
  test('не нажимает выход', () => assert.equal(site.state.hits.logout, 0));
  test('данные из валидной отправки сохранены, атакующие — отвергнуты', () => {
    assert.ok(site.state.items.length >= 1);
    assert.ok(site.state.items.every((i) => i.title.length <= 100));
  });
});

describe('вход', { timeout: 60000 }, () => {
  test('неверный пароль — понятная ошибка, а не пустой отчёт', async () => {
    const site = await startVulnerable();
    try {
      await assert.rejects(
        new Crawler({ url: site.url, out: tmp('badlogin'), login: { url: '/login', user: 'admin', pass: 'wrong' }, timeout: 5000 }).run(),
        /Вход не выполнен/,
      );
    } finally {
      await site.close();
    }
  });
  test('нет CRAWL_USER/CRAWL_PASS — ошибка', async () => {
    const site = await startVulnerable();
    const saved = [process.env.CRAWL_USER, process.env.CRAWL_PASS];
    delete process.env.CRAWL_USER;
    delete process.env.CRAWL_PASS;
    try {
      await assert.rejects(new Crawler({ url: site.url, out: tmp('nologin'), login: { url: '/login' } }).run(), /CRAWL_USER/);
    } finally {
      [process.env.CRAWL_USER, process.env.CRAWL_PASS] = saved;
      if (saved[0] === undefined) delete process.env.CRAWL_USER;
      if (saved[1] === undefined) delete process.env.CRAWL_PASS;
      await site.close();
    }
  });
});

describe('режимы и ограничения', { timeout: 120000 }, () => {
  test('forms=none не отправляет формы; без security нет атакующих проверок', async () => {
    const site = await startVulnerable();
    try {
      const rep = await new Crawler({ url: site.url, out: tmp('none'), login: LOGIN, forms: 'none', security: false, mobile: false, timeout: 5000 }).run();
      assert.equal(rep.stats.formSubmits, 0);
      assert.equal(site.state.comments.length, 0);
      assert.ok(!rep.findings.some((f) => /^sec\.(xss|ssti|sql_error|path_traversal|open_redirect|sensitive_file|no_auth)/.test(f.id)));
      assert.ok(!rep.findings.some((f) => f.id.startsWith('mobile.')));
    } finally {
      await site.close();
    }
  });
  test('forms=safe: без атакующих строк', async () => {
    const site = await startVulnerable();
    try {
      const rep = await new Crawler({ url: site.url, out: tmp('safe'), login: LOGIN, forms: 'safe', mobile: false, timeout: 5000 }).run();
      assert.ok(rep.stats.formSubmits > 0);
      assert.ok(!site.state.comments.some((c) => /crawler-xss|1337/.test(c.text + c.author)));
      assert.ok(!rep.findings.some((f) => f.id === 'sec.xss_reflected' || f.id === 'sec.ssti'));
    } finally {
      await site.close();
    }
  });
  test('maxPages и exclude соблюдаются', async () => {
    const site = await startVulnerable();
    try {
      const rep = await new Crawler({ url: site.url, out: tmp('lim'), login: LOGIN, maxPages: 3, exclude: '/comments', forms: 'none', mobile: false, security: false, timeout: 5000 }).run();
      assert.ok(rep.stats.pages <= 3);
      assert.ok(!rep.pages.some((p) => p.url.includes('/comments')));
    } finally {
      await site.close();
    }
  });
  test('public исключает намеренно открытые страницы из проверки доступа', async () => {
    const site = await startVulnerable();
    try {
      const rep = await new Crawler({ url: site.url, out: tmp('pub'), login: LOGIN, public: '/admin$', forms: 'none', mobile: false, timeout: 5000 }).run();
      assert.ok(!rep.findings.some((f) => f.id === 'sec.no_auth' && f.url.endsWith('/admin')));
    } finally {
      await site.close();
    }
  });
  test('недоступный стенд — отчёт с ошибкой запроса, без падения', async () => {
    const rep = await new Crawler({ url: 'http://127.0.0.1:9/', out: tmp('down'), mobile: false, security: false, timeout: 3000 }).run();
    assert.ok(rep.findings.some((f) => f.id === 'http.request_failed'));
  });
});

describe('настройки: проверка значений и противоречий', () => {
  const ok = { url: 'http://localhost:1' };
  const bad = (o, re) => assert.throws(() => validateOptions({ ...ok, ...o }), re);
  test('обязателен корректный url', () => {
    assert.throws(() => validateOptions({}), /--url обязателен/);
    bad({ url: 'ftp://x' }, /http\/https/);
    bad({ url: 'не адрес' }, /некорректный адрес/);
  });
  test('перечисления', () => {
    bad({ forms: 'all' }, /--forms/);
    bad({ lang: 'de' }, /--lang/);
    bad({ failOn: 'error' }, /--fail-on/);
  });
  test('числа', () => {
    bad({ maxPages: -1 }, /maxPages/);
    bad({ maxPages: 0 }, /минимум 1/);
    bad({ delay: 1.5 }, /delay/);
    bad({ timeout: 'x' }, /timeout/);
  });
  test('регулярные выражения', () => bad({ include: '(' }, /include: неверное/));
  test('противоречивые сочетания', () => {
    bad({ bruteforce: 5 }, /требует настроенного входа/);
    bad({ login: { url: '/l' }, storageState: 'x.json' }, /либо login, либо storage-state/);
    bad({ authCheck: false, public: '/x' }, /--public имеет смысл/);
    assert.equal(validateOptions({ ...ok, security: false, forms: 'full' }).forms, 'safe');
  });
  test('CLI: ключи, config и приоритет командной строки', () => {
    const dir = tmp('cfg');
    const cfg = path.join(dir, 'c.json');
    fs.writeFileSync(cfg, JSON.stringify({ url: 'http://a.test', maxPages: 5, lang: 'en' }));
    const o = parseCli(['--config', cfg, '--max-pages', '7', '--no-mobile', '--login-url', '/in']);
    assert.equal(o.url, 'http://a.test');
    assert.equal(o.maxPages, 7);
    assert.equal(o.lang, 'en');
    assert.equal(o.mobile, false);
    assert.deepEqual(o.login, { url: '/in' });
  });
  test('пример crawl.example.json проходит проверку настроек', () => {
    const o = parseCli(['--config', new URL('../crawl.example.json', import.meta.url).pathname]);
    assert.equal(o.forms, 'full');
    assert.equal(o.login.url, '/login');
  });
  test('CLI: коды выхода', async () => {
    const log = console.log;
    const err = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      assert.equal(await main(['--help']), 0);
      assert.equal(await main(['--version']), 0);
      assert.equal(await main([]), 2);
      assert.equal(await main(['--url', 'http://x', '--forms', 'bad']), 2);
    } finally {
      console.log = log;
      console.error = err;
    }
  });
});

describe('вспомогательные функции', () => {
  test('validValue по типам полей', () => {
    assert.equal(validValue({ type: 'email' }), 'crawler@example.com');
    assert.equal(validValue({ type: 'number', min: '5', max: '' }), '5');
    assert.equal(validValue({ type: 'number', min: '', max: '0' }), '0');
    assert.equal(validValue({ type: 'text', minLength: 20, maxLength: 0 }).length, 20);
    assert.equal(validValue({ type: 'text', minLength: 0, maxLength: 3 }).length, 3);
    assert.equal(validValue({ type: 'select-one', tag: 'select', options: ['', 'a', 'b'] }), 'a');
    assert.match(validValue({ type: 'date' }), /^\d{4}-\d{2}-\d{2}$/);
  });
  test('normalizeUrl', () => {
    assert.equal(normalizeUrl('/a#x', 'http://h:80/b'), 'http://h/a');
    assert.equal(normalizeUrl('https://h:443/a?b=1'), 'https://h/a?b=1');
    assert.equal(normalizeUrl('::::'), null);
  });
  test('withTimeout', async () => {
    assert.equal(await withTimeout(new Promise(() => {}), 20, 'fb'), 'fb');
    assert.equal(await withTimeout(Promise.reject(new Error('x')), 1000, 'fb'), 'fb');
    assert.equal(await withTimeout(Promise.resolve(1), 1000, 'fb'), 1);
  });
  test('каталог проверок: уровни корректны, есть RU и EN', () => {
    for (const [id, [sev, ru, en]] of Object.entries(CHECKS)) {
      assert.ok(SEVERITY.includes(sev), id);
      assert.ok(ru && en, id);
    }
    assert.equal(checkInfo('hdr.csp', 'en').title, CHECKS['hdr.csp'][2]);
  });
  test('HTML-отчёт экранирует всё', () => {
    const evil = '<script>alert(1)</script>';
    const html = renderHtml({
      lang: 'ru', target: evil, started: '', finished: '', version: '1', failOn: 'high', passed: false,
      stats: { pages: 1, forms: 0, formSubmits: 0 }, counts: { critical: 1 },
      pages: [{ url: evil, status: 200, title: evil }],
      findings: [{ id: 'sec.xss_reflected', severity: 'critical', title: evil, url: evil, detail: evil, from: evil }],
    });
    assert.ok(!html.includes(evil));
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  });
});
