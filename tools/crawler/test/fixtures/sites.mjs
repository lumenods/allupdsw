// Учебные сайты для тестов краулера.
// vulnerable — специально с ошибками и уязвимостями (каждую краулер обязан найти);
// secure — сделан правильно (краулер не должен находить проблем уровня medium и выше).
// Слушают только 127.0.0.1.

import http from 'node:http';

function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(new URLSearchParams(b)));
  });
}

const escHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
}

// ------------------------------------------------------------------ vulnerable
export async function startVulnerable() {
  const state = { comments: [], hits: { logout: 0, deleteAll: 0 }, logins: 0 };
  const page = (body, { version = true, viewport = false } = {}) => `<!doctype html><html><head><meta charset="utf-8">${viewport ? '<meta name="viewport" content="width=device-width, initial-scale=1">' : ''}<title>Vuln</title></head><body>
<nav><a href="/" style="font-size:9px">Главная</a> <a href="/comments" style="font-size:9px">Комментарии</a> <a href="/logout">Выход</a>${version ? ' <span>v1.0.0</span>' : ''}</nav>
${body}</body></html>`;

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const cookie = req.headers.cookie || '';
    const authed = /session=abc/.test(cookie);
    const send = (code, html, headers = {}) => {
      res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', Server: 'Apache/2.4.1', 'X-Powered-By': 'PHP/7.1.33', ...headers });
      res.end(html);
    };

    if (p === '/.git/HEAD') return send(200, 'ref: refs/heads/main\n', { 'Content-Type': 'text/plain' });
    if (p === '/api/v1/debug/status') return send(200, '{"debug":true,"db":"ok"}', { 'Content-Type': 'application/json' });
    if (p === '/admin') return send(200, page('<h1>Админка</h1><p>Доступна всем — ошибка</p>'));
    if (p === '/login') {
      return send(200, page(`<form method="get" action="/do-login"><input name="username" style="font-size:12px">
<input type="password" name="password"><button type="submit">Войти</button></form>${u.searchParams.get('e') ? '<p>Неверный пароль</p>' : ''}`));
    }
    if (p === '/do-login') {
      state.logins++;
      if (u.searchParams.get('username') === 'admin' && u.searchParams.get('password') === 'secret') {
        res.writeHead(302, { Location: '/', 'Set-Cookie': 'session=abc; Path=/' });
        return res.end();
      }
      res.writeHead(302, { Location: '/login?e=1' });
      return res.end();
    }
    if (!authed) {
      res.writeHead(302, { Location: '/login' });
      return res.end();
    }

    switch (p) {
      case '/':
        return send(200, page(`<h1>Главная</h1><ul>
<li><a href="/search?q=hello">Поиск</a></li><li><a href="/broken">Битая</a></li><li><a href="/err">Ошибка</a></li>
<li><a href="/wide">Широкая</a></li><li><a href="/js-error">JS</a></li><li><a href="/sql">SQL</a></li>
<li><a href="/file?name=readme.txt">Файл</a></li><li><a href="/admin">Админка</a></li><li><a href="/go?next=/">Перейти</a></li>
<li><a href="/danger">Опасное</a></li><li><a href="/logout-now">Завершить сеанс</a></li></ul>`));
      case '/search': {
        const q = (u.searchParams.get('q') || '').replace('{{1337*7331}}', '9801547');
        return send(200, page(`<form><label>Запрос <input name="q"></label><button>Найти</button></form><p>Вы искали: ${q}</p>`));
      }
      case '/comments':
        if (req.method === 'POST') {
          const b = await readBody(req);
          state.comments.push({ author: b.get('author') || '', text: b.get('text') || '' });
          res.writeHead(303, { Location: '/comments' });
          return res.end();
        }
        return send(200, page(`<form method="post"><label>Автор <input name="author"></label><label>Текст <textarea name="text"></textarea></label>
<button type="submit">Отправить</button></form><div>${state.comments.map((c) => `<p><b>${c.author}</b>: ${c.text}</p>`).join('')}</div>`));
      case '/broken':
        return send(200, page('<a href="/missing">куда-то</a>'));
      case '/err':
        return send(500, page('<pre>Traceback (most recent call last):\n  File "app.py", line 1</pre>'));
      case '/wide':
        return send(200, page('<div style="width:1200px">широко</div>', { version: false, viewport: true }));
      case '/js-error':
        return send(200, page('<script>console.error("bad thing");throw new Error("boom")</script>'));
      case '/sql':
        if (req.method === 'POST') {
          const b = await readBody(req);
          if (/['"`]/.test(b.get('id') || '')) return send(500, page('You have an error in your SQL syntax near \'\'\''));
          return send(200, page('ok'));
        }
        return send(200, page('<form method="post"><label>ID <input type="number" name="id" min="1" max="100"></label><button type="submit">Найти</button></form>'));
      case '/file':
        if ((u.searchParams.get('name') || '').includes('../')) return send(200, 'root:x:0:0:root:/root:/bin/bash', { 'Content-Type': 'text/plain' });
        return send(200, page('readme'));
      case '/go':
        res.writeHead(302, { Location: u.searchParams.get('next') || '/' });
        return res.end();
      case '/danger':
        return send(200, page('<form method="post" action="/delete-all"><button type="submit">Удалить всё</button></form>'));
      case '/delete-all':
        state.hits.deleteAll++;
        return send(200, page('удалено'));
      case '/logout':
      case '/logout-now':
        state.hits.logout++;
        res.writeHead(302, { Location: '/login', 'Set-Cookie': 'session=; Path=/; Max-Age=0' });
        return res.end();
      default:
        return send(404, page('Не найдено'));
    }
  });
  const url = await listen(server);
  return { url, state, close: () => new Promise((r) => server.close(r)) };
}

// ------------------------------------------------------------------ secure
export async function startSecure() {
  const state = { items: [], fails: 0, sessions: new Set(), hits: { logout: 0 } };
  const SEC = {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    Server: 'web',
  };
  const css = 'body{font:16px sans-serif;margin:0;padding:16px}nav a,button{display:inline-block;min-height:44px;min-width:44px;padding:10px}input,textarea{font-size:16px;min-height:44px;width:100%;max-width:100%;box-sizing:border-box}';
  const page = (body) => `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure</title><link rel="stylesheet" href="/app.css"></head><body>
<nav><a href="/">Главная</a> <a href="/items">Записи</a> <a href="/search?q=test">Поиск</a> <a href="/logout">Выход</a> <span>v2.3.4</span></nav>
<main>${body}</main></body></html>`;

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const sid = (/(?:^|;\s*)sid=([a-z0-9]+)/.exec(req.headers.cookie || '') || [])[1];
    const authed = sid && state.sessions.has(sid);
    const send = (code, html, headers = {}) => {
      res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', ...SEC, ...headers });
      res.end(html);
    };
    const csrf = sid ? `t${sid}` : 'anon';

    if (p === '/app.css') return send(200, css, { 'Content-Type': 'text/css' });
    if (p === '/api/v1/debug/status') return send(401, '{"error":"auth"}', { 'Content-Type': 'application/json' });
    if (p === '/login') {
      if (req.method === 'POST') {
        if (state.fails >= 5) return send(429, page('<p>Слишком много попыток, повторите позже</p>'));
        const b = await readBody(req);
        if (b.get('username') === 'admin' && b.get('password') === 'secret') {
          const s = Math.random().toString(36).slice(2);
          state.sessions.add(s);
          res.writeHead(303, { Location: '/', 'Set-Cookie': `sid=${s}; Path=/; HttpOnly; SameSite=Lax`, ...SEC });
          return res.end();
        }
        state.fails++;
        return send(401, page('<p>Неверный логин или пароль</p>' + loginForm()));
      }
      return send(200, page(loginForm()));
    }
    if (!authed) {
      res.writeHead(302, { Location: '/login', ...SEC });
      return res.end();
    }
    switch (p) {
      case '/':
        return send(200, page('<h1>Главная</h1><p>Всё хорошо.</p>'));
      case '/items':
        if (req.method === 'POST') {
          const b = await readBody(req);
          if (b.get('csrf_token') !== csrf) return send(403, page('<p>Неверный токен</p>'));
          const title = (b.get('title') || '').trim();
          const qty = Number(b.get('qty'));
          if (!title || title.length > 100 || !Number.isInteger(qty) || qty < 1 || qty > 1000) {
            return send(422, page('<p role="alert">Проверьте поля: название 1–100 символов, количество 1–1000</p>'));
          }
          state.items.push({ title, qty });
          res.writeHead(303, { Location: '/items', ...SEC });
          return res.end();
        }
        return send(200, page(`<form method="post"><input type="hidden" name="csrf_token" value="${csrf}">
<label for="t">Название</label><input id="t" name="title" required maxlength="100">
<label for="q">Количество</label><input id="q" name="qty" type="number" min="1" max="1000" required>
<button type="submit">Добавить</button></form><ul>${state.items.map((i) => `<li>${escHtml(i.title)} × ${i.qty}</li>`).join('')}</ul>`));
      case '/search': {
        const q = u.searchParams.get('q') || '';
        return send(200, page(`<form><label for="s">Запрос</label><input id="s" name="q" value="${escHtml(q)}"><button>Найти</button></form><p>Вы искали: ${escHtml(q)}</p>`));
      }
      case '/logout':
        state.hits.logout++;
        state.sessions.delete(sid);
        res.writeHead(302, { Location: '/login', ...SEC });
        return res.end();
      default:
        return send(404, page('<p>Не найдено</p>'));
    }
  });
  function loginForm() {
    return `<form method="post" action="/login"><input type="hidden" name="csrf_token" value="login"><label for="u">Логин</label><input id="u" name="username" autocomplete="username">
<label for="p">Пароль</label><input id="p" type="password" name="password" autocomplete="current-password"><button type="submit">Войти</button></form>`;
  }
  const url = await listen(server);
  return { url, state, close: () => new Promise((r) => server.close(r)) };
}
