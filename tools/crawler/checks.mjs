// Каталог проверок краулера: код → уровень и название RU/EN.
// Уровни: critical > high > medium > low > info.

export const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];

export const CHECKS = {
  // HTTP и работоспособность
  'http.5xx': ['high', 'Ошибка сервера (5xx) при открытии страницы', 'Server error (5xx) on page load'],
  'http.4xx': ['medium', 'Битая ссылка (4xx)', 'Broken link (4xx)'],
  'http.resource_error': ['medium', 'Ресурс страницы не загрузился (CSS/JS/картинка/API)', 'Page resource failed (CSS/JS/image/API)'],
  'http.request_failed': ['medium', 'Запрос не выполнен (сеть/таймаут)', 'Request failed (network/timeout)'],
  'js.error': ['medium', 'Необработанная ошибка JavaScript', 'Uncaught JavaScript error'],
  'js.console_error': ['low', 'Ошибка в консоли браузера', 'Browser console error'],

  // Формы
  'form.server_error': ['high', 'Форма вызвала ошибку сервера (5xx)', 'Form caused server error (5xx)'],
  'form.skipped_destructive': ['info', 'Форма пропущена как разрушающая (удаление/выход)', 'Form skipped as destructive (delete/logout)'],
  'form.no_label': ['low', 'Поле формы без подписи (label/aria-label/title)', 'Form field without label'],
  'form.password_autocomplete': ['low', 'Поле пароля без autocomplete=current-password/new-password', 'Password field without proper autocomplete'],

  // Безопасность
  'sec.xss_reflected': ['critical', 'Отражённый XSS: ввод выводится без экранирования', 'Reflected XSS: input rendered unescaped'],
  'sec.xss_stored': ['critical', 'Хранимый XSS: сохранённый ввод выводится без экранирования', 'Stored XSS: saved input rendered unescaped'],
  'sec.sql_error': ['high', 'Текст ошибки SQL в ответе (возможна SQL-инъекция)', 'SQL error in response (possible SQL injection)'],
  'sec.ssti': ['critical', 'Инъекция в шаблон (SSTI): выражение было вычислено', 'Server-side template injection evaluated'],
  'sec.path_traversal': ['critical', 'Обход пути: прочитан системный файл', 'Path traversal: system file read'],
  'sec.open_redirect': ['high', 'Открытый редирект на внешний сайт', 'Open redirect to external site'],
  'sec.csrf_missing': ['medium', 'POST-форма без CSRF-токена', 'POST form without CSRF token'],
  'sec.password_get': ['high', 'Пароль отправляется методом GET (попадёт в URL и логи)', 'Password sent via GET (ends up in URL/logs)'],
  'sec.insecure_form': ['high', 'Форма на HTTPS отправляется по HTTP', 'HTTPS form submits over HTTP'],
  'sec.mixed_content': ['medium', 'Смешанное содержимое: HTTP-ресурс на HTTPS-странице', 'Mixed content: HTTP resource on HTTPS page'],
  'sec.sensitive_file': ['critical', 'Доступен служебный файл', 'Sensitive file exposed'],
  'sec.no_auth': ['high', 'Страница доступна без входа', 'Page accessible without login'],
  'sec.no_bruteforce_protection': ['medium', 'Нет защиты от перебора паролей', 'No brute-force protection on login'],
  'sec.cookie_httponly': ['high', 'Сессионная cookie без HttpOnly', 'Session cookie without HttpOnly'],
  'sec.cookie_secure': ['medium', 'Cookie без Secure на HTTPS', 'Cookie without Secure on HTTPS'],
  'sec.cookie_samesite': ['low', 'Cookie с SameSite=None', 'Cookie with SameSite=None'],

  // Заголовки
  'hdr.csp': ['medium', 'Нет заголовка Content-Security-Policy', 'Missing Content-Security-Policy'],
  'hdr.clickjacking': ['medium', 'Нет защиты от встраивания во фрейм (X-Frame-Options / frame-ancestors)', 'No clickjacking protection'],
  'hdr.nosniff': ['low', 'Нет X-Content-Type-Options: nosniff', 'Missing X-Content-Type-Options: nosniff'],
  'hdr.referrer': ['low', 'Нет Referrer-Policy', 'Missing Referrer-Policy'],
  'hdr.hsts': ['medium', 'Нет Strict-Transport-Security на HTTPS', 'Missing Strict-Transport-Security on HTTPS'],
  'hdr.version_disclosure': ['low', 'Заголовок раскрывает версию ПО сервера', 'Header discloses server software version'],

  // Утечки
  'leak.stack_trace': ['medium', 'Трассировка ошибки видна пользователю', 'Stack trace shown to user'],
  'leak.dir_listing': ['medium', 'Открыт листинг каталога', 'Directory listing enabled'],

  // Интерфейс по концепции
  'ux.version_missing': ['medium', 'Номер версии не виден на странице', 'Version number not visible'],

  // Мобильная версия
  'mobile.overflow': ['medium', 'Горизонтальная прокрутка на мобильном', 'Horizontal scroll on mobile'],
  'mobile.no_viewport': ['medium', 'Нет meta viewport', 'Missing meta viewport'],
  'mobile.small_targets': ['low', 'Слишком мелкие элементы для нажатия (< 24px)', 'Tap targets too small (< 24px)'],
  'mobile.input_zoom': ['low', 'Шрифт поля ввода < 16px (iOS увеличит страницу)', 'Input font < 16px (iOS will zoom)'],
};

export function checkInfo(id, lang = 'ru') {
  const c = CHECKS[id];
  if (!c) return { severity: 'info', title: id };
  return { severity: c[0], title: lang === 'en' ? c[2] : c[1] };
}

export function sevRank(s) {
  const i = SEVERITY.indexOf(s);
  return i < 0 ? SEVERITY.length : i;
}

// Шаблоны распознавания
export const RX = {
  sqlError: /(SQL syntax|syntax error at or near|unterminated quoted string|SQLSTATE\[|sqlite3?\.OperationalError|ORA-\d{5}|PG::SyntaxError|psycopg2?\.errors|mysql_fetch|You have an error in your SQL|Microsoft OLE DB|ODBC SQL Server Driver|SQLiteException|near ".{0,20}": syntax error)/i,
  stackTrace: /(Traceback \(most recent call last\)|at [\w$.]+\([\w./-]+\.(java|kt|js|ts|mjs):\d+|Exception in thread|System\.\w+Exception:|Fatal error:.* on line \d+|Stack trace:\s*#0|django\.core\.exceptions|Whoops! There was an error)/,
  dirListing: /<title>\s*Index of \/|<h1>\s*Index of \//i,
  passwd: /root:x:0:0:/,
  ssti: /9801547/,
  sessionCookie: /sess|sid|token|auth|jwt|login|remember/i,
  csrfField: /csrf|xsrf|_token|authenticity|nonce|request_verification/i,
  destructive: /(logout|log-out|signout|sign-out|выход|выйти|delete|remove|destroy|drop|purge|wipe|truncate|reset|удал|очист|сброс|уничтож)/i,
  versionHeader: /\d+\.\d+/,
  redirectParam: /^(next|redirect|redirect_uri|redirect_url|url|return|returnto|return_to|returnurl|continue|to|goto|dest|destination|target|back)$/i,
  staticExt: /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|bmp|woff2?|ttf|otf|eot|pdf|zip|gz|tgz|rar|7z|mp4|webm|mp3|wav|ogg|csv|xlsx?|docx?|pptx?|txt|xml|json)$/i,
};

// Метка XSS: если она появилась в DOM как элемент — ввод не экранирован.
export const XSS_PAYLOAD = `"'><img src=x data-crawler-xss=1 onerror="window.__crawlerXss=1"><script>window.__crawlerXss=1</script>`;
export const SSTI_PAYLOAD = '{{1337*7331}}${1337*7331}<%= 1337*7331 %>#{1337*7331}';
export const SQLI_PAYLOADS = [`' OR '1'='1' -- `, `1"'\`)`];
export const TRAVERSAL_PAYLOAD = '../../../../../../../../etc/passwd';

// Служебные файлы: путь + признак настоящего содержимого (а не «мягкой» 404).
export const SENSITIVE_PATHS = [
  ['/.git/HEAD', /^ref: refs\//m],
  ['/.git/config', /\[core\]/],
  ['/.env', /^[A-Z_][A-Z0-9_]*\s*=/m],
  ['/.env.local', /^[A-Z_][A-Z0-9_]*\s*=/m],
  ['/.htpasswd', /^[^:\s]+:\$?[\w./$]+$/m],
  ['/config.php.bak', /<\?php/],
  ['/backup.sql', /(CREATE TABLE|INSERT INTO)/i],
  ['/dump.sql', /(CREATE TABLE|INSERT INTO)/i],
  ['/db.sqlite3', /^SQLite format 3/],
  ['/phpinfo.php', /phpinfo\(\)|PHP Version/],
  ['/server-status', /Apache Server Status/],
  ['/.DS_Store', /Bud1/],
  ['/WEB-INF/web.xml', /<web-app/],
  ['/actuator/env', /"propertySources"/],
  ['/debug/pprof/', /goroutine/],
];
