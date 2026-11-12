// HTML-отчёт краулера: один самодостаточный файл, светлая/тёмная тема, мобильная вёрстка.
// Всё содержимое экранируется: в находках бывают атакующие строки.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const T = {
  ru: {
    title: 'Отчёт краулера', target: 'Стенд', when: 'Время', pages: 'Страниц', forms: 'Форм', submits: 'Отправок форм',
    result: 'Итог', passed: 'пройдено', failed: 'есть проблемы', failOn: 'порог', all: 'Все', findings: 'Находки',
    none: 'Находок нет', page: 'Страница', detail: 'Подробности', screenshot: 'скриншот', from: 'ссылка со страницы',
    visited: 'Обойдённые страницы', status: 'Код', filter: 'Фильтр', search: 'Поиск по находкам',
  },
  en: {
    title: 'Crawler report', target: 'Target', when: 'Time', pages: 'Pages', forms: 'Forms', submits: 'Form submits',
    result: 'Result', passed: 'passed', failed: 'issues found', failOn: 'threshold', all: 'All', findings: 'Findings',
    none: 'No findings', page: 'Page', detail: 'Details', screenshot: 'screenshot', from: 'linked from',
    visited: 'Visited pages', status: 'Status', filter: 'Filter', search: 'Search findings',
  },
};

export function renderHtml(rep) {
  const t = T[rep.lang === 'en' ? 'en' : 'ru'];
  const sevs = ['critical', 'high', 'medium', 'low', 'info'];
  const rows = rep.findings.map((f) => `
      <li class="f" data-sev="${esc(f.severity)}">
        <div class="fh"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span><b>${esc(f.title)}</b><code>${esc(f.id)}</code></div>
        <div class="fu"><a href="${esc(f.url)}" rel="noreferrer noopener" target="_blank">${esc(f.url)}</a></div>
        ${f.detail ? `<pre>${esc(f.detail)}</pre>` : ''}
        ${f.from ? `<div class="m">${t.from}: ${esc(f.from)}</div>` : ''}
        ${f.screenshot ? `<div class="m"><a href="${esc(f.screenshot)}" target="_blank">${t.screenshot}</a></div>` : ''}
      </li>`).join('');
  const pages = rep.pages.map((p) => `<tr><td>${esc(p.status)}</td><td><a href="${esc(p.url)}" target="_blank" rel="noreferrer noopener">${esc(p.url)}</a></td><td>${esc(p.title)}</td></tr>`).join('');
  const chips = sevs.map((s) => `<button type="button" class="chip" data-f="${s}"><span class="sev ${s}">${s}</span> ${rep.counts[s] || 0}</button>`).join('');
  return `<!doctype html>
<html lang="${rep.lang === 'en' ? 'en' : 'ru'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.title}</title>
<style>
:root{--bg:#fff;--fg:#1d2330;--mut:#5c6578;--line:#dfe3ea;--card:#f6f7f9;--critical:#b3261e;--high:#d0541b;--medium:#a77700;--low:#2f6db5;--info:#5c6578;--ok:#1d7a3e}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b313b;--card:#1b1f26;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b23a;--low:#6ea8ff;--info:#9aa3b2;--ok:#4cc27a}}
:root[data-theme=dark]{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b313b;--card:#1b1f26;--critical:#ff6b61;--high:#ff8a4c;--medium:#e0b23a;--low:#6ea8ff;--info:#9aa3b2;--ok:#4cc27a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:22px;margin:8px 0}h2{font-size:18px;margin:24px 0 8px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}.meta div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.meta span{display:block;color:var(--mut);font-size:12px}.ok{color:var(--ok);font-weight:600}.bad{color:var(--critical);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0}.chip{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:16px;padding:6px 10px;min-height:36px;cursor:pointer;font:inherit}
.chip[aria-pressed=true]{outline:2px solid var(--low)}input[type=search]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:16px}
ul{list-style:none;padding:0;margin:0}.f{border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0;background:var(--card)}
.fh{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.fh code{color:var(--mut);font-size:12px}.fu{word-break:break-all;font-size:13px;margin-top:4px}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin:6px 0 0;font-size:12px;max-height:200px;overflow:auto}
.m{color:var(--mut);font-size:12px;margin-top:4px;word-break:break-all}a{color:var(--low)}
.sev{display:inline-block;border-radius:4px;padding:0 6px;font-size:12px;font-weight:600;color:#fff;text-transform:uppercase}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}td{border-bottom:1px solid var(--line);padding:4px 6px;vertical-align:top;word-break:break-all}
</style>
</head>
<body>
<main>
<h1>${t.title}</h1>
<div class="meta">
  <div><span>${t.target}</span>${esc(rep.target)}</div>
  <div><span>${t.when}</span>${esc(rep.started)} — ${esc(rep.finished)}</div>
  <div><span>${t.pages} / ${t.forms} / ${t.submits}</span>${rep.stats.pages} / ${rep.stats.forms} / ${rep.stats.formSubmits}</div>
  <div><span>${t.result} (${t.failOn}: ${esc(rep.failOn)})</span><span class="${rep.passed ? 'ok' : 'bad'}">${rep.passed ? t.passed : t.failed}</span></div>
  <div><span>allupdsw-crawler</span>${esc(rep.version)}</div>
</div>
<h2>${t.findings} (${rep.findings.length})</h2>
<div class="chips"><button type="button" class="chip" data-f="" aria-pressed="true">${t.all}</button>${chips}</div>
<input type="search" id="q" placeholder="${t.search}" aria-label="${t.search}">
${rep.findings.length ? `<ul id="list">${rows}</ul>` : `<p class="ok">${t.none}</p>`}
<h2>${t.visited} (${rep.pages.length})</h2>
<div class="tw"><table><tbody>${pages}</tbody></table></div>
</main>
<script>
(function(){var cur='',q=document.getElementById('q');
function apply(){var s=q.value.toLowerCase();document.querySelectorAll('.f').forEach(function(li){
var ok=(!cur||li.dataset.sev===cur)&&(!s||li.textContent.toLowerCase().indexOf(s)>=0);li.style.display=ok?'':'none';});}
document.querySelectorAll('.chip').forEach(function(b){b.addEventListener('click',function(){cur=b.dataset.f;
document.querySelectorAll('.chip').forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false')});apply();});});
q.addEventListener('input',apply);})();
</script>
</body>
</html>
`;
}
