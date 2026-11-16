# allupdsw

Реестр версий всех проектов. Перед любой работой следуй DEVELOPMENT_CONCEPT.md.
Формат файлов описан в README.md. После изменения JSON обязательно запусти `python3 tools/validate.py`.
Любое изменение в tools/ сопровождается тестами в tests/; перед коммитом: `python3 -m unittest discover -s tests`.
Краулер (tools/crawler) всегда проверяет формы — не добавлять возможность отключить. CVE-сканер (tools/cve_scan.py) работает только на стандартной библиотеке Python.
