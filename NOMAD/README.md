# NOMAD — локальный наблюдатель публичной сетевой инфраструктуры

**Версия:** 1.0.0  
**Архитектура:** один компьютер, локальный FastAPI-контроллер и семь дочерних OS-процессов-зондов.  
**Хранилище:** SQLite (`data/nomad.sqlite3`), WAL, постоянное сохранение сущностей, маршрутов, наблюдений, событий и результатов проверок.

NOMAD получает опубликованные сведения об IP-адресах через фиксированные публичные API RIPEstat: сетевую регистрацию WHOIS, reverse DNS и приблизительную GeoLite-географию. BGP/ASN используются внутренне для обнаружения и связывания IP с держателем сети, но не выводятся отдельными списками в главном интерфейсе. Активный ICMP sweep доступен только для явно разрешённых публичных IPv4 CIDR; произвольные диапазоны и порты не сканируются. NOMAD не переносит исполняемый код на другие устройства, не устанавливает удалённых агентов и не пытается аутентифицироваться на удалённых системах.

## Запуск

Нужен Python 3.10 или новее.

```bash
cd NOMAD
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
python -m pip install -r requirements.txt
python start.py
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python start.py
```

Открой `http://127.0.0.1:8765/`. Сервер привязан только к loopback-интерфейсу; `index.html` отдельно через `file://` открывать не нужно.

Чтобы не запускать браузер автоматически:

```bash
NOMAD_NO_BROWSER=1 python start.py
```

## Модель зондов

Семь постоянно работающих дочерних процессов выполняют пассивное enrichment через RIPEstat. Отдельный локальный ICMP host-sweep запускается после первичного discovery только для явно разрешённых CIDR; traceroute и ARP остаются отдельными ручными действиями контроллера. Это локальные процессы, не удалённые агенты.

После первого открытия веб-интерфейса запускаются SHA-256-проверки файлов приложения, SQLite integrity_check и проверка JSON-содержимого сохранённых записей. Только после завершения этих проверок доступен запуск зондов.

При нажатии Start создаются семь отдельных локальных процессов:

- **Discovery Scout (1)** — выполняет lookup заданных seed-IP через RIPEstat `network-info`, извлекает origin ASN и ставит новые ASN в очередь исследования.
- **Resource Scout (2)** — получает имена держателей и организационные сведения через `as-overview`, а также регистрационные записи IP через `whois`.
- **Route Scout (2)** — получает BGP-наблюдения через `looking-glass` и соседей ASN через `asn-neighbours`.
- **Geo Scout (2)** — получает приблизительные GeoIP-метаданные через `maxmind-geo-lite` и PTR-имена через `reverse-dns-ip`.

FastAPI/Uvicorn — отдельный контроллер, он не считается зондом. У каждого дочернего процесса свой PID, heartbeat, статус, счётчик запросов и закрытый список разрешённых endpoint. Контроллер распределяет запросы через локальные multiprocessing queues. Если процесс аварийно завершается, supervisor создаёт ему замену.

Все семь процессов находятся на том же компьютере. Они не перемещаются по сети и не выполняют команды на удалённых системах.

## Непрерывная работа и discovery

После Start контроллер:

1. Выполняет первичный пассивный проход по seed-IP из `config.json` и получает сетевые сведения через RIPEstat.
2. Из наблюдаемых BGP-маршрутов извлекает публичные префиксы и выбирает представительские IP для пассивного metadata discovery. Это не перебор адресов внутри префиксов.
3. Если в `host_scan` включены явно разрешённые публичные CIDR, выполняет ICMP sweep этих диапазонов: один echo request на адрес, параллелизм до 32 адресов. По умолчанию функция выключена и список диапазонов пуст.
4. После завершения ping sweep обогащает только ответившие адреса; обработка целей последовательная: NOMAD завершает набор RIPEstat-запросов для одного IP, прежде чем перейти к следующему живому IP.
5. Затем продолжает IP-first scheduler: обрабатывает очередь IP небольшими порциями и расширяет ASN-граф, когда нет ожидающей IP-работы.
6. Остаётся в состоянии `MONITORING`, контролирует PID/heartbeat, перезапускает аварийные процессы и повторяет пассивный discovery по расписанию.

В коде нет конечного количества циклов, дневного лимита запросов NOMAD или фиксированного предела количества раскрываемых ASN. Процесс работает, пока пользователь не нажмёт Stop, не завершится сам сервер или система не остановит его. Рабочие очереди и состояние scheduler остаются оперативными; сохранённые записи восстанавливаются из SQLite при следующем запуске.

**Это не означает сканирование всего Интернета.** Пассивное discovery использует публичные BGP/ASN-данные RIPEstat и выбирает представительские IP, не перебирая найденные префиксы. Активный ICMP sweep возможен только для явно внесённых пользователем публичных IPv4 CIDR, не более 256 адресов в каждом диапазоне и максимум восьми диапазонов. Используй только адресное пространство, которым владеешь или на тестирование которого у тебя есть явное разрешение. NOMAD не сканирует все публичные BGP-префиксы, не делает порт-сканирование и не пытается определить ОС активными fingerprint-методами. В частности, traceroute показывает только маршрут от этого компьютера до одной разрешённой цели; он не обнаруживает всех пользователей или пакеты, которые «проходят через» эту цель.

## Лимиты и поведение источника

- Удалён дневной счётчик `900 запросов/сутки`, который раньше переводил NOMAD в SAFE_MODE.
- Удалён фиксированный предел `300 ASN` на сессию и прежний предел очереди ASN.
- Сохранено минимальное межзапросное расстояние, задаваемое `request_spacing_seconds` (не менее 1 секунды), чтобы не создавать неконтролируемую параллельную нагрузку на RIPEstat. Запросы к API выполняются последовательно.
- При HTTP 429 NOMAD ставит запросы на паузу на 5 минут, сохраняет незавершённый ASN в очереди и продолжает позднее. При HTTP 403 или неожиданном редиректе включается SAFE_MODE.
- Если discovery найдёт очень большое количество ASN, множества дедупликации и граф могут занять значительный объём RAM. Постоянные записи сохраняются в SQLite, а очереди текущего scheduler остаются в RAM.
- Условия и ограничения самого RIPEstat остаются в силе. Отсутствие внутреннего дневного лимита не является разрешением обходить ограничения поставщика данных.

## Настройки (`config.json`)

Редактируй конфигурацию при остановленном NOMAD.

- `seeds` — публичные IP-литералы, используемые для пассивного RIPEstat discovery. По умолчанию NOMAD не отправляет к ним ICMP.
- `discovery_interval_seconds` — интервал повторного прохода по seed-IP; по умолчанию 30 секунд в поставляемом config.json, технический минимум 5 секунд.
- `asn_refresh_interval_seconds` — через сколько повторно опрашивать уже известный ASN, чтобы замечать изменения в графе соседей; по умолчанию 3600 секунд, минимум 300 секунд.
- `request_spacing_seconds` — минимальная пауза между запросами к RIPEstat; технический минимум 1 секунда.
- `host_scan.enabled` — включает ICMP sweep только для перечисленных ниже разрешённых диапазонов; по умолчанию `false`.
- `host_scan.approved_subnets` — список публичных IPv4 CIDR, которые разрешено проверять. Принимаются только global IPv4 диапазоны не более 256 адресов каждый. По умолчанию список пуст.
- `host_scan.concurrency` — число одновременных ICMP-проверок, ограничено 32.
- `host_scan.timeout_seconds` — тайм-аут одного ping, 2–5 секунд.
- `observe_egress_ip` — кнопка измерения доступна по умолчанию, но сам запрос не выполняется автоматически: для получения IP-адреса исходящего соединения и приблизительного GeoLite-контекста нажми **Measure my public egress IP**. Запрос выполняется только после нажатия: RIPEstat возвращает адрес, который видит со своей стороны, а GeoLite — приблизительную геолокацию. Это не точная география компьютера; карта в интерфейсе удалена.
- `poll_interval_seconds` — устаревший параметр предыдущей версии; в v0.5.1 для периодического discovery используется `discovery_interval_seconds`.

### Опциональный traceroute

Traceroute выключен по умолчанию. Разрешены только публичные IP-литералы, вручную указанные в `traceroute.approved_targets` в локальном `config.json`, для которых у пользователя есть право проводить измерения. Максимум два адреса, не более восьми hop, интервал между измерениями одной цели — не менее часа. Доменные имена и цели, полученные из очереди discovery, не принимаются.

Пример настройки:

```json
"traceroute": {
  "enabled": true,
  "approved_targets": ["YOUR_AUTHORIZED_PUBLIC_IP_LITERAL"],
  "max_hops": 8,
  "interval_seconds": 3600,
  "timeout_seconds": 16
}
```

Нужна системная команда `traceroute` (Linux/macOS) или `tracert` (Windows). NOMAD не устанавливает её и не запрашивает повышенные привилегии.

## IP inventory и атрибуция

- Главный экран показывает IP-адреса. Если у одной зарегистрированной организации обнаружено больше одного IP, они объединяются в раскрываемую папку компании; одиночные IP остаются самостоятельными карточками.
- Связь IP с компанией строится по holder из RIPEstat AS Overview, а если он недоступен — по организационному полю WHOIS. ASN и CIDR используются внутренне для корреляции, но не выводятся отдельными строками.
- Для каждого публичного IP NOMAD запрашивает `network-info`, `whois`, `reverse-dns-ip` и `maxmind-geo-lite`. WHOIS может вернуть регистрационный диапазон, netname, организацию, страну, статус, даты создания/изменения и authority; Reverse DNS IP возвращает PTR-имя, если оно опубликовано.
- `first_seen` и `last_seen` фиксируют время первого и последнего наблюдения IP в текущем запуске NOMAD. Эти времена не являются датами регистрации адреса.
- GeoLite — приблизительная сетево-географическая оценка, не GPS и не доказательство физического местоположения устройства или человека.
- Порты не сканируются. ОС и модель устройства не определяются по одному IP, ASN, WHOIS или GeoLite. Если локальный разрешённый ARP-опрос вернул MAC и vendor, интерфейс показывает производителя сетевого интерфейса, но не выдаёт это за точную модель устройства.
- Автоматический ICMP sweep работает только по явно разрешённым публичным CIDR из `host_scan.approved_subnets`. Ручные ping, traceroute и ARP используют свои отдельные allowlists. Никакой этап не делает порт-сканирование или OS fingerprinting.

### Пример host_scan (только для своего / явно разрешённого публичного диапазона)

Добавь объект в локальный `config.json`; существующие `ping`, `traceroute` и `arp_scan` allowlists менять не требуется:

```json
"host_scan": {
  "enabled": true,
  "approved_subnets": ["YOUR_AUTHORIZED_PUBLIC_CIDR"],
  "concurrency": 32,
  "timeout_seconds": 3
}
```

Вместо placeholder укажи конкретный публичный IPv4 CIDR, на который у тебя есть разрешение. Не используй `0.0.0.0/0`, целые ASN или автоматически найденные BGP-диапазоны.

## Хранение и целостность

Рабочая база находится в `data/nomad.sqlite3`. Это обычный SQLite-файл без внешнего сервера и без дополнительных Python-зависимостей. Его можно открыть сторонними программами: DB Browser for SQLite, SQLiteStudio, DBeaver или стандартным модулем `sqlite3` в Python.

Сохраняются сущности, маршруты, наблюдения, события и результаты активных действий, включая результаты host-sweep ping. При запуске NOMAD восстанавливает сохранённые записи в рабочее состояние. Оперативные очереди, heartbeat и состояние текущих процессов не являются историческими записями БД.

SQLite использует WAL и `synchronous=FULL`. Пока NOMAD работает, рядом с основным файлом могут находиться `nomad.sqlite3-wal` и `nomad.sqlite3-shm`: это штатные служебные файлы SQLite. Не копируй работающую БД простым копированием одного файла; используй кнопку **Download SQLite backup**, которая делает согласованную копию через SQLite Backup API.

После первого GET веб-страницы (а не при старте Python-процесса) выполняется `PRAGMA integrity_check`, SHA-256 хеширование файлов приложения и проверка содержимого БД: каждая запись должна быть корректным JSON-объектом, а ID в payload должен совпадать с ключом SQLite. При запуске также рассчитываются SHA-256 хеши файлов приложения и сравниваются с локальным baseline предыдущего запуска. Изменённые, новые и отсутствующие файлы отображаются в статусе. Это обнаружение локальных изменений, а не проверка цифровой подписи или доказательство происхождения файлов.

Полосы прогресса показывают реальные байты при хешировании, число прочитанных и проверенных записей при восстановлении и счётчик VM-инструкций во время `integrity_check`. Отдельные live-индикаторы показывают количество завершённых ICMP-проверок и последовательных IP-enrichment задач. Завершённые 100% индикаторы скрываются; итог остаётся в статусе операции. У SQLite нет доступного надёжного общего процента для этой операции, поэтому её индикатор работает в неопределённом режиме и не изображает ложные 37% или 82%. Передача `/api/status` в браузер отдельно показывает фактически полученные байты HTTP-ответа.

База и резервные копии находятся в `data/`, этот каталог не включается в исходный ZIP и не отправляется в GitHub.

## Самопроверка

```bash
python selftest.py
```

Автономные тесты проверяют парсинг ASN/AS_PATH и WHOIS, регистрацию новых источников в закрытом allowlist, GeoIP-нормализацию, сохранение first-seen времени IP, ограничения активной диагностики, повторение discovery-проходов, локальный API и жизненный цикл семи процессов. Они не отправляют запросы к RIPEstat. Реальную работу внешнего API необходимо проверить на компьютере пользователя.

## Источники

- [SQLite WAL mode](https://sqlite.org/wal.html)\n- [SQLite integrity_check](https://sqlite.org/pragma.html#pragma_integrity_check)\n- [RIPEstat Data API](https://stat.ripe.net/docs/data-api/ripestat-data-api)
- [Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html)
- [Looking Glass](https://stat.ripe.net/docs/data-api/api-endpoints/looking-glass)
- [ASN Neighbours](https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours)
- [AS Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview)
- [MaxMind GeoLite](https://stat.ripe.net/docs/data-api/api-endpoints/maxmind-geo-lite)
- [WHOIS](https://stat.ripe.net/docs/data-api/api-endpoints/whois.html)
- [Reverse DNS IP](https://stat.ripe.net/docs/data-api/api-endpoints/reverse-dns-ip.html)
- [What's My IP](https://stat.ripe.net/docs/data-api/api-endpoints/whats-my-ip)


### v0.5.1: устойчивый scheduler и маркеры локальных зондов

- Периодический seed-discovery больше не ждёт полного опустошения очередей IP/ASN.
- Очереди IP и ASN обрабатываются небольшими порциями (по одному элементу за оборот), поэтому большая BGP-компонента не блокирует следующий discovery-pass.
- Исключения отдельных заданий и проходов фиксируются в event stream; coordinator продолжает работу вместо тихого завершения после первой ошибки.
- `discovery_interval_seconds` допускает значение от 5 секунд; в поставляемом `config.json` выставлено 30 секунд. Реальное расписание зависит также от времени ответов RIPEstat и request pacing.
- Кнопка **Locate probes** запрашивает разрешение браузера на приблизительное положение локального компьютера. После нажатия нужно разрешить геолокацию в браузере. Координаты используются только в оперативной памяти текущего процесса и не записываются в config/БД; их можно очистить перезапуском сервера. Все семь зондов показываются концентрическими цветными кольцами в одной точке, поскольку они находятся на одном компьютере.


### v0.6.0 — Organization / Network Intelligence

- Карта и зависимости Leaflet/OpenStreetMap удалены из интерфейса.
- Главный экран показывает организации/ASN, CIDR-префиксы и конкретные IP-адреса; поиск и раскрытие карточек работают в браузере.
- Evidence score — объяснимая эвристика полноты атрибутов (holder, ASN, prefix, RIPEstat source, announced), не вероятность достоверности.
- Счётчик IP показывает только адреса, реально встреченные в текущем наборе данных. Он не оценивает полное количество устройств в сети.
- Никакие порты не сканируются. Модель не заявляет об обнаружении роутеров, веб-серверов или устройств, если источник не предоставил подтверждения.
- ICMP/ARP и дополнительные traceroute-зонды не добавлены в этот выпуск; существующий traceroute остаётся выключенным по умолчанию и ограничен ручным allowlist из config.json.


### v0.7.0 — bounded active diagnostics and evidence agents

- Added manual ICMP ping to exact IP literals in `ping.approved_targets`; disabled by default, three echo requests per run, per-target cooldown.
- Added manual traceroute API action; it requires `traceroute.enabled=true` and exact global IP literals in `traceroute.approved_targets`. It is excluded from the automatic discovery loop.
- Added manual Linux `arp-scan` for explicitly allowlisted private IPv4 subnets no larger than /24, pinned to `arp_scan.interface`; disabled by default. The host needs the `arp-scan` binary and suitable local privileges. Only use on a LAN you administer.
- Added local-only POST endpoints `/api/active/ping`, `/api/active/traceroute`, and `/api/active/arp`. Every action checks the config allowlist again on the server; commands are argv arrays, never shell strings.
- Added an explainable correlation engine. It links ASN holders, origin IPs, prefixes, BGP neighbour/path observations, user-triggered ping responses, ARP MAC records and traceroute hops. It reports source evidence and a completeness score, not a probability, ownership proof, or AI-generated certainty.
- No port scan, banner grabbing, remote agent installation, or service enumeration is implemented. Device counts remain lower bounds of observed records, not a census of a subnet.

#### Active probe configuration example (manual opt-in)

```json
"ping": {"enabled": true, "approved_targets": ["192.168.1.1"], "interval_seconds": 30, "timeout_seconds": 8},
"arp_scan": {"enabled": true, "approved_subnets": ["192.168.1.0/24"], "interface": "eth0", "interval_seconds": 3600, "timeout_seconds": 25},
"traceroute": {"enabled": true, "approved_targets": ["YOUR_AUTHORIZED_PUBLIC_IP_LITERAL"], "max_hops": 8, "interval_seconds": 3600, "timeout_seconds": 16}
```

Restart NOMAD after editing `config.json`. Ping and traceroute buttons appear only for configured targets. ARP additionally requires a valid local interface name. On Linux, install `arp-scan` separately; NOMAD does not elevate privileges automatically.


### v0.8.0 — company-grouped IP inventory and enrichment

- Replaced the visible ASN/prefix/BGP tables and topology diagram with a single IP inventory.
- IPs are grouped under a company folder only when at least two observed addresses share a resolved organization. Single-IP records remain standalone.
- Added RIPEstat WHOIS and Reverse DNS IP lookups for each newly inspected public address.
- Added per-IP first-seen/last-seen timestamps and registration, PTR, GeoLite and local diagnostic fields.
- Detail panels explicitly mark ports as not scanned and device/OS as unknown unless a source provides verifiable data. No port scan or OS fingerprinting was introduced.


### v1.0.0 — deferred integrity, live progress and staged host sweep

- SQLite integrity/hash/content checks begin only after the first browser GET `/`; starting the Python process alone does not touch the database.
- Startup restore validates JSON payload types and verifies each payload ID against its SQLite row key.
- During fast search only Discovery Scout performs RIPEstat network-info lookups; the other scout roles wait. After the allowlisted ping phase, each reachable IP is enriched sequentially and the current target is shown above the probe list.
- The dashboard shows live seed-discovery, ping-sweep, database and enrichment progress; completed 100% bars are hidden.
- IP frontier work is prioritized ahead of ASN expansion.
- Added optional ICMP discovery for explicitly approved public IPv4 CIDRs, bounded to 256 addresses per range, eight ranges and 32 concurrent pings. Defaults remain disabled with an empty allowlist; existing ping/traceroute/ARP settings are unchanged.
- After a sweep, reachable addresses are enriched sequentially, one IP at a time. No port scanning or automatic Internet-wide BGP prefix sweep is performed.
