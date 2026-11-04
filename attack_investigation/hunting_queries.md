# Поиск подозрительной активности на других хостах

Запросы приведены в KQL-подобном псевдосинтаксисе. Используются поля, формируемые правилами нормализации: `time`, `event_src.fqdn`, `msgid`, `subject.account.name`, `subject.process.fullpath`, `subject.process.id`, `object.process.fullpath`, `object.process.id`, `object.process.parent.id`, `object.process.cmdline`, `object.fullpath`, `src.ip`, `dst.ip`, `dst.port`, `protocol`, `direction`. В конкретной SIEM синтаксис обращения к полям может отличаться.

Для временной корреляции используется `time`, полученный из `System.TimeCreated.SystemTime`.

## Подозрительный запуск PowerShell

```kql
Events
| where msgid == "1"
| where tolower(object.process.fullpath) endswith "\powershell.exe"
| where tolower(object.process.cmdline) contains "-enc"
| where tolower(object.process.cmdline) contains_any ("-ep bypass", "-executionpolicy bypass")
| where tolower(object.process.cmdline) contains_any ("iex", "invoke-expression", "downloadstring", "iwr")
| project time, event_src.fqdn, subject.account.name,
          object.process.fullpath, object.process.id,
          object.process.parent.id, object.process.cmdline,
          object.process.hash.sha256
```

## Сетевые соединения PowerShell

```kql
Events
| where msgid == "3"
| where tolower(object.process.fullpath) endswith "\powershell.exe"
| where direction == "egress"
| where dst.port !in (80, 443)
| project time, event_src.fqdn, object.process.id,
          object.process.fullpath, src.ip, dst.ip, dst.port, protocol
```

Отдельно проверить соединения к `10.158.3.4:9000`. Перед блокировкой необходимо установить, не является ли адрес корпоративным сервером.

## Доступ к чувствительным документам

```kql
Events
| where msgid in ("4656", "4663")
| where object == "file"
| where tolower(object.fullpath) contains_any (
    "\documents\advanced_research_report.docx",
    "\work\reports\incident_report.pdf",
    "\salary_calculation\expert_services_department.xls",
    "\competitive_analysis\product_fails.pdf",
    "\competitive_analysis\product_fails_fix_plan.docx",
    "\ipo_")
| project time, event_src.fqdn, subject.account.name,
          subject.process.fullpath, subject.process.id,
          object.fullpath, object.value, msgid, status
```

События доступа необходимо сопоставлять с процессом, пользователем и соседними событиями. Само по себе открытие документа через Explorer или Word не доказывает его сбор атакующим.

## Корреляция запуска PowerShell и сетевой активности

```text
JOIN Events AS p (msgid = "1")
  WITH Events AS n (msgid = "3")
ON p.event_src.fqdn = n.event_src.fqdn
AND p.object.process.id = n.object.process.id
AND n.time BETWEEN p.time AND p.time + 2 minutes
WHERE lower(p.object.process.fullpath) ENDSWITH "\powershell.exe"
  AND lower(p.object.process.cmdline) CONTAINS "-enc"
  AND lower(p.object.process.cmdline) CONTAINS "-ep bypass"
  AND n.direction = "egress"
```

Предпочтительно связывать события по `ProcessGuid`, если он доступен в нормализованной схеме обоих событий. Если используется только PID, следует учитывать его повторное использование.

## Проверка PowerShell Module Logging

События с `msgid = "4103"` полезны для анализа команд PowerShell. Однако в текущем результате теста нормализации содержимое `Payload` не подтверждено как отдельное нормализованное поле. Поэтому поиск по `Get-ChildItem`, `Get-Item` и тексту скрипта нельзя считать реализованным только на основании `subject.process.name` или `datafield1`. Для такого поиска необходимо явно сохранить `$Data["Payload"]` в поддерживаемое поле правила и повторно проверить тест.

## Артефакты для проверки

- Sysmon Operational: создание процессов, сетевые соединения и создание файлов.
- PowerShell Operational: Script Block Logging и Module Logging.
- Security: аудит доступа к объектам и события входа; отдельно сопоставить LogonId `0xcd0ed1`.
- Prefetch, Amcache, `$MFT`, USN Journal, `Zone.Identifier`, история загрузок браузера.
- Defender/EDR: обнаружения, карантин, дерево процессов и сетевые соединения.
- Proxy, Firewall, DNS, NDR, DLP и серверные журналы для `10.158.3.4:9000`; проверить HTTP-ответ и объём переданных данных.
- Проверить все целевые документы и файлы с префиксом `IPO_` на доступ, копирование, архивирование и передачу.
