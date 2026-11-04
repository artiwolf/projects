# Шаблоны правил корреляции

Шаблоны используют нормализованные поля, формируемые правилами XP. Это логика обнаружения, а не готовый синтаксис конкретной SIEM. Имена `msgid` соответствуют исходным типам Windows-событий после нормализации.

## R-01. Запуск PowerShell с encoded-командой и обходом политики

**Событие:** создание процесса, `msgid = "1"` (Sysmon Process Create).

```text
ON event WHERE msgid = "1"
  AND lower(object.process.fullpath) ENDSWITH "\powershell.exe"
  AND lower(object.process.cmdline) CONTAINS "-enc"
  AND lower(object.process.cmdline) CONTAINS_ANY (
        "-ep bypass", "-executionpolicy bypass")
  AND lower(object.process.cmdline) CONTAINS_ANY (
        "iex", "invoke-expression", "downloadstring", "iwr")
EMIT high_severity_alert WITH
  event_src.fqdn, object.account.id,
  object.process.id, object.process.parent.id,
  object.process.cmdline, object.process.hash.sha256
```

Для этой выгрузки совпадение соответствует Sysmon RecordID `210355013`, PID `4044`, PPID `9512`. Сочетание encoded-команды, обхода политики и загрузки с последующим выполнением является более надёжным признаком, чем каждый параметр отдельно.

## R-02. Исходящее соединение PowerShell с нестандартным портом

**Событие:** сетевое соединение, `msgid = "3"` (Sysmon Network Connection).

```text
ON event WHERE msgid = "3"
  AND lower(object.process.fullpath) ENDSWITH "\powershell.exe"
  AND direction = "egress"
  AND dst.port NOT IN (80, 443)
  AND dst.ip NOT IN approved_admin_endpoints
EMIT medium_severity_alert WITH
  event_src.fqdn, object.process.id,
  src.ip, src.port, dst.ip, dst.port, protocol
```

Для этой выгрузки зафиксированы соединения к `10.158.3.4:9000` (RecordID `210355034` и `210355475`). Адрес необходимо проверить по корпоративному списку узлов до блокировки.

## R-03. Доступ к чувствительным документам

**События:** запрос дескриптора объекта `msgid = "4656"` и доступ к объекту `msgid = "4663"`.

```text
ON event WHERE msgid IN ("4656", "4663")
  AND object = "file"
  AND lower(object.fullpath) MATCHES_ANY (
        "*\documents\advanced_research_report.docx",
        "*\work\reports\incident_report.pdf",
        "*\salary_calculation\expert_services_department.xls",
        "*\competitive_analysis\product_fails.pdf",
        "*\competitive_analysis\product_fails_fix_plan.docx",
        "*\ipo_*")
EMIT alert WITH
  time, event_src.fqdn, subject.account.name,
  subject.process.fullpath, subject.process.id,
  object.fullpath, object.value, msgid
```

Само обращение к документу не означает утечку. Повышать приоритет следует при совпадении с подозрительным процессом, необычной учётной записью или сетевой передачей.

## R-04. Корреляция запуска и сетевой активности одного процесса

```text
JOIN normalized_process_create AS p
  WITH normalized_network_connection AS n
ON p.event_src.fqdn = n.event_src.fqdn
AND p.object.process.id = n.object.process.id
AND n.time BETWEEN p.time AND p.time + 2 minutes
WHERE p.msgid = "1"
  AND n.msgid = "3"
  AND lower(p.object.process.fullpath) ENDSWITH "\powershell.exe"
  AND lower(p.object.process.cmdline) CONTAINS "-enc"
  AND lower(p.object.process.cmdline) CONTAINS "-ep bypass"
  AND n.direction = "egress"
EMIT high_severity_alert WITH p.*, n.*
```

Если доступен `ProcessGuid`, предпочтительно использовать его вместо PID. При корреляции только по PID необходимо ограничивать временное окно и учитывать повторное использование идентификаторов.

## Ограничение для PowerShell Module Logging

События PowerShell Module Logging (`msgid = "4103"`) содержат сведения о командах и контексте выполнения. В текущем проверенном результате нормализации не подтверждено отдельное поле с содержимым `$Data["Payload"]`. Поэтому шаблон поиска текста `Get-ChildItem`/`Get-Item` по нормализованным полям не приводится: сначала требуется добавить отображение `Payload` в поддерживаемое поле и повторно проверить модульный тест. До этого содержимое `Payload` следует анализировать в исходном событии.

## Проверка на известных событиях

- Положительный пример R-01: Sysmon RecordID `210355013`.
- Положительные примеры R-02: Sysmon RecordID `210355034` и `210355475`.
- Положительные примеры R-03: Security RecordID `15523478–15523642`.
- Отрицательный пример: Sysmon File Create RecordID `210355061`, где `WINWORD.EXE` создал ярлык `Advanced_Research_Report.docx.LNK` в Office Recent. Это обычное поведение Office и не должно само по себе вызывать тревогу о загрузчике или эксфильтрации.
