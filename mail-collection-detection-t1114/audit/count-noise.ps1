#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Считает события Security 4663 за заданный интервал и раскладывает их
  по процессам, объектам и маске доступа. Нужен для оценки шума аудита.
.EXAMPLE
  .\count-noise.ps1 -Label idle   -Hours 1
  .\count-noise.ps1 -Label active -Hours 1
#>
param(
    [Parameter(Mandatory)][string]$Label,          # метка замера, например idle / active
    [double]$Hours = 1,                            # длина окна в часах
    [datetime]$End = (Get-Date),                   # конец окна (по умолчанию сейчас)
    [string]$OutDir = "$PSScriptRoot\noise"        # куда сохранять CSV
)

# Окно наблюдения: от (конец минус N часов) до конца
$start = $End.AddHours(-$Hours)
New-Item $OutDir -ItemType Directory -Force | Out-Null
Write-Host "Window: $start  ->  $End  ($Hours h), label = $Label"

# Берём все события 4663 из журнала Security за это окно
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $start; EndTime = $End } -ErrorAction SilentlyContinue
if (-not $events) {
    # Событий нет: записываем нулевую сводку и выходим
    Write-Host 'No 4663 events in this window.'
    [pscustomobject]@{ Label = $Label; Hours = $Hours; Total = 0; PerHour = 0 } | Export-Csv "$OutDir\summary_$Label.csv" -NoTypeInformation
    return
}

# Разбираем XML каждого события и достаём нужные поля
$rows = foreach ($e in $events) {
    $d = @{}
    ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
        Time       = $e.TimeCreated
        Process    = $d['ProcessName']
        Object     = $d['ObjectName']
        AccessMask = $d['AccessMask']
        User       = $d['SubjectUserName']
        # Признак: объект — почтовый файл (а не каталог или что-то другое)
        IsFile     = [bool]($d['ObjectName'] -match '\.(pst|ost|mbox|msf)$' -or $d['ObjectName'] -match 'Thunderbird.*\\(Mail|ImapMail)\\')
    }
}

# Общие счётчики
$total    = @($rows).Count
$onFiles  = @($rows | Where-Object IsFile).Count
$onDirs   = $total - $onFiles

Write-Host ''
Write-Host "Total 4663:                 $total   ($([math]::Round($total / $Hours, 1)) per hour)"
Write-Host "  on mail files (.pst/.ost): $onFiles"
Write-Host "  on directories / other:    $onDirs"

# Разбивка по процессам: показывает, кто шумит больше всех
Write-Host "`n--- By process ---"
$byProc = $rows | Group-Object Process | Sort-Object Count -Descending |
          Select-Object Count, @{n='PerHour';e={[math]::Round($_.Count / $Hours, 1)}}, @{n='Process';e={$_.Name}}
$byProc | Format-Table -AutoSize

# Разбивка по объектам: топ-10 файлов и каталогов
Write-Host "--- By object (top 10) ---"
$rows | Group-Object Object | Sort-Object Count -Descending | Select-Object -First 10 Count, @{n='Object';e={$_.Name}} | Format-Table -AutoSize -Wrap

# Разбивка по маске доступа
Write-Host "--- By access mask ---"
$rows | Group-Object AccessMask | Sort-Object Count -Descending | Select-Object Count, @{n='AccessMask';e={$_.Name}} | Format-Table -AutoSize

# Сохраняем результаты для README и скриншотов
$rows   | Export-Csv "$OutDir\events_$Label.csv"  -NoTypeInformation -Encoding UTF8
$byProc | Export-Csv "$OutDir\by_process_$Label.csv" -NoTypeInformation -Encoding UTF8
[pscustomobject]@{
    Label = $Label; Hours = $Hours; Start = $start; End = $End
    Total = $total; PerHour = [math]::Round($total / $Hours, 1)
    OnMailFiles = $onFiles; OnDirectories = $onDirs
} | Export-Csv "$OutDir\summary_$Label.csv" -NoTypeInformation -Encoding UTF8
Write-Host "`nSaved to $OutDir"