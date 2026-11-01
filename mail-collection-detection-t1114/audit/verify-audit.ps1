#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Проверяет, что аудит для T1114.001 применён: политика, реестр, SACL
  и живой тест чтения файла, после которого должно появиться событие 4663.
#>
param(
    # Каталоги, в которых проверяем SACL
    [string[]]$Paths = @(
        "$env:USERPROFILE\Documents\Outlook Files",
        "$env:LOCALAPPDATA\Microsoft\Outlook"
    )
)

# Список результатов проверок и функция для добавления строки в него
$results = New-Object System.Collections.Generic.List[object]
function Add-Result($Check, $Ok, $Details) {
    $results.Add([pscustomobject]@{ Check = $Check; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Details = $Details })
}

# 1. Подкатегории аудита (auditpol /r отдаёт CSV, колонки не зависят от языка)
$subs = @(
    @{ Name = 'File System';         Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Handle Manipulation'; Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Process Creation';    Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}' }
)
foreach ($s in $subs) {
    $csv = auditpol /get /subcategory:"$($s.Guid)" /r | ConvertFrom-Csv
    $val = ($csv | Select-Object -First 1).'Inclusion Setting'
    Add-Result "auditpol: $($s.Name)" ($val -match 'Success|Успех') $val
}

# 2. Командная строка в событии 4688
$cmd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Add-Result 'Command line in 4688' ($cmd -eq 1) "value = $cmd"

# 3. Приоритет подкатегорий над старой политикой
$leg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
Add-Result 'SCENoApplyLegacyAuditPolicy' ($leg -eq 1 -or $null -eq $leg) "value = $leg (1 or missing is OK)"

# 4. Размер журнала Security
$max = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
Add-Result 'Security log size >= 256 MB' ($max -ge 268435456) ("{0} MB" -f [math]::Round($max / 1MB))

# 5. SACL на каталогах и на файлах внутри них
$testFile = $null
foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { Add-Result "SACL folder: $p" $false 'path not found'; continue }
    # Ищем правило аудита: чтение (ReadData) + успешные операции
    $aud = (Get-Acl $p -Audit).Audit | Where-Object { $_.FileSystemRights -match 'ReadData' -and $_.AuditFlags -match 'Success' }
    Add-Result "SACL folder: $p" ([bool]$aud) $(if ($aud) { ($aud | ForEach-Object { "$($_.IdentityReference)/$($_.FileSystemRights)" }) -join '; ' } else { 'no ReadData/Success rule' })

    # То же для каждого почтового файла; первый файл с SACL берём для живого теста
    Get-ChildItem $p -File -Recurse -Include *.pst,*.ost -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $a = (Get-Acl $_.FullName -Audit).Audit | Where-Object { $_.FileSystemRights -match 'ReadData' -and $_.AuditFlags -match 'Success' }
        Add-Result "SACL file: $($_.Name)" ([bool]$a) $(if ($a) { 'ok' } else { 'no rule on file' })
        if (-not $testFile -and $a) { $testFile = $_.FullName }
    }
}

# 6. Живой тест: читаем файл и ищем событие 4663
if ($testFile) {
    $t0 = Get-Date
    # Открываем файл на чтение и читаем первый килобайт
    $fs = [IO.File]::Open($testFile, 'Open', 'Read', 'ReadWrite')
    $buf = New-Object byte[] 1024; [void]$fs.Read($buf, 0, $buf.Length); $fs.Dispose()
    # Пауза, чтобы событие успело попасть в журнал
    Start-Sleep -Seconds 3
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $t0 } -ErrorAction SilentlyContinue |
          Where-Object { $_.Message -like "*$testFile*" }
    Add-Result 'Live test: 4663 appears after read' ([bool]$ev) $(if ($ev) { "$(@($ev).Count) event(s) for $testFile" } else { "no event for $testFile" })
} else {
    Add-Result 'Live test' $false 'no file with SACL found to test'
}

# Итоговая таблица и общий вердикт
$results | Format-Table -AutoSize -Wrap
$fail = @($results | Where-Object Result -eq 'FAIL').Count
if ($fail -eq 0) { Write-Host 'ALL CHECKS PASSED' -ForegroundColor Green }
else { Write-Host "$fail CHECK(S) FAILED" -ForegroundColor Red }