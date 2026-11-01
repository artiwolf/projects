#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Включает настройки аудита Windows, нужные для обнаружения T1114.001
  (сбор локальной почты) через события Security 4656/4663/4688.
#>

# Вместо имён используются GUID, чтобы скрипт работал в любой языковой версии ОС
$subcategories = @(
    @{ Name = 'File System';          Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Why = '4663: file read/write by process (main event for the rule)' },
    @{ Name = 'Handle Manipulation';  Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}'; Why = '4656/4658: handle requested/closed' },
    @{ Name = 'Process Creation';     Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Why = '4688: who started the reading process' }
)

# Включаем аудит успешных операций для каждой подкатегории
foreach ($s in $subcategories) {
    auditpol /set /subcategory:"$($s.Guid)" /success:enable /failure:disable | Out-Null
    Write-Host "[OK] $($s.Name): Success enabled  ($($s.Why))"
}

# Записывать командную строку процесса в событие 4688
$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
Set-ItemProperty -Path $key -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
Write-Host '[OK] Command line in 4688 enabled'

# Настройки подкатегорий должны иметь приоритет над старой политикой по категориям
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-ItemProperty -Path $lsa -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord
Write-Host '[OK] SCENoApplyLegacyAuditPolicy = 1'

# Журнал Security 1 ГБ, чтобы он не перезаписывался во время экспериментов
wevtutil sl Security /ms:1073741824
Write-Host '[OK] Security log max size = 1 GB'

Write-Host ''
Write-Host 'Done. NOTE: auditing of file reads also needs a SACL on the target folders:'
Write-Host '  run set-mail-sacl.ps1, then verify-audit.ps1'