#Requires -RunAsAdministrator
# SACL (аудит чтения) на каталоги с почтой и на почтовые файлы внутри них

$dirs = @(
    "$env:USERPROFILE\Documents\Outlook Files",
    "$env:LOCALAPPDATA\Microsoft\Outlook",
    "$env:APPDATA\Thunderbird\Profiles"
)

function Add-ReadAudit([string]$Target, [bool]$IsDir) {
    $acl = Get-Acl -Path $Target -Audit
    # Правило уже есть - повторно не добавляем
    $has = $acl.Audit | Where-Object {
        $_.IdentityReference -match 'Everyone' -and
        $_.FileSystemRights -match 'ReadData' -and
        $_.AuditFlags -match 'Success'
    }
    if ($has) { Write-Host "SACL exists: $Target"; return }

    if ($IsDir) {
        # Для каталога: наследование на вложенные каталоги и файлы
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "ReadData", "ContainerInherit,ObjectInherit", "None", "Success")
    } else {
        # Для файла: без флагов наследования
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "ReadData", "Success")
    }
    $acl.AddAuditRule($rule)
    Set-Acl -Path $Target -AclObject $acl
    Write-Host "SACL set: $Target"
}

foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { Write-Warning "not found: $d"; continue }
    Add-ReadAudit $d $true
    # Файлы, созданные до установки SACL, наследование не подхватывает - ставим явно
    Get-ChildItem $d -File -Recurse -Include *.pst,*.ost,*.nst -Force -ErrorAction SilentlyContinue |
        ForEach-Object { Add-ReadAudit $_.FullName $false }
}