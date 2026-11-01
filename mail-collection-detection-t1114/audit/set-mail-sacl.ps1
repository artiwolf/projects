#Requires -RunAsAdministrator
$paths = @(
  "$env:USERPROFILE\Documents\Outlook Files",
  "$env:LOCALAPPDATA\Microsoft\Outlook",
  "$env:APPDATA\Thunderbird\Profiles"
)
foreach ($p in $paths) {
  if (-not (Test-Path $p)) { Write-Warning "нет $p"; continue }
  $acl  = Get-Acl -Path $p -Audit
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",            # для кого
            "ReadData",            # на какую операцию (чтение содержимого)
            "ContainerInherit,ObjectInherit",
            "None",
            "Success")             # только успешные
  $acl.AddAuditRule($rule)
  Set-Acl -Path $p -AclObject $acl
  Write-Host "SACL установлен: $p"
}